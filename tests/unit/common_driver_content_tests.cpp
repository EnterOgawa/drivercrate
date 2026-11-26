//------------------------------------------------------------------------------
/**
 * @file common_driver_content_tests.cpp
 * @brief 同INF付属内容の必要参照と未評価作用を局所検証します
 * @version 01.16.01
 * @date 2026/11/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/05  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/06  Windows管理driver scopeの実byte正負fixtureを追加
 * Ver.01.02.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.02.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.02.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.03.00 Shunji Ogawa  2026/11/19  表示用の独自クラスと導入経路からの分離を検証
 * Ver.01.04.00 Shunji Ogawa  2026/11/19  AMD64の全導入分岐と必要な媒体ファイルを構造検証
 * Ver.01.05.00 Shunji Ogawa  2026/11/19  元Models行とWindows nodeの役割を照合する試験を追加
 * Ver.01.06.00 Shunji Ogawa  2026/11/19  独自クラスの登録と既存作用の読取試験を追加
 * Ver.01.07.00 Shunji Ogawa  2026/11/19  選択Modelsと同じ元INFのクラス登録情報を検証
 * Ver.01.08.00 Shunji Ogawa  2026/11/19  登録済みDriver Storeの原ファイル照合と保持を検証
 * Ver.01.09.00 Shunji Ogawa  2026/11/20  空媒体のSDHostが収集用の実選択節だけを渡すことを検証
 * Ver.01.10.00 Shunji Ogawa  2026/11/20  標準Portsページの元所有・登録scopeと収集用途を確認
 * Ver.01.11.00 Shunji Ogawa  2026/11/20  標準NVMeの元空リストと三選択節を正負で確認
 * Ver.01.12.00 Shunji Ogawa  2026/11/21  標準AHCIの元順位、空媒体と三選択節を正負で確認
 * Ver.01.13.00 Shunji Ogawa  2026/11/21  自己媒体Portsの元コピーと標準ページを正負で確認
 * Ver.01.14.00 Shunji Ogawa  2026/11/23  ストレージの名前付きイベントと補助サービスの選択範囲を確認
 * Ver.01.15.00 Shunji Ogawa  2026/11/24  収集用クラスの旧登録節と別の導入役割からの参照を検証
 * Ver.01.16.00 Shunji Ogawa  2026/11/24  表示クラスの単一KMDF収集で元参照の正負を確認
 * Ver.01.16.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note 共通実装を専用compileし、製品へ診断入口を追加しません。署名や導入成功を偽装しません
 * @see docs/adr/0449-declared-catalog-hash-and-inf-attached-content.md
 */
//------------------------------------------------------------------------------

#include "platform/official_driver_package.cpp"
#include "platform/driver_store_inf_transport_internal.h"
#include "platform/mtd_handler_internal.h"
#include "platform/registered_driver_store_package_internal.h"
#include "official_driver_package_tests.cpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <crtdbg.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <devpkey.h>
#include <exception>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {
/** @brief 合成Windowsルートで二つの照会APIが返す値を保持する */
struct RegisteredStoreLookupFixture {
	/// この試験が作成したWindows相当のルート
	std::wstring		 windows ;
	/// この試験が作成したOEM INFの位置
	std::wstring		 registeredInf ;
	/// 照会が返す配置済み元INFの位置
	std::wstring		 storeInf ;
	/// 照会が失敗する場合の元Win32 error
	std::optional<DWORD> storeError ;
} ;

thread_local RegisteredStoreLookupFixture registeredStoreFixture ;	// 呼出しスレッドの人工応答

//------------------------------------------------------------------------------
/**
 * @brief 合成Windowsルートを返す
 * @param[out] buffer 元ルートを受ける領域
 * @param[in] capacity WCHAR単位の領域容量
 * @return 成功時は終端を除いた文字数、領域不足時は終端を含む必要数
 */
//------------------------------------------------------------------------------
UINT WINAPI registeredStoreWindowsDirectory( LPWSTR buffer, const UINT capacity)
{
	const auto &root	 = registeredStoreFixture.windows ;			// 試験中に固定した人工ルート
	const auto	required = static_cast<UINT>( root.size() + 1U) ;	// 終端を含む必要容量
	// Windows APIの容量規則に合わせ、領域が不足する場合は書き込まない
	if( !buffer || capacity < required) {
		return required ;
	}

	std::copy( root.cbegin(), root.cend(), buffer) ;
	buffer[root.size()] = L'\0' ;
	return required - 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 合成OEM INFに対応する配置位置か、設定したエラーを返す
 * @param[in] registered OEM INFの完全パス
 * @param[in] alternate 指定しないプラットフォーム
 * @param[in] locale 指定しないロケール
 * @param[out] buffer 配置済みINFの完全パスを受ける領域
 * @param[in] capacity WCHAR単位の領域容量
 * @param[out] required 指定された場合に終端込み必要数を返す
 * @return 設定した場所の返却に成功した場合だけTRUE
 */
//------------------------------------------------------------------------------
BOOL WINAPI registeredStoreLocation( PCWSTR registered, PSP_ALTPLATFORM_INFO alternate,
									PCWSTR locale, PWSTR buffer, const DWORD capacity,
									PDWORD required)
{
	const auto &fixture = registeredStoreFixture ;	// 同じ登録を解決する人工応答
	// この試験の登録以外から配置先を返さない
	if( !registered || fixture.registeredInf != registered || alternate || locale) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	// 失敗を示すAPIが元エラー0を返す場合も含め、応答をそのまま設定する
	if( fixture.storeError) {
		SetLastError( *fixture.storeError) ;
		return FALSE ;
	}

	const auto characters = static_cast<DWORD>( fixture.storeInf.size() + 1U) ;	// 終端込み容量
	// 必要容量を要求された場合だけ返却領域を使う
	if( required) {
		*required = characters ;
	}

	// 領域不足時に出力パスの先頭だけを返さない
	if( !buffer || capacity < characters) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::copy( fixture.storeInf.cbegin(), fixture.storeInf.cend(), buffer) ;
	buffer[fixture.storeInf.size()] = L'\0' ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一時ファイルを変更せずに、指定された書込みまたは削除アクセスを試す
 * @param[in] path この試験が作成した実ファイルの完全パス
 * @param[in] access 実際に要求するWin32アクセス
 * @return 開閉に成功した場合0、失敗した場合は元Win32 error
 */
//------------------------------------------------------------------------------
[[nodiscard]] DWORD probeRegisteredStoreFileAccess( const std::wstring &path, const DWORD access)
{
	const HANDLE file = CreateFileW(
		path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// この関数が閉じる試験ハンドル
	// 共有違反を呼出し元へそのまま返す
	if( file == INVALID_HANDLE_VALUE) {
		return GetLastError() ;
	}

	return CloseHandle( file) ? ERROR_SUCCESS : GetLastError() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一時ファイルで配置先、全ファイルの同一性と読取り保持を検証する
 * @param[in,out] context 検証結果を集計する所有先
 * @note 二つの位置照会だけ置換する。全ファイルは一時領域に置き、署名や導入は実行しない
 */
//------------------------------------------------------------------------------
void registeredDriverStorePackageMatrix( TestContext &context)
{
	constexpr std::wstring_view REPOSITORY =
		L"Windows\\System32\\DriverStore\\FileRepository\\" ;			// 人工Storeの正規相対ルート
	constexpr std::wstring_view OEM_INF = L"Windows\\INF\\oem42.inf" ;	// 人工の登録先
	constexpr std::array<std::wstring_view, 4U> MEMBERS{
		L"fixture.inf", L"fixture.cat", L"driver.sys", L"media\\amd64\\nested.sys"} ;	// 選択元閉包
	constexpr std::array<std::string_view, MEMBERS.size()> BYTES{
		"same INF bytes", "CAT variant A", "SYS variant A",
		"nested SYS bytes"} ;						// 架空のファイル内容
	constexpr std::size_t			   CAT = 1U ;	// 元CATの位置
	constexpr std::size_t			   SYS = 2U ;	// 同じ位置の比較に使う元SYS
	constexpr DriverStorePackageLookup LOOKUP{registeredStoreWindowsDirectory,
											  registeredStoreLocation} ;	// 位置照会だけを置換する
	OfficialDownloadWorkspace		   workspace ;							// 人工ファイルとその親だけを所有する
	const auto						   initialized =
		workspace.initialize( L"registered-store-test", 858U,
							 OfficialWorkspaceMode::CURRENT_USER_INSPECTION) ;	// 本人用の一時領域
	DRIVERCRATE_EXPECT( context, initialized == 0) ;
	// 一時領域を確保できない状態でファイル操作を始めない
	if( initialized != 0) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, OEM_INF, BYTES.front())) ;
	registeredStoreFixture.registeredInf = workspace.path( OEM_INF) ;
	registeredStoreFixture.windows = std::filesystem::path( registeredStoreFixture.registeredInf)
										 .parent_path()
										 .parent_path()
										 .wstring() ;
	registeredStoreFixture.storeError.reset() ;
	OfficialInfPackage							 original ;		// 元配置を保持する検査済み入力の形
	std::array<OfficialZipEntry, MEMBERS.size()> entries{} ;	// 全元ファイルの長さと実SHA-256
	// 選択元ファイルを個別に作成し、配置から独立に元ハッシュを得る
	for( std::size_t index = 0U; index < MEMBERS.size(); ++index) {
		auto &entry			   = entries[index] ;	// この一ファイルの元証拠
		entry.relativePath	   = std::wstring( L"original\\") + std::wstring( MEMBERS[index]) ;
		entry.uncompressedSize = BYTES[index].size() ;
		DRIVERCRATE_EXPECT( context,
						   writeWorkspaceFile( workspace, entry.relativePath, BYTES[index])) ;
		DRIVERCRATE_EXPECT(
			context, computeFileSha256( workspace.path( entry.relativePath), entry.sha256) == 0) ;
	}

	original.infRelativePath	 = entries.front().relativePath ;
	original.catalogRelativePath = entries[CAT].relativePath ;
	original.sourceFiles		 = {entries[SYS].relativePath, entries.back().relativePath} ;
	const std::wstring selected =
		// 正しい配置
		std::wstring( REPOSITORY) + L"fixture.inf_amd64_selected\\" ;
	const std::wstring alternate =
		// 同じ全バイトの別配置
		std::wstring( REPOSITORY) + L"fixture.inf_amd64_alternate\\" ;
	const struct {
		/// 失敗時に表示するケース名
		std::string_view  name ;
		/// このケースの配置相対ディレクトリ
		std::wstring	  directory ;
		/// 同じ長さで比較するCATバイト列
		std::string_view  catalog ;
		/// 同じ長さで比較するSYSバイト列
		std::string_view  driver ;
		/// 入れ子のSYSを置く実際の位置
		std::wstring_view nested ;
		/// 全ファイルと配置の照合が成立するかどうか
		bool			  accepted ;
	} cases[]{
		{"selected", selected, BYTES[CAT], BYTES[SYS], MEMBERS.back(), true},
		{"same-byte alternate", alternate, BYTES[CAT], BYTES[SYS], MEMBERS.back(), true},
		{"different CAT", std::wstring( REPOSITORY) + L"fixture.inf_amd64_cat\\", "CAT variant B",
		 BYTES[SYS], MEMBERS.back(), false},
		{"different SYS", std::wstring( REPOSITORY) + L"fixture.inf_amd64_sys\\", BYTES[CAT],
		 "SYS variant B", MEMBERS.back(), false},
		{"wrong nested position", std::wstring( REPOSITORY) + L"fixture.inf_amd64_flat\\",
		 BYTES[CAT], BYTES[SYS], L"nested.sys", false},
		{"outside repository", L"Windows\\System32\\DriverStore\\Other\\fixture.inf_amd64_other\\",
		 BYTES[CAT], BYTES[SYS], MEMBERS.back(), false},
	} ;
	// 同じINFから始まる各実配置を個別に作り、APIが指定した一箇所だけを照合する
	for( const auto &example : cases) {
		DRIVERCRATE_EXPECT(
			context,
			writeWorkspaceFile( workspace, example.directory + MEMBERS[0].data(), BYTES[0])) ;
		DRIVERCRATE_EXPECT( context,
						   writeWorkspaceFile( workspace, example.directory + MEMBERS[CAT].data(),
											  example.catalog)) ;
		DRIVERCRATE_EXPECT(
			context,
			writeWorkspaceFile( workspace, example.directory + MEMBERS[SYS].data(), example.driver)) ;
		DRIVERCRATE_EXPECT(
			context,
			writeWorkspaceFile( workspace, example.directory + example.nested.data(), BYTES.back())) ;
		registeredStoreFixture.storeInf =
			workspace.path( example.directory + MEMBERS.front().data()) ;
		RegisteredDriverStorePackage pinned ;	// この配置に対する一回の保持結果
		const auto error = pinned.pin( registeredStoreFixture.registeredInf, original, entries,
									  LOOKUP) ;	// 配置照合結果
		context.expect( (error == 0) == example.accepted,
					   std::string( example.name) + " pin error " + std::to_string( error), __FILE__,
					   __LINE__) ;
		DRIVERCRATE_EXPECT( context, (pinned.verify() == 0) == example.accepted) ;
	}

	const auto selectedInf = workspace.path( selected + MEMBERS.front().data()) ;	// 元の正常な照会先
	registeredStoreFixture.storeInf = selectedInf ;
	{
		RegisteredDriverStorePackage pinned ;	// 破棄まで選択した実ファイルを保持する
		DRIVERCRATE_EXPECT( context, pinned.verify() != 0) ;
		DRIVERCRATE_EXPECT( context, pinned.pin( registeredStoreFixture.registeredInf, original,
											   entries, LOOKUP) == 0) ;
		// INFだけでなくCATと両方のSYSへの書込みと削除を保持中だけ排除する
		for( const auto member : MEMBERS) {
			const auto path =
				// 選択した配置内の一ファイル
				workspace.path( selected + member.data()) ;
			DRIVERCRATE_EXPECT( context, probeRegisteredStoreFileAccess( path, GENERIC_WRITE) ==
											ERROR_SHARING_VIOLATION) ;
			DRIVERCRATE_EXPECT( context, probeRegisteredStoreFileAccess( path, DELETE) ==
											ERROR_SHARING_VIOLATION) ;
		}

		DRIVERCRATE_EXPECT( context, pinned.verify() == 0) ;
		registeredStoreFixture.storeInf = workspace.path( alternate + MEMBERS.front().data()) ;
		DRIVERCRATE_EXPECT( context, pinned.verify() != 0) ;
		registeredStoreFixture.storeInf	  = selectedInf ;
		registeredStoreFixture.storeError = ERROR_ACCESS_DENIED ;
		DRIVERCRATE_EXPECT( context, pinned.verify() == nativeErrorFromWin32( ERROR_ACCESS_DENIED)) ;
		registeredStoreFixture.storeError.reset() ;
		DRIVERCRATE_EXPECT( context, pinned.verify() == 0) ;
	}

	// 所有を解放した後は同じ実ファイルに書込み・削除アクセスを要求できる
	for( const auto member : MEMBERS) {
		const auto path = workspace.path( selected + member.data()) ;	// 保持中と同じ完全パス
		DRIVERCRATE_EXPECT( context,
						   probeRegisteredStoreFileAccess( path, GENERIC_WRITE) == ERROR_SUCCESS) ;
		DRIVERCRATE_EXPECT( context, probeRegisteredStoreFileAccess( path, DELETE) == ERROR_SUCCESS) ;
	}

	{
		RegisteredDriverStorePackage pinned ;						// 不正な元パスでは保持が成立しない
		auto						 unsafeOriginal = original ;	// 元ファイル位置だけを変更する
		auto						 unsafeEntries	= entries ;		// 元ハッシュと長さは保持する
		unsafeEntries.back().relativePath = L"original\\media\\amd64\\..\\amd64\\nested.sys" ;
		unsafeOriginal.sourceFiles.back() = unsafeEntries.back().relativePath ;
		DRIVERCRATE_EXPECT( context, pinned.pin( registeredStoreFixture.registeredInf, unsafeOriginal,
											   unsafeEntries, LOOKUP) != 0) ;
		auto wrongSize = entries ;	// 全ハッシュが同じでも元ファイルの長さは独立に確認する
		++wrongSize[CAT].uncompressedSize ;
		DRIVERCRATE_EXPECT( context, pinned.pin( registeredStoreFixture.registeredInf, original,
											   wrongSize, LOOKUP) != 0) ;
		registeredStoreFixture.storeError = ERROR_FILE_NOT_FOUND ;
		DRIVERCRATE_EXPECT( context,
						   pinned.pin( registeredStoreFixture.registeredInf, original, entries,
									  LOOKUP) == nativeErrorFromWin32( ERROR_FILE_NOT_FOUND)) ;
		registeredStoreFixture.storeError = ERROR_SUCCESS ;
		DRIVERCRATE_EXPECT( context, pinned.pin( registeredStoreFixture.registeredInf, original,
											   entries, LOOKUP) != 0) ;
		DRIVERCRATE_EXPECT( context, pinned.verify() != 0) ;
		registeredStoreFixture.storeError.reset() ;
	}

	const std::filesystem::path asciiWindows(
		registeredStoreFixture.windows) ;	// 作成済みの人工Windowsルート
	const auto workspaceRoot =
		// 所有済みの一時領域
		std::filesystem::path( workspace.path( L"anchor")).parent_path() ;
	const auto unicodeWindows  = workspaceRoot / L"Windows 検査" ;	// 同じ一時領域内の新しい名前
	const bool insideWorkspace = !workspaceRoot.empty() &&
								 // 元位置が所有直下であることの確認
								 asciiWindows == workspaceRoot / L"Windows" ;
	DRIVERCRATE_EXPECT( context, insideWorkspace) ;
	// 所有中の一時領域にあるWindows相当の直下ディレクトリだけを移動する
	if( !insideWorkspace) {
		return ;
	}

	auto unicodeRoot = unicodeWindows.wstring() ;						// 位置照会が返す非ASCIIのWindowsルート
	auto unicodeOem	 = (unicodeWindows / L"INF\\oem42.inf").wstring() ;	// 同じ登録INFの移動先
	auto unicodeStore =
		(unicodeWindows / std::filesystem::path( selectedInf).lexically_relative( asciiWindows))
			.wstring() ;	// 同じStore INFの移動先
	const auto renamed =
		// 同じ一時領域内の名前変更
		MoveFileW( asciiWindows.c_str(), unicodeWindows.c_str()) ;
	DRIVERCRATE_EXPECT( context, renamed != FALSE) ;
	// 名前変更が成立した場合だけ同じ内容を新しい位置から照合する
	if( renamed) {
		registeredStoreFixture.windows.swap( unicodeRoot) ;
		registeredStoreFixture.registeredInf.swap( unicodeOem) ;
		registeredStoreFixture.storeInf.swap( unicodeStore) ;
		NativeError pinError{} ;	// 非ASCIIのWindowsルートでの保持結果
		NativeError verifyError{} ;	// 同じ非ASCII位置の再照会結果
		{
			RegisteredDriverStorePackage pinned ;	// 一時ルート名を戻す前に全ハンドルを閉じる
			pinError = pinned.pin( registeredStoreFixture.registeredInf, original, entries, LOOKUP) ;
			verifyError = pinned.verify() ;
		}

		const auto restored =
			// cleanupが追跡する名前へ戻す
			MoveFileW( unicodeWindows.c_str(), asciiWindows.c_str()) ;
		DRIVERCRATE_EXPECT( context, restored != FALSE) ;
		DRIVERCRATE_EXPECT( context, pinError == 0) ;
		DRIVERCRATE_EXPECT( context, verifyError == 0) ;
		// 既知の一時パスへ戻せなければ後続のファイル操作を行わない
		if( !restored) {
			return ;
		}

		registeredStoreFixture.windows.swap( unicodeRoot) ;
		registeredStoreFixture.registeredInf.swap( unicodeOem) ;
		registeredStoreFixture.storeInf.swap( unicodeStore) ;
	}

	std::wstring alias ;	// 一時領域が終了時に削除する追加ハードリンク
	DRIVERCRATE_EXPECT( context, workspace.prepareExternalFile( L"alias.sys", alias) == 0) ;
	const auto sysPath = workspace.path( selected + MEMBERS[SYS].data()) ;	// 照合対象の正規SYS位置
	const auto linked  = CreateHardLinkW( alias.c_str(), sysPath.c_str(),
										 nullptr) ;	// 同じボリュームの人工ファイルだけ
	DRIVERCRATE_EXPECT( context, linked != FALSE) ;
	// 追加ハードリンクを作れたときだけ、正規位置から同じバイトを読めることを確認する
	if( linked) {
		RegisteredDriverStorePackage pinned ;	// 正規位置にある同じ実ファイルを固定する
		DRIVERCRATE_EXPECT( context, pinned.pin( registeredStoreFixture.registeredInf, original,
											   entries, LOOKUP) == 0) ;
		DRIVERCRATE_EXPECT( context, pinned.verify() == 0) ;
		DRIVERCRATE_EXPECT( context, probeRegisteredStoreFileAccess( alias, GENERIC_WRITE) ==
										ERROR_SHARING_VIOLATION) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ合成INFからクラス登録の正負例と用途境界を検証する
 * @param[in,out] context 検証結果を集計する所有先
 * @note 元CATの署名や導入を試験成功として数えない
 */
//------------------------------------------------------------------------------
void declarativeSetupClassMatrix( TestContext &context)
{
	using Purpose = OfficialInfInspectionPurpose ;
	// 同じINFの登録を変更して用途と作用を比較する
	constexpr std::string_view BASE =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=FixtureDisplaySupport\r\n"
		"ClassGUID={e3c601e9-19bc-4c05-91b9-7a5b192cf804}\r\nProvider=Fixture Vendor\r\n"
		"DriverVer=11/19/2026,2.0.0.0\r\nCatalogFile=sample.cat\r\n"
		"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
		"Device=Install,PCI\\SYNTH_DECLARATIVE_CLASS\r\n"
		"[Install.NT]\r\nCopyFiles=DriverFiles\r\n"
		"[Install.NT.Services]\r\nAddService=FixtureKernel,2,KernelService\r\n"
		"[KernelService]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\sample.sys\r\n[DestinationDirs]\r\nDriverFiles=12\r\n"
		"[DriverFiles]\r\nsample.sys\r\n[SourceDisksNames]\r\n1=fixture,,,\r\n"
		"[SourceDisksFiles]\r\nsample.sys=1\r\n"
		"[ClassInstall32]\r\nAddReg=ClassValues\r\n[ClassValues]\r\n"
		"HKR,,,,%FriendlyClass%\r\nHKR,,Icon,,\"-10\"\r\n"
		"[Strings]\r\nFriendlyClass=\"Fixture display support\"\r\n" ;
	const struct {
		std::string_view before ;		// 置換する元の値
		std::string_view after ;		// 置換後の値
		Purpose			 purpose ;		// 同じ構造入口へ渡す用途
		bool			 pass ;			// 期待する構造判定
		bool			 extended{} ;	// 非手動追加指定と旧節を持つ収集用の元形
	} cases[]{
		{"", "", Purpose::COLLECTOR_CONTENT, true},
		{"", "", Purpose::DEVICE_STORAGE_CANDIDATE, true},
		{"", "", Purpose::STANDARD_DRIVER, false},
		{"", "", Purpose::REQUIRED_COLLECTOR_IMPORT, false},
		{"[ClassInstall32]", "[ClassInstall32.ntamd64]", Purpose::COLLECTOR_CONTENT, true},
		{"HKR,,Icon,,\"-10\"\r\n", "", Purpose::COLLECTOR_CONTENT, true},
		{"HKR,,Icon,,\"-10\"", "HKR,,Icon,0x0,\"-10\"", Purpose::COLLECTOR_CONTENT, true},
		{"HKR,,Icon,,\"-10\"", "HKR,,Icon,,\"10\"", Purpose::COLLECTOR_CONTENT, false},
		{"HKR,,Icon,,\"-10\"", "HKR,,Installer32,,\"fixture.dll,Install\"",
		 Purpose::COLLECTOR_CONTENT, false},
		{"HKR,,Icon,,\"-10\"", "HKR,,UpperFilters,0x10000,Fixture", Purpose::COLLECTOR_CONTENT,
		 false},
		{"HKR,,,,%FriendlyClass%", "HKR,SubKey,,,%FriendlyClass%", Purpose::COLLECTOR_CONTENT,
		 false},
		{"Fixture display support", "@fixture.dll,-10", Purpose::COLLECTOR_CONTENT, false},
		{"[Strings]", "[ClassValues.security]\r\n\"D:P(A;;GA;;;WD)\"\r\n[Strings]",
		 Purpose::COLLECTOR_CONTENT, false},
		{"CopyFiles=DriverFiles", "CopyFiles=DriverFiles\r\nAddReg=ClassValues",
		 Purpose::COLLECTOR_CONTENT, false},
		{"CopyFiles=DriverFiles", "CopyFiles=DriverFiles\r\nNeeds=ClassInstall32",
		 Purpose::COLLECTOR_CONTENT, false},
		{"[Strings]", "[ClassInstall32.ntamd64]\r\nAddReg=UnverifiedValues\r\n[Strings]",
		 Purpose::COLLECTOR_CONTENT, false},
		{"Class=FixtureDisplaySupport", "Class=SideShow", Purpose::COLLECTOR_CONTENT, false},
		{"{e3c601e9-19bc-4c05-91b9-7a5b192cf804}", "{88bae032-5a81-49f0-bc3d-a4ff138216d6}",
		 Purpose::COLLECTOR_CONTENT, false},
		{"Class=FixtureDisplaySupport",
		 "Class=FixtureDisplaySupport\r\nClass=FixtureDisplaySupport", Purpose::COLLECTOR_CONTENT,
		 false},
		{"", "", Purpose::COLLECTOR_CONTENT, true, true},
		{"", "", Purpose::DEVICE_STORAGE_CANDIDATE, false, true},
		{"[ClassInstall32]", "[ClassInstall32.NTamd64]", Purpose::COLLECTOR_CONTENT, true, true},
		{"[ClassInstall]\r\nAddReg=ClassValues\r\n", "", Purpose::COLLECTOR_CONTENT, true, true},
		{"[ClassInstall]\r\nAddReg=ClassValues\r\n", "", Purpose::DEVICE_STORAGE_CANDIDATE, false,
		 true},
		{"HKR,,NoInstallClass,,1\r\n", "", Purpose::COLLECTOR_CONTENT, true, true},
		{"HKR,,NoInstallClass,,1", "HKR,,NoInstallClass,,01", Purpose::COLLECTOR_CONTENT, false,
		 true},
		{"HKR,,NoInstallClass,,1", "HKR,,NoInstallClass,0x10001,1", Purpose::COLLECTOR_CONTENT,
		 false, true},
		{"HKR,,NoInstallClass,,1", "HKR,,NoInstallClass,2,1", Purpose::COLLECTOR_CONTENT, false,
		 true},
		{"HKR,,NoInstallClass,,1", "HKR,OtherKey,NoInstallClass,,1", Purpose::COLLECTOR_CONTENT,
		 false, true},
		{"HKR,,NoInstallClass,,1", "HKR,,NoInstallClass,,%Marker%\r\n[Strings.0804]\r\nMarker=1",
		 Purpose::COLLECTOR_CONTENT, false, true},
		{"HKR,,NoInstallClass,,1", "HKR,,NoInstallClass,,1\r\nHKR,,noinstallclass,,1",
		 Purpose::COLLECTOR_CONTENT, false, true},
		{"[Strings]", "[ClassValues.security]\r\n\"D:P(A;;GA;;;WD)\"\r\n[Strings]",
		 Purpose::COLLECTOR_CONTENT, false, true},
		{"[ClassInstall]", "[ClassInstall.NTamd64]", Purpose::COLLECTOR_CONTENT, false, true},
		{"[ClassInstall]\r\nAddReg=ClassValues", "[ClassInstall]\r\nNeeds=ClassValues",
		 Purpose::COLLECTOR_CONTENT, false, true},
		{"[ClassInstall]\r\nAddReg=ClassValues", "[ClassInstall]\r\nAddReg=ClassValues,ClassValues",
		 Purpose::COLLECTOR_CONTENT, false, true},
		{"[Strings]",
		 "[ClassInstall32.NTamd64]\r\nAddReg=OtherValues\r\n"
		 "[OtherValues]\r\nHKR,,,,Other\r\n[Strings]",
		 Purpose::COLLECTOR_CONTENT, false, true},
		{"[Strings]", "[ClassInstall]\r\n[Strings]", Purpose::COLLECTOR_CONTENT, false, true},
		{"Device=Install,", "Device=ClassInstall,", Purpose::COLLECTOR_CONTENT, false, true},
		{"Device=Install,", "Device=ClassInstall32,", Purpose::COLLECTOR_CONTENT, false, true},
		{"AddService=FixtureKernel,2,KernelService", "AddService=FixtureKernel,2,ClassInstall",
		 Purpose::COLLECTOR_CONTENT, false, true},
		{"CopyFiles=DriverFiles", "CopyFiles=DriverFiles,ClassInstall", Purpose::COLLECTOR_CONTENT,
		 false, true},
		{"Device=Install,", "Device=%FriendlyClass%,", Purpose::COLLECTOR_CONTENT, false, true},
		{"[Strings.0804]\r\nFriendlyClass=\"Localized display support\"",
		 "[Strings.0804]\r\n"
		 "FriendlyClass=ClassInstall32",
		 Purpose::COLLECTOR_CONTENT, false, true},
		{"CopyFiles=DriverFiles", "CopyFiles=DriverFiles\r\nNeeds=%FriendlyClass%%FriendlyClass%",
		 Purpose::COLLECTOR_CONTENT, false, true},
	} ;

	constexpr std::wstring_view classes[]{L"Display"} ;			// 既存Class許可一覧
	constexpr std::wstring_view signatures[]{L"$Windows NT$"} ;	// 通常のINF署名宣言
	std::uint64_t				identity = 820U ;				// 各例が所有するworkspace番号
	// 全例を同じ公式INF構造検査へ入力する
	for( const auto &example : cases) {
		std::string body( BASE) ;	// 各例は同じ未変更のfixtureから始める
		// 新しい形は同じ登録先の旧節と既定の表示名を別言語でも用意する
		if( example.extended) {
			body.insert( body.find( "[ClassValues]"), "[ClassInstall]\r\nAddReg=ClassValues\r\n") ;
			body.insert( body.find( "[Strings]"), "HKR,,NoInstallClass,,1\r\n") ;
			body += "[Strings.0804]\r\nFriendlyClass=\"Localized display support\"\r\n" ;
		}

		// 正負例に必要な元行だけを差し替える
		if( !example.before.empty()) {
			body.replace( body.find( example.before), example.before.size(), example.after) ;
		}

		OfficialDownloadWorkspace workspace ;	// この例に限る元ファイルの所有先
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"declarative-class-test", identity) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		const std::array			entries{OfficialZipEntry{L"sample.inf", body.size()},
									OfficialZipEntry{L"sample.cat", 1U},
									OfficialZipEntry{L"sample.sys", 1U}} ;		// 構造試験用の一覧
		OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;	// 各用途の構造条件
		policy.acceptAnyProvider	= true ;
		policy.rejectInstallActions = true ;
		policy.purpose				= example.purpose ;
		OfficialInfPackage package ;	// 全構造が成立した場合に返る結果
		// 元署名を検査する前の構造判定
		const auto		   error =
			inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ;
		context.expect( (error == 0) == example.pass,
					   "declarative class " + std::to_string( identity++) + " error " +
						   std::to_string( error),
					   __FILE__, __LINE__) ;
		// 正例でも端末の読み取り結果と導入用途を分ける
		if( error == 0) {
			DRIVERCRATE_EXPECT( context, package.className == L"FixtureDisplaySupport") ;
			DRIVERCRATE_EXPECT( context, !package.classGuid.empty()) ;
			DRIVERCRATE_EXPECT( context, package.inspectionPurpose ==
											(example.purpose == Purpose::DEVICE_STORAGE_CANDIDATE
												 ? Purpose::DECLARATIVE_CLASS_CONTENT
												 : Purpose::COLLECTOR_CONTENT)) ;
			DRIVERCRATE_EXPECT( context,
							   !package.collectorClassInfSha256.empty() == example.extended) ;
			// 追加形式で保持した原ハッシュと後続CATへ渡すINFの差替え拒否を確認する
			if( example.extended) {
				const auto	 path = workspace.path( L"sample.inf") ;	// 同じ試験領域の架空INF
				std::wstring actual ;									// 変更前の元バイトを別の呼出しで計算する
				DRIVERCRATE_EXPECT( context, computeFileSha256( path, actual) == 0 &&
												actual == package.collectorClassInfSha256) ;
				std::ofstream changed( std::filesystem::path( path),
									  std::ios::binary |
										  std::ios::app) ;	// 架空INFだけを書き換える出力
				changed << "; Different fixture bytes\r\n" ;
				changed.close() ;
				DRIVERCRATE_EXPECT( context, changed.good()) ;
				DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) ==
												static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
			}
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief AMD64の全Modelsから到達する元ファイルと従来用途の全面照合を検証する
 * @param[in,out] context 構造判定と成功時の参照集合を集計する所有先
 * @note SetupAPIへ合成INFを読み取り用に渡す。CATとSYSは媒体一覧で表す
 */
//------------------------------------------------------------------------------
void activeAmd64SourceMatrix( TestContext &context)
{
	using Purpose					   = OfficialInfInspectionPurpose ;
	constexpr std::string_view INSTALL =	// 通常選択のカーネルサービスとローカルコピー
		"[Install.NT]\r\nCopyFiles=DriverFiles\r\n"
		"[Install.NT.Services]\r\nAddService=FixtureKernel,2,KernelService\r\n" ;
	constexpr std::string_view OLDER_INSTALL =	// 現在のWindowsが選ばない旧OS側だけで使う追加コピー
		"Older=Alternate,PCI\\SYNTH_AMD64_OLDER\r\n"
		"[Alternate.NT]\r\nCopyFiles=DriverFiles,AlternateFiles\r\n"
		"[Alternate.NT.Services]\r\nAddService=FixtureKernel,2,KernelService\r\n"
		"[AlternateFiles]\r\noptional.sys" ;
	// 版を限定しないNTの選択節だけが使う元ファイル
	const auto platformFallback = std::string( "Older=Install,PCI\\SYNTH_AMD64_OLDER\r\n"
											  "[Models.NT]\r\n") +
								  std::string( OLDER_INSTALL) ;
	// 版を限定しないAMD64の選択節だけが使う元ファイル
	const auto amd64Fallback = std::string( "Older=Install,PCI\\SYNTH_AMD64_OLDER\r\n"
										   "[Models.NTamd64]\r\n") +
							   std::string( OLDER_INSTALL) ;
	constexpr std::string_view NULL_MODEL =	// 通常選択のModelsに同居する無作用の明示null
		"Current=Install,PCI\\SYNTH_AMD64_CURRENT\r\n"
		"NullDevice=NoDriver,PCI\\SYNTH_AMD64_NULL\r\n"
		"[NoDriver.NT]\r\n[NoDriver.NT.Services]\r\nAddService=,2" ;
	constexpr std::string_view MEDIA =	// どの導入にも使わない元宣言を含む共通媒体表
		"[DriverFiles]\r\nsample.sys\r\n[SourceDisksNames]\r\n1=fixture,,,\r\n"
		"[SourceDisksFiles]\r\nsample.sys=1\r\noptional.sys=1\r\n" ;
	constexpr std::string_view OVERLAY_MEDIA =	// AMD64専用表と、その表にない共通行を使う媒体
		"[DriverFiles]\r\nsample.sys\r\namd64.sys\r\n[SourceDisksNames]\r\n1=fixture,,,\r\n"
		"[SourceDisksFiles.amd64]\r\namd64.sys=1,arch\r\narch-unused.sys=1,arch\r\n"
		"[SourceDisksFiles]\r\nsample.sys=1\r\noptional.sys=1\r\n" ;
	const struct {
		/// 失敗時に対応する合成条件の名前
		std::string_view  name ;
		/// 同INF入口で切り替える検査用途
		Purpose			  purpose ;
		/// 変更する元INFの単一部分。空なら元のまま使用する
		std::string_view  before ;
		/// 変更後の元INFの部分
		std::string_view  after ;
		/// 主ドライバーを同媒体の一覧に置く場合true
		bool			  driverPresent ;
		/// 同じ媒体一覧に置く追加ファイルの相対位置。空なら追加しない
		std::wstring_view additionalSource ;
		/// 期待する構造判定
		bool			  pass ;
	} cases[]{
		{"collector unused source", Purpose::COLLECTOR_CONTENT, {}, {}, true, {}, true},
		{"device declarative unused source",
		 Purpose::DEVICE_STORAGE_CANDIDATE,
		 {},
		 {},
		 true,
		 {},
		 true},
		{"missing active source",
		 Purpose::COLLECTOR_CONTENT,
		 {},
		 {},
		 false,
		 L"optional.sys",
		 false},
		{"unmaterialized compressed source",
		 Purpose::COLLECTOR_CONTENT,
		 {},
		 {},
		 false,
		 L"sample.sy_",
		 false},
		{"AMD64 and common media sources", Purpose::COLLECTOR_CONTENT, MEDIA, OVERLAY_MEDIA, true,
		 L"arch\\amd64.sys", true},
		{"missing common media source", Purpose::COLLECTOR_CONTENT, MEDIA, OVERLAY_MEDIA, false,
		 L"arch\\amd64.sys", false},
		{"missing AMD64 media source",
		 Purpose::COLLECTOR_CONTENT,
		 MEDIA,
		 OVERLAY_MEDIA,
		 true,
		 {},
		 false},
		{"older AMD64 source", Purpose::COLLECTOR_CONTENT, "Older=Install,PCI\\SYNTH_AMD64_OLDER",
		 OLDER_INSTALL, true, L"optional.sys", true},
		{"missing older AMD64 source",
		 Purpose::COLLECTOR_CONTENT,
		 "Older=Install,PCI\\SYNTH_AMD64_OLDER",
		 OLDER_INSTALL,
		 true,
		 {},
		 false},
		{"missing NT fallback source",
		 Purpose::COLLECTOR_CONTENT,
		 "Older=Install,PCI\\SYNTH_AMD64_OLDER",
		 platformFallback,
		 true,
		 {},
		 false},
		{"missing AMD64 fallback source",
		 Purpose::COLLECTOR_CONTENT,
		 "Older=Install,PCI\\SYNTH_AMD64_OLDER",
		 amd64Fallback,
		 true,
		 {},
		 false},
		{"explicit empty target Models",
		 Purpose::COLLECTOR_CONTENT,
		 "Older=Install,PCI\\SYNTH_AMD64_OLDER",
		 {},
		 true,
		 {},
		 true},
		{"unreadable older AMD64 install",
		 Purpose::COLLECTOR_CONTENT,
		 "Older=Install",
		 "Older=MissingInstall",
		 true,
		 {},
		 false},
		{"unreadable older AMD64 Models",
		 Purpose::COLLECTOR_CONTENT,
		 "[Models.NTamd64.6.2]",
		 "[UnlistedModels.NTamd64.6.2]",
		 true,
		 {},
		 false},
		{"missing renamed source",
		 Purpose::COLLECTOR_CONTENT,
		 "[DriverFiles]\r\nsample.sys",
		 "[DriverFiles]\r\nsample.sys\r\nalias.sys,optional.sys",
		 true,
		 {},
		 false},
		{"service binary not copied",
		 Purpose::COLLECTOR_CONTENT,
		 "ServiceBinary=%12%\\sample.sys",
		 "ServiceBinary=%11%\\sample.sys",
		 true,
		 {},
		 false},
		{"service description refers to a source",
		 Purpose::COLLECTOR_CONTENT,
		 "ServiceBinary=%12%\\sample.sys",
		 "ServiceBinary=%12%\\sample.sys\r\nDescription=\"@%12%\\optional.sys,-1\"",
		 true,
		 {},
		 false},
		{"unknown active directive",
		 Purpose::COLLECTOR_CONTENT,
		 "CopyFiles=DriverFiles",
		 "CopyFiles=DriverFiles\r\nFixtureUnknown=optional.sys",
		 true,
		 {},
		 false},
		{"mixed kernel and null",
		 Purpose::COLLECTOR_CONTENT,
		 "Current=Install,PCI\\SYNTH_AMD64_CURRENT",
		 NULL_MODEL,
		 true,
		 {},
		 true},
		{"malformed mixed null",
		 Purpose::COLLECTOR_CONTENT,
		 "Current=Install,PCI\\SYNTH_AMD64_CURRENT",
		 "Current=Install,PCI\\SYNTH_AMD64_CURRENT\r\nNullDevice=NoDriver,PCI\\SYNTH_AMD64_NULL\r\n"
		 "[NoDriver.NT]\r\n[NoDriver.NT.Services]\r\nAddService=,0",
		 true,
		 {},
		 false},
		{"pure null root",
		 Purpose::COLLECTOR_CONTENT,
		 INSTALL,
		 "[Install.NT]\r\n[Install.NT.Services]\r\nAddService=,2\r\n",
		 true,
		 {},
		 false},
		{"legacy complete source table",
		 Purpose::STANDARD_DRIVER,
		 {},
		 {},
		 true,
		 L"optional.sys",
		 true},
		{"legacy missing table source", Purpose::STANDARD_DRIVER, {}, {}, true, {}, false},
	} ;

	constexpr std::wstring_view classes[]{L"Display"} ;			// 標準クラスの許可値
	constexpr std::wstring_view signatures[]{L"$Windows NT$"} ;	// 通常のINF署名宣言
	std::uint64_t				identity = 850U ;				// 各例の独立workspace番号
	// 同じ媒体表で変えた導入分岐と実在ファイルを構造入口から検査する
	for( const auto &example : cases) {
		const bool	device = example.purpose == Purpose::DEVICE_STORAGE_CANDIDATE ;	// 端末読取用途
		std::string body   = "[Version]\r\nSignature=\"$Windows NT$\"\r\n" ;		// 合成INFの所有byte
		body +=
			device
				? "Class=FixtureDisplaySupport\r\nClassGUID={e3c601e9-19bc-4c05-91b9-7a5b192cf804}\r\n"
				: "Class=Display\r\nClassGUID={4d36e968-e325-11ce-bfc1-08002be10318}\r\n" ;
		body +=
			"Provider=Fixture Vendor\r\nDriverVer=11/19/2026,2.0.0.0\r\nCatalogFile=sample.cat\r\n"
			"[Manufacturer]\r\nVendor=Models,NTamd64.6.2,NTamd64.10.0...16299\r\n"
			"[Models.NTamd64.6.2]\r\nOlder=Install,PCI\\SYNTH_AMD64_OLDER\r\n"
			"[Models.NTamd64.10.0...16299]\r\nCurrent=Install,PCI\\SYNTH_AMD64_CURRENT\r\n" ;
		body.append( INSTALL) ;
		body +=
			"[KernelService]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
			"ServiceBinary=%12%\\sample.sys\r\n[DestinationDirs]\r\nDriverFiles=12\r\nAlternateFiles=12\r\n" ;
		body.append( MEDIA) ;
		// 端末の正例は独自クラスの明示的な読み取り用途を通す
		if( device) {
			body += "[ClassInstall32]\r\nAddReg=ClassValues\r\n[ClassValues]\r\n"
					"HKR,,,,\"Fixture display support\"\r\nHKR,,Icon,,\"-10\"\r\n" ;
		}

		// 各条件の差分を本来の元部分へ一度だけ適用する
		if( !example.before.empty()) {
			const auto position = body.find( example.before) ;	// 合成INF内の置換位置
			DRIVERCRATE_EXPECT( context, position != body.npos) ;
			// 元部分に変更があれば古い条件を試験成功へ数えない
			if( position == body.npos) {
				continue ;
			}

			body.replace( position, example.before.size(), example.after) ;
		}

		OfficialDownloadWorkspace workspace ;	// この例だけのINFを閉じる所有先
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"active-amd64-source-test", identity++) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		// 構造検査の元媒体一覧。CATは後段署名検証まで読み込まない
		std::vector<OfficialZipEntry> entries{{L"sample.inf", body.size()}, {L"sample.cat", 1U}} ;
		// 現在の選択が使うSYSの有無を構造用一覧へ反映する
		if( example.driverPresent) {
			entries.push_back( {L"sample.sys", 1U}) ;
		}

		// この条件の追加ファイルを一覧へ置く。圧縮名は展開せずに渡す
		if( !example.additionalSource.empty()) {
			entries.push_back( {std::wstring( example.additionalSource), 1U}) ;
		}

		OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;	// 同公式構造の用途
		policy.acceptAnyProvider					   = true ;
		policy.rejectInstallActions					   = true ;
		policy.allowRequiredDriverComponents		   = true ;
		policy.allowReferencedExecutablesForContent	   = true ;
		policy.allowWindowsManagedDriverDataForContent = true ;
		policy.purpose								   = example.purpose ;
		OfficialInfPackage package ;	// 全構造が成立した場合に返る内容
		const auto		   error =		// 署名の前段でSetupAPIから取得する構造判定
			inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ;
		context.expect( (error == 0) == example.pass,
					   std::string( example.name) + " error " + std::to_string( error), __FILE__,
					   __LINE__) ;
		// 正例は全参照を保持し、端末の独自クラスに導入用途を与えない
		if( example.pass && error == 0) {
			const auto expectedFiles = example.additionalSource.empty() ? 1U : 2U ;	// 元参照数
			DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == expectedFiles) ;
			DRIVERCRATE_EXPECT( context, std::ranges::find( package.sourceFiles, L"sample.sys") !=
											package.sourceFiles.end()) ;
			// 追加の必要ファイルは別表の元相対位置も維持する
			if( !example.additionalSource.empty()) {
				DRIVERCRATE_EXPECT(
					context, std::ranges::find( package.sourceFiles, example.additionalSource) !=
								 package.sourceFiles.end()) ;
			}

			DRIVERCRATE_EXPECT( context,
							   package.inspectionPurpose ==
								   (device ? Purpose::DECLARATIVE_CLASS_CONTENT : example.purpose)) ;
			// 混在するnull行を使う元IDも読み取り結果に残す
			if( example.after == NULL_MODEL) {
				DRIVERCRATE_EXPECT(
					context, std::ranges::find( package.hardwareIds, L"PCI\\SYNTH_AMD64_NULL") !=
								 package.hardwareIds.end()) ;
			}
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じAMD64 Modelsの元行と現在OSのクラス登録を判定する
 * @param[in,out] context 読取り専用ケースの集計先
 * @note 互換nodeの結果はfixtureで渡し、実機への選択や導入は行わない
 */
//------------------------------------------------------------------------------
void selectedModelRoleMatrix( TestContext &context)
{
	using Role							= OfficialInfSelectedModelRole ;
	constexpr std::string_view ORIGINAL =	// 複数IDの実ドライバーと無作用のnullを同じModelsに置く
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=FixtureModelRoles\r\n"
		"ClassGUID={e3c601e9-19bc-4c05-91b9-7a5b192cf804}\r\nProvider=Fixture Vendor\r\n"
		"DriverVer=11/19/2026,2.0.0.0\r\nCatalogFile=sample.cat\r\n"
		"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
		"Kernel=Install,PCI\\SYNTH_KERNEL,PCI\\SYNTH_COMPAT_ONE,PCI\\SYNTH_COMPAT_TWO\r\n"
		"Null=NoDriver,PCI\\SYNTH_NULL\r\n"
		"[Install.NT]\r\nCopyFiles=DriverFiles\r\n"
		"[Install.NT.Services]\r\nAddService=FixtureKernel,2,KernelService\r\n"
		"[KernelService]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\sample.sys\r\n[NoDriver.NT]\r\n[NoDriver.NT.Services]\r\nAddService=,2\r\n"
		"[DestinationDirs]\r\nDriverFiles=12\r\n[DriverFiles]\r\nsample.sys\r\n"
		"[SourceDisksNames]\r\n1=fixture,,,\r\n[SourceDisksFiles]\r\nsample.sys=1\r\n"
		"[ClassInstall32]\r\nAddReg=ClassName\r\n[ClassName]\r\nHKR,,,,Fixture\r\n" ;
	const std::array kernel{std::wstring( L"PCI\\SYNTH_KERNEL"),
							std::wstring( L"PCI\\SYNTH_COMPAT_ONE"),
							// Hardware IDと互換IDの元順
							std::wstring( L"PCI\\SYNTH_COMPAT_TWO")} ;
	const std::array nullRow{std::wstring( L"PCI\\SYNTH_NULL")} ;	// null行が持つ元Hardware ID
	const std::array reordered{kernel[0], kernel[2], kernel[1]} ;	// 互換IDの順序だけが異なる観測
	const std::array partial{kernel[0], kernel[1]} ;				// 元IDの一部しか返さない観測
	/** @brief 照合済みINFから得る予定のクラス登録情報 */
	struct ClassRegistrationExpected {
		/// OSが選ぶ元クラス節
		std::wstring_view  section ;
		/// 元クラス節から展開した表示名
		std::wstring_view  displayName ;
		/// 元クラス節の内蔵アイコン番号
		std::optional<int> icon ;
	} ;
	const struct {
		const wchar_t							*basic ;			// Windowsのnodeが返した基本DDInstall名
		std::span<const std::wstring>			 ids ;				// 当該nodeの全ID
		const wchar_t							*models ;			// 原recordで照合したModels節
		std::string_view						 before ;			// この例で変更する元INF内の文字列
		std::string_view						 after ;			// 変更後の文字列
		DWORD									 error ;			// 期待するWin32診断
		Role									 role ;				// 完全成功時の作用
		std::optional<ClassRegistrationExpected> registration{} ;	// 実ドライバーだけの元表示
		bool									 changeHash{} ;		// 異なる元INFハッシュの入力
	} cases[]{
		{L"Install",
		 kernel,
		 L"Models.NTamd64",
		 {},
		 {},
		 0U,
		 Role::KERNEL_DRIVER,
		 ClassRegistrationExpected{L"ClassInstall32", L"Fixture", std::nullopt}},
		{L"NoDriver", nullRow, L"Models.NTamd64", {}, {}, 0U, Role::NULL_DRIVER},
		{L"Install", nullRow, L"Models.NTamd64", {}, {}, ERROR_NOT_FOUND, Role::UNASSESSED},
		{L"Install", reordered, L"Models.NTamd64", {}, {}, ERROR_NOT_FOUND, Role::UNASSESSED},
		{L"Install", partial, L"Models.NTamd64", {}, {}, ERROR_NOT_FOUND, Role::UNASSESSED},
		{L"NoDriver",
		 nullRow,
		 L"Models.NTamd64.6.2",
		 {},
		 {},
		 ERROR_REVISION_MISMATCH,
		 Role::UNASSESSED},
		{L"NoDriver", nullRow, L"Models.NTamd64", "Null=NoDriver,PCI\\SYNTH_NULL",
		 "Null=NoDriver,PCI\\SYNTH_NULL\r\nDuplicate=NoDriver,PCI\\SYNTH_NULL", ERROR_DUP_NAME,
		 Role::UNASSESSED},
		{L"NoDriver", nullRow, L"Models.NTamd64", "AddService=,2", "AddService=,0",
		 ERROR_NOT_SUPPORTED, Role::UNASSESSED},
		{L"NoDriver", nullRow, L"Models.NTamd64", "[NoDriver.NT.Services]",
		 "[NoDriver.NT.HW]\r\nAddReg=ClassName\r\n[NoDriver.NT.Services]", ERROR_NOT_SUPPORTED,
		 Role::UNASSESSED},
		{L"Install", kernel, L"Models.NTamd64", "AddService=FixtureKernel,2,KernelService",
		 "AddService=FixtureKernel,0,KernelService", ERROR_NOT_SUPPORTED, Role::UNASSESSED},
		{L"Install", kernel, L"Models.NTamd64", "HKR,,,,Fixture",
		 "HKR,,,,Fixture\r\n[ClassInstall32.NT]\r\nAddReg=ClassNameNt\r\n"
		 "[ClassNameNt]\r\nHKR,,,,Fixture NT\r\nHKR,,Icon,,-7",
		 0U, Role::KERNEL_DRIVER,
		 ClassRegistrationExpected{L"ClassInstall32.NT", L"Fixture NT", -7}},
		{L"Install", kernel, L"Models.NTamd64", "HKR,,,,Fixture",
		 "HKR,,,,Fixture\r\n[ClassInstall32.NT]\r\nAddReg=ClassNameNt\r\n"
		 "[ClassNameNt]\r\nHKR,,,,Fixture NT\r\n[ClassInstall32.NTamd64]\r\n"
		 "AddReg=ClassNameX64\r\n[ClassNameX64]\r\nHKR,,,,%Display%\r\nHKR,,Icon,,-10\r\n"
		 "[Strings]\r\nDisplay=\"Fixture x64\"",
		 0U, Role::KERNEL_DRIVER,
		 ClassRegistrationExpected{L"ClassInstall32.NTamd64", L"Fixture x64", -10}},
		{L"Install", kernel, L"Models.NTamd64", "HKR,,,,Fixture",
		 "HKR,,,,Fixture\r\n[ClassInstall32.NTx86]\r\nAddReg=OtherClassName\r\n"
		 "[OtherClassName]\r\nHKR,,,,Fixture x86",
		 0U, Role::KERNEL_DRIVER,
		 ClassRegistrationExpected{L"ClassInstall32", L"Fixture", std::nullopt}},
		{L"Install", kernel, L"Models.NTamd64", "HKR,,,,Fixture",
		 "HKR,,,,Fixture\r\n[ClassInstall32.NTamd64]\r\nAddReg=ClassNameX64\r\n"
		 "[ClassNameX64]\r\nHKR,,,,Fixture x64\r\nHKR,,Icon,,10",
		 ERROR_NOT_SUPPORTED, Role::UNASSESSED},
		{L"Install", kernel, L"Models.NTamd64", "[ClassInstall32]", "[IgnoreClassInstall32]",
		 ERROR_NOT_SUPPORTED, Role::UNASSESSED},
		{L"Install", kernel, L"Models.NTamd64", "HKR,,,,Fixture",
		 "HKR,,,,Fixture\r\nHKR,,Icon,,-10", ERROR_CRC, Role::UNASSESSED, std::nullopt, true},
	} ;

	std::uint64_t identity = 900U ;	// 各fixtureの保護領域を分ける番号
	// 全例を同じ元行照合の入口に渡す
	for( const auto &example : cases) {
		std::string body( ORIGINAL) ;	// この場合だけの元INF
		// 元文を限定した変更で同じ構造の正負例を作る
		if( !example.before.empty()) {
			body.replace( body.find( example.before), example.before.size(), example.after) ;
		}

		OfficialDownloadWorkspace workspace ;	// 元INFだけを保護する試験領域
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"selected-model-role", identity) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		OfficialInfPackage package ;	// このfixtureの内容用途と元ファイル
		package.infRelativePath	  = L"sample.inf" ;
		package.inspectionPurpose = OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ;
		package.sourceFiles		  = {L"sample.sys"} ;
		package.hardwareIds		  = {kernel[0], kernel[1], kernel[2], nullRow[0]} ;
		package.className		  = L"FixtureModelRoles" ;
		package.classGuid		  = L"{e3c601e9-19bc-4c05-91b9-7a5b192cf804}" ;
		std::wstring hash ;	// ここで固定した元INFのハッシュ
		DRIVERCRATE_EXPECT( context, computeFileSha256( workspace.path( L"sample.inf"), hash) == 0) ;
		const std::wstring unrelatedHash( 64U, L'0') ;	// 元INFに対応しない固定ハッシュ
		std::optional<OfficialInfDeclarativeClassRegistration> registration(
			std::in_place) ;						// 失敗時に残してはならない入力値
		Role	   role	 = Role::KERNEL_DRIVER ;	// 失敗時に未評価へ戻ることも確認する
		const auto error = inspectOfficialInfSelectedModelRole(
			workspace, package, example.changeHash ? unrelatedHash : hash, example.models,
			example.basic, example.ids, role, &registration) ;	// 元行と表示値の実照合
		context.expect( error == nativeErrorFromWin32( example.error) && role == example.role,
					   "selected model " + std::to_string( identity++) + " error " +
						   std::to_string( error),
					   __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context, registration.has_value() == example.registration.has_value()) ;
		// 完全に同じ元ハッシュへ結合した表示名とアイコンだけを保持する
		if( registration && example.registration) {
			DRIVERCRATE_EXPECT( context, registration->infSha256 == hash) ;
			DRIVERCRATE_EXPECT( context, registration->classGuid == package.classGuid) ;
			// Windowsが列挙した節の大小文字をINFの比較規則に合わせて確認する
			DRIVERCRATE_EXPECT( context,
							   stringsEqual( registration->section, example.registration->section)) ;
			DRIVERCRATE_EXPECT( context,
							   registration->displayName == example.registration->displayName) ;
			DRIVERCRATE_EXPECT( context, registration->builtInIcon == example.registration->icon) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 明示元INFの現在Models全行を元データのまま役割診断へ渡す
 * @param[in] inputPath 保存元INFのローカルパス
 * @param[in] sourceName 先行する全CAT検査で確認した同位置の元ファイル名
 * @return 全行の読取完了0、未評価または不正1
 * @note テスト用の選択行入力を作る。実機の互換node・署名・導入の合格には使用しない
 */
//------------------------------------------------------------------------------
int diagnoseOriginalModelRoles( const wchar_t *inputPath, const wchar_t *sourceName)
{
	std::ifstream	  input( std::filesystem::path( inputPath), std::ios::binary) ;	// 明示元INFの読取
	const std::string bytes( std::istreambuf_iterator<char>{input}, {}) ;			// 元byteを変更しない
	OfficialDownloadWorkspace workspace ;											// 診断の元INFだけを保持する
	// 保存済みの原本を変更せず有限な試験領域に固定する
	if( !input || bytes.empty() || bytes.size() > 4U * 1024U * 1024U ||
	   workspace.initialize( L"original-model-roles", 942U) != 0 ||
	   !writeWorkspaceFile( workspace, L"sample.inf", bytes)) {
		return 1 ;
	}

	const auto		   path = workspace.path( L"sample.inf") ;	// 同じ元データのテスト位置
	const UniqueInf	   inf( SetupOpenInfFileW( path.c_str(), nullptr,
											 INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											 nullptr)) ;	// 元Modelsを読むHINF
	OfficialInfPackage package ;							// テストで役割確認へ渡す元内容
	package.inspectionPurpose = OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ;
	package.infRelativePath	  = L"sample.inf" ;
	package.sourceFiles.emplace_back( sourceName) ;
	OfficialInfPublishedIdentity identity ;	// 現在OSが選ぶ元Modelsとハッシュ
	// Windowsが読める同じ元Modelsを前提とする
	if( inf.get() == INVALID_HANDLE_VALUE ||
	   readInfDirective( inf.get(), L"Version", L"Class", 1U, package.className) != 0 ||
	   collectHardwareIds( inf.get(), 4096U, package.hardwareIds) != 0 ||
	   readOfficialInfPublishedIdentity( workspace, package, identity) != 0) {
		return 1 ;
	}

	package.classGuid = identity.classGuid ;
	std::size_t nullDrivers{} ;		// 空サービスの行数
	std::size_t kernelDrivers{} ;	// 元ファイルを使う関連カーネルサービスの行数
	std::optional<OfficialInfDeclarativeClassRegistration>
		originalRegistration ;	// このINF全体で一つの登録情報
	// 元Modelsの全行を読み、各行のIDを架空の選択nodeへそのまま渡す
	for( const auto &model : identity.models) {
		INFCONTEXT row{} ;	// 元Modelsの一行
		// 一行も読めない節を診断合格に含めない
		if( !SetupFindFirstLineW( inf.get(), model.modelSection.c_str(), nullptr, &row)) {
			return 1 ;
		}

		// 元行の完全な基本節とID列だけで判定する
		do {
			std::wstring			  basic ;	// 元行の基本DDInstall名
			std::vector<std::wstring> ids ;		// Hardware IDの後に元順のCompatible IDを置く
			// 元基本節の読取に失敗した場合は不明な役割として止める
			if( readInfField( row, 1U, basic) != 0) {
				return 1 ;
			}

			// 現在Modelsの元IDの種別と順序を保持する
			for( DWORD field = 2U; field <= SetupGetFieldCount( &row); ++field) {
				// 空のIDで不足を埋めない
				if( readInfField( row, field, ids.emplace_back()) != 0) {
					return 1 ;
				}
			}

			OfficialInfSelectedModelRole role{} ;	// 保護INFの元行だけの作用
			std::optional<OfficialInfDeclarativeClassRegistration>
				registration ;	// この行の初回クラス登録
			// 診断で元行を確定できた場合だけ集計する
			if( inspectOfficialInfSelectedModelRole( workspace, package, identity.infSha256,
												   model.modelSection, basic, ids, role,
												   &registration) != 0 ||
			   (registration.has_value() !=
				(role == OfficialInfSelectedModelRole::KERNEL_DRIVER))) {
				return 1 ;
			}

			// 一つの元INFの実行行は全て同じ初回登録情報へ結びます
			if( registration) {
				// 別の節や値が返る行を合計へ含めません
				if( originalRegistration && originalRegistration != registration) {
					return 1 ;
				}

				originalRegistration = std::move( registration) ;
			}

			nullDrivers += role == OfficialInfSelectedModelRole::NULL_DRIVER ? 1U : 0U ;
			kernelDrivers += role == OfficialInfSelectedModelRole::KERNEL_DRIVER ? 1U : 0U ;
		} while( SetupFindNextLine( &row, &row)) ;
	}

	std::cout << "modelIds=" << package.hardwareIds.size() << " nullRows=" << nullDrivers
			  << " driverRows=" << kernelDrivers
			  << " classRegistration=" << originalRegistration.has_value() << " icon="
			  << (originalRegistration ? originalRegistration->builtInIcon.value_or( 0) : 0)
			  << " nativeDeviceSelection=0 install=0\n" ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ本製品の可変長ID読取でWindowsの型付きID境界を確認する
 * @param[in,out] context 正負例の集計先
 * @note Windowsが返す長さと終端の組を使い、列挙や導入は行わない
 */
//------------------------------------------------------------------------------
void nativeModelIdBufferMatrix( TestContext &context)
{
	constexpr wchar_t hardware[]{L'H', L'W', L'\0'} ;		// Hardware IDだけの単一終端
	constexpr wchar_t compatible[]		= L"HW\0C1\0C2\0" ;	// Hardware IDと二重終端の互換ID列
	constexpr wchar_t emptyCompatible[] = L"HW\0\0C2\0" ;	// 途中に空の互換IDがある原バッファ
	const struct {
		std::span<const wchar_t> buffer ;	// APIが返した実バッファ
		std::size_t				 offset ;	// 互換IDの開始位置
		std::size_t				 length ;	// 互換IDの文字数
		bool					 expected ;	// 形式の成立
	} cases[]{
		{hardware, 3U, 0U, true},	  {compatible, 3U, 7U, true},  {compatible, 0U, 7U, false},
		{compatible, 11U, 0U, false}, {compatible, 3U, 8U, false}, {compatible, 2U, 7U, false},
		{compatible, 3U, 6U, false},  {compatible, 3U, 1U, false}, {emptyCompatible, 3U, 5U, false},
	} ;
	// 既定終端、二重終端と破損境界を同じdecoderへ渡す
	for( const auto &example : cases) {
		std::vector<std::wstring> ids ;	// 成功例の原ID列
		const bool				  accepted = driver_store_inf_detail::readDriverModelIds(
			   example.buffer, example.offset, example.length, ids) ;	// 製品と同じ判定
		DRIVERCRATE_EXPECT( context, accepted == example.expected) ;
		// 受理例はHardware IDの後の互換ID順も確認する
		if( accepted) {
			const auto expected =
				example.length == 0U
					? std::vector<std::wstring>{L"HW"}
					: std::vector<std::wstring>{L"HW", L"C1", L"C2"} ;	// 種別と原順の期待列
			DRIVERCRATE_EXPECT( context, ids == expected) ;
		}
	}
}

//------------------------------------------------------------------------------
// 独自クラスの登録と作用の読み取り
//------------------------------------------------------------------------------

// 合成INFが宣言する対象クラス
constexpr GUID FIXTURE_TARGET_CLASS{
	0xe3c601e9, 0x19bc, 0x4c05, {0x91, 0xb9, 0x7a, 0x5b, 0x19, 0x2c, 0xf8, 0x04}} ;
// 初回導入で選択した架空の端末が現在持つ別クラス
constexpr GUID FIXTURE_SOURCE_CLASS{
	0x371a2c47, 0x83de, 0x43b4, {0x8a, 0x11, 0x94, 0x2f, 0x6a, 0x07, 0xb9, 0xee}} ;
// INF側の名前
constexpr wchar_t FIXTURE_TARGET_NAME[] = L"FixtureDisplaySupport" ;
// Windowsから別の大文字小文字で返る同じ名前
constexpr wchar_t FIXTURE_REGISTERED_NAME[] = L"fIXTUREdISPLAYsUPPORT" ;
// クラスとは独立したキーパス
constexpr wchar_t FIXTURE_COINSTALLER_KEY[] =
	L"SYSTEM\\CurrentControlSet\\Control\\CoDeviceInstallers" ;
// 対象GUIDで索引された値の名前
constexpr wchar_t	 FIXTURE_COINSTALLER_VALUE[] = L"{E3C601E9-19BC-4C05-91B9-7A5B192CF804}" ;
// 対象setup class側の四つの作用の元キー
constexpr std::array CLASS_EFFECT_KEYS{
	&DEVPKEY_DeviceClass_ClassInstaller, &DEVPKEY_DeviceClass_PropPageProvider,
	&DEVPKEY_DeviceClass_UpperFilters, &DEVPKEY_DeviceClass_LowerFilters} ;
// 選択端末側の四つの作用の元キー
constexpr std::array DEVICE_EFFECT_KEYS{&DEVPKEY_Device_DriverCoInstallers,
										&DEVPKEY_Device_DriverPropPageProvider,
										&DEVPKEY_Device_UpperFilters, &DEVPKEY_Device_LowerFilters} ;

/** @brief 一回のクラス名・GUID相互照会とクラスキーの人工応答 */
struct SetupClassRegistrationFixture {
	/// GUIDからの照会が失敗する場合の元Win32 error
	std::optional<DWORD> guidError{ERROR_INVALID_CLASS} ;
	/// クラスキーを開けない場合の元Win32 error
	std::optional<DWORD> classKeyError{ERROR_INVALID_CLASS} ;
	/// 名前からの照会が失敗する場合の元Win32 error
	std::optional<DWORD> reverseError ;
	/// GUIDに対して返す人工クラス名
	std::wstring_view	 name{FIXTURE_REGISTERED_NAME} ;
	/// 名前に対応すると返す最初のクラスGUID
	GUID				 reverseGuid{FIXTURE_TARGET_CLASS} ;
	/// 同名の登録数
	DWORD				 reverseCount{} ;
	/// 正常名取得で終端を含む返却長を報告する場合true
	bool				 reportNameLength{true} ;
} ;

// 両方向の照会が一つの同じクラスを確認する基本例
constexpr SetupClassRegistrationFixture REGISTERED_CLASS_FIXTURE{
	std::nullopt,		  std::nullopt, std::nullopt, FIXTURE_REGISTERED_NAME,
	FIXTURE_TARGET_CLASS, 1U,			true} ;

/** @brief 一つの既存プロパティまたはレジストリ値に返す元型と全byte */
struct ClassEffectValueFixture {
	/// 容量照会で返す元型
	DWORD					 type{} ;
	/// 容量照会と実読取りで返す元UTF-16単位。未設定は不在
	std::span<const wchar_t> value ;
	/// 容量照会の失敗を注入する場合の元Win32 error
	std::optional<DWORD>	 queryError ;
	/// 実読取り時だけ失敗させる場合の元Win32 error
	DWORD					 readError{} ;
	/// 実読取り時だけ変化させる型。0なら容量照会時と同一
	DWORD					 returnedType{} ;
	/// 実読取り時だけ報告する異常な実byte数
	std::optional<DWORD>	 returnedBytes ;
} ;

/** @brief テストの一呼出しだけに使う人工API状態と引数検証結果 */
struct SetupClassReadFixture {
	/// 作用を読む前の登録
	SetupClassRegistrationFixture				 registration ;
	/// 作用を読んだ後だけ別の登録状態を返す場合の元応答
	std::optional<SetupClassRegistrationFixture> nextRegistration ;
	/// クラス側の各作用をクラスキーで区別した応答
	std::array<ClassEffectValueFixture, 4U>		 classEffects ;
	/// 端末側の各作用を選択端末のキーで区別した応答
	std::array<ClassEffectValueFixture, 4U>		 deviceEffects ;
	/// クラスキーと独立したコインストーラーキーを開く元結果
	LSTATUS										 coKeyStatus{ERROR_FILE_NOT_FOUND} ;
	/// 対象GUIDで索引されたコインストーラー値
	ClassEffectValueFixture						 coInstaller ;
	/// クラスプロパティを照会した回数
	unsigned									 classReads{} ;
	/// 端末プロパティを照会した回数
	unsigned									 deviceReads{} ;
	/// 独立キーを開こうとした回数
	unsigned									 coOpens{} ;
	/// 独立値を照会した回数
	unsigned									 coReads{} ;
	/// 返した人工クラスキーの数
	unsigned									 classHandles{} ;
	/// 返した人工コインストーラーキーの数
	unsigned									 coHandles{} ;
	/// 閉じた人工クラスキーの数
	unsigned									 classCloses{} ;
	/// 閉じた人工コインストーラーキーの数
	unsigned									 coCloses{} ;
	/// 対象、プロパティ、キーまたは読取権限が契約外ならfalse
	bool										 callsValid{true} ;
} ;

thread_local SetupClassReadFixture	 setupClassReadFixture ;	// 呼出しスレッドの人工API状態

//------------------------------------------------------------------------------
/**
 * @brief 作用の読み取り前後に見せるクラスの人工応答を選ぶ
 * @return 作用を読む境界に達した後だけ、設定済みの後発登録を返す
 */
//------------------------------------------------------------------------------
const SetupClassRegistrationFixture &fixtureRegistration()
{
	return setupClassReadFixture.nextRegistration && setupClassReadFixture.coOpens != 0U
			   ? *setupClassReadFixture.nextRegistration
			   : setupClassReadFixture.registration ;
}

//------------------------------------------------------------------------------
/**
 * @brief 対象GUIDに対するWindowsのクラス名応答を模擬する
 * @param[in] guid 選択INFが宣言する対象GUID
 * @param[out] buffer 元のクラス名を受け取る同期バッファ
 * @param[in] size 終端を含めて格納できる文字数
 * @param[out] required 終端を含むクラス名の文字数
 * @return 容量と人工登録が成立した場合TRUE、失敗時は元Win32 errorを設定する
 */
//------------------------------------------------------------------------------
BOOL WINAPI fixtureSetupClassName( const GUID *guid, PWSTR buffer, DWORD size, PDWORD required)
{
	// 元端末のクラスや別クラスに置き換わっていたら不正を保持する
	if( !guid || !IsEqualGUID( *guid, FIXTURE_TARGET_CLASS) || !required) {
		setupClassReadFixture.callsValid = false ;
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	const auto &registration = fixtureRegistration() ;	// この照会の人工登録
	// 対象クラスの正式不在と、同じ境界で起きる失敗を区別する
	if( registration.guidError) {
		SetLastError( *registration.guidError) ;
		return FALSE ;
	}

	const auto length = static_cast<DWORD>( registration.name.size() + 1U) ;	// 終端込み
	*required		  = length ;
	// APIの容量照会では値を書かずに必要長を伝える
	if( !buffer || size < length) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::copy( registration.name.begin(), registration.name.end(), buffer) ;
	buffer[length - 1U] = L'\0' ;
	*required			= registration.reportNameLength ? length : 0U ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFの名前に対応する登録済みGUIDの列を模擬する
 * @param[in] name INFが宣言する名前
 * @param[out] buffer 容量が足りる場合にGUID列を受け取る同期バッファ
 * @param[in] size 格納できるGUID数
 * @param[out] required 対応するGUIDの総数
 * @return 正常照会は0件でもTRUE、失敗時は元Win32 errorを設定する
 */
//------------------------------------------------------------------------------
BOOL WINAPI fixtureSetupClassGuids( PCWSTR name, LPGUID buffer, DWORD size, PDWORD required)
{
	// Windowsから戻った表示名へ元INFの照会対象を差し替えない
	if( !name || std::wstring_view( name) != FIXTURE_TARGET_NAME || !required) {
		setupClassReadFixture.callsValid = false ;
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	const auto &registration = fixtureRegistration() ;	// この照会の人工登録
	// 失敗は登録0件の成功へ変えない
	if( registration.reverseError) {
		SetLastError( *registration.reverseError) ;
		return FALSE ;
	}

	*required = registration.reverseCount ;
	// 実APIと同様、必要なGUID列を部分成功として返さない
	if( *required > size || (*required != 0U && !buffer)) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	// 登録数に従い名前の衝突も人工列に残す
	for( DWORD index = 0U; index < *required; ++index) {
		buffer[index] = index == 0U ? registration.reverseGuid : FIXTURE_SOURCE_CLASS ;
	}

	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 対象GUIDのローカルクラスキーを開く読取APIを模擬する
 * @param[in] guid 選択INFの対象GUID
 * @param[in] access 読み取り専用のレジストリ権限
 * @param[in] flags DIOCR_INSTALLERを指定するクラスキー種別
 * @param[in] machine ローカルmachineのためnullptr
 * @param[in] reserved 予約引数のためnullptr
 * @return 人工ハンドル、または元Win32 errorを設定してINVALID_HANDLE_VALUE
 */
//------------------------------------------------------------------------------
HKEY WINAPI fixtureOpenSetupClass( const GUID *guid, REGSAM access, DWORD flags, PCWSTR machine,
								  PVOID reserved)
{
	// クラスキー以外へのアクセスや書込み権限を同じ成功へ通さない
	if( !guid || !IsEqualGUID( *guid, FIXTURE_TARGET_CLASS) || flags != DIOCR_INSTALLER || machine ||
	   reserved || (access & KEY_QUERY_VALUE) == 0U ||
	   (access & ~(KEY_READ | KEY_WOW64_64KEY)) != 0U) {
		setupClassReadFixture.callsValid = false ;
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return static_cast<HKEY>( INVALID_HANDLE_VALUE) ;
	}

	const auto &registration = fixtureRegistration() ;	// この照会の人工登録
	// クラスキーの正式不在と読取権限不足を別結果にする
	if( registration.classKeyError) {
		SetLastError( *registration.classKeyError) ;
		return static_cast<HKEY>( INVALID_HANDLE_VALUE) ;
	}

	++setupClassReadFixture.classHandles ;
	// 人工HKEYはこのAPI表のcloseだけへ返す識別用アドレス
	return reinterpret_cast<HKEY>( &setupClassReadFixture.classHandles) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選んだクラスまたは端末の作用をSetupAPIの二段階読取として返す
 * @param[in] key 候補の元プロパティキー
 * @param[in] keys 観測側に許される四つのキー
 * @param[in] effects 各キーの人工値
 * @param[out] type 元DEVPROPTYPE
 * @param[out] buffer 同期中に元byteを書き込む領域。容量照会時はnullptr
 * @param[in] size bufferのbyte数
 * @param[out] required 元値または実読取のbyte数
 * @return 実読取成功時TRUE、未登録・容量照会・人工失敗ではWin32 errorを設定してFALSE
 */
//------------------------------------------------------------------------------
BOOL fixtureSetupProperty( const DEVPROPKEY *key, const std::array<const DEVPROPKEY *, 4U> &keys,
						  const std::array<ClassEffectValueFixture, 4U> &effects, DEVPROPTYPE *type,
						  PBYTE buffer, DWORD size, PDWORD required)
{
	// 作用の取り違えや出力先欠落を人工不在と区別する
	if( !key || !type || !required) {
		setupClassReadFixture.callsValid = false ;
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 与えられた四つの元キーから完全に一致する人工値だけを読む
	for( std::size_t index = 0U; index < keys.size(); ++index) {
		// 隣の作用を選ばないようpidとfmtidを照合する
		if( !IsEqualDevPropKey( *key, *keys[index])) {
			continue ;
		}

		const auto &value = effects[index] ;	// 元キーに対応する人工作用
		// 不在と初回API失敗は別の元エラーを返す
		if( value.queryError || value.value.empty()) {
			SetLastError( value.queryError.value_or( ERROR_NOT_FOUND)) ;
			return FALSE ;
		}

		const auto bytes = static_cast<DWORD>( value.value.size_bytes()) ;	// 小さい合成値のbyte数
		*type			 = value.type ;
		*required		 = bytes ;
		// 容量照会と小さいバッファは書込みなしで応答する
		if( !buffer || size < bytes) {
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// 二回目までに消失した場合などの元API失敗を模擬する
		if( value.readError != ERROR_SUCCESS) {
			SetLastError( value.readError) ;
			return FALSE ;
		}

		std::memcpy( buffer, value.value.data(), bytes) ;
		*type	  = value.returnedType != 0U ? value.returnedType : value.type ;
		*required = value.returnedBytes.value_or( bytes) ;
		return TRUE ;
	}

	setupClassReadFixture.callsValid = false ;
	SetLastError( ERROR_INVALID_PARAMETER) ;
	return FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 対象setup classに対する作用の読取りを模擬する
 * @param[in] guid INF対象クラスのGUID
 * @param[in] key クラスの元プロパティキー
 * @param[out] type 元DEVPROPTYPE
 * @param[out] buffer 元byteの同期出力先。容量照会時はnullptr
 * @param[in] size bufferのbyte数
 * @param[out] required 元値または実読取のbyte数
 * @param[in] flags インストーラー用のクラスプロパティを指定する旗
 * @return 対象と旗が一致する場合だけ人工プロパティの読取結果を返す
 */
//------------------------------------------------------------------------------
BOOL WINAPI fixtureSetupClassProperty( const GUID *guid, const DEVPROPKEY *key, DEVPROPTYPE *type,
									  PBYTE buffer, DWORD size, PDWORD required, DWORD flags)
{
	++setupClassReadFixture.classReads ;
	// 元GUIDとsetup classの名前空間を同時に確認する
	if( !guid || !IsEqualGUID( *guid, FIXTURE_TARGET_CLASS) || flags != DICLASSPROP_INSTALLER) {
		setupClassReadFixture.callsValid = false ;
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	return fixtureSetupProperty( key, CLASS_EFFECT_KEYS, setupClassReadFixture.classEffects, type,
								buffer, size, required) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元端末の既存作用を保持するプロパティを模擬する
 * @param[in] set この試験の人工端末集合
 * @param[in] device 選択時点の元クラスと識別子を持つ端末
 * @param[in] key 端末の元プロパティキー
 * @param[out] type 元DEVPROPTYPE
 * @param[out] buffer 元byteの同期出力先。容量照会時はnullptr
 * @param[in] size bufferのbyte数
 * @param[out] required 元値または実読取のbyte数
 * @param[in] flags 予約済みのため0
 * @return 同じ選択端末と旗を確認した場合だけ人工プロパティの読取結果を返す
 */
//------------------------------------------------------------------------------
BOOL WINAPI fixtureSetupDeviceProperty( HDEVINFO set, PSP_DEVINFO_DATA device, const DEVPROPKEY *key,
									   DEVPROPTYPE *type, PBYTE buffer, DWORD size, PDWORD required,
									   DWORD flags)
{
	++setupClassReadFixture.deviceReads ;
	// 初回導入では元クラスのまま既存端末の作用を読む
	if( set != &setupClassReadFixture || !device || device->DevInst != 71U ||
	   !IsEqualGUID( device->ClassGuid, FIXTURE_SOURCE_CLASS) || flags != 0U) {
		setupClassReadFixture.callsValid = false ;
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	return fixtureSetupProperty( key, DEVICE_EFFECT_KEYS, setupClassReadFixture.deviceEffects, type,
								buffer, size, required) ;
}

//------------------------------------------------------------------------------
/**
 * @brief クラスキーとは独立したコインストーラーキーを模擬する
 * @param[in] root HKLMのローカルルート
 * @param[in] path コインストーラーの対応表が置かれる元キーパス
 * @param[in] options 予約引数のため0
 * @param[in] access 読み取り専用のレジストリ権限
 * @param[out] value 成功時は専用の人工ハンドル
 * @return 読みに使う権限を確認した場合の人工開錠結果
 */
//------------------------------------------------------------------------------
LSTATUS WINAPI fixtureOpenClassCoKey( HKEY root, LPCWSTR path, DWORD options, REGSAM access,
									 PHKEY value)
{
	++setupClassReadFixture.coOpens ;
	// 別のキーや書込み権限から同じ作用の読取を成立させない
	if( root != HKEY_LOCAL_MACHINE || !path ||
	   CompareStringOrdinal( path, -1, FIXTURE_COINSTALLER_KEY, -1, TRUE) != CSTR_EQUAL ||
	   options != 0U || !value || (access & KEY_QUERY_VALUE) == 0U ||
	   (access & ~(KEY_READ | KEY_WOW64_64KEY)) != 0U) {
		setupClassReadFixture.callsValid = false ;
		return ERROR_INVALID_PARAMETER ;
	}

	// キー不在と開錠拒否は人工ハンドルを発行しない
	if( setupClassReadFixture.coKeyStatus == ERROR_SUCCESS) {
		++setupClassReadFixture.coHandles ;
		// このAPI表のreadValueとcloseだけで使う人工HKEY
		*value = reinterpret_cast<HKEY>( &setupClassReadFixture.coHandles) ;
	}

	return setupClassReadFixture.coKeyStatus ;
}

//------------------------------------------------------------------------------
/**
 * @brief 対象GUIDで索引されたコインストーラー値を模擬する
 * @param[in] key 独立した人工コインストーラーキー
 * @param[in] name 対象GUIDのブレース付き文字列表現
 * @param[in] reserved 予約引数のためnullptr
 * @param[out] type 元のレジストリ型
 * @param[out] buffer 同期中に元byteを書き込む領域。容量照会時はnullptr
 * @param[in,out] size 入力ではbufferのbyte数、出力では必要または実byte数
 * @return この値の容量照会または実読取の人工LSTATUS
 */
//------------------------------------------------------------------------------
LSTATUS WINAPI fixtureReadClassCoValue( HKEY key, LPCWSTR name, LPDWORD reserved, LPDWORD type,
									   LPBYTE buffer, LPDWORD size)
{
	++setupClassReadFixture.coReads ;
	// GUIDと専用キーの両方を確かめ、クラスキー内の値に置き換えさせない
	if( key != reinterpret_cast<HKEY>( &setupClassReadFixture.coHandles) || !name ||
	   CompareStringOrdinal( name, -1, FIXTURE_COINSTALLER_VALUE, -1, TRUE) != CSTR_EQUAL ||
	   reserved || !type || !size) {
		setupClassReadFixture.callsValid = false ;
		return ERROR_INVALID_PARAMETER ;
	}

	const auto &value = setupClassReadFixture.coInstaller ;	// このGUIDだけの人工登録
	// 値不在と、同じ位置への照会失敗を元のLSTATUSへ分離する
	if( value.queryError || value.value.empty()) {
		return static_cast<LSTATUS>( value.queryError.value_or( ERROR_FILE_NOT_FOUND)) ;
	}

	const auto bytes	= static_cast<DWORD>( value.value.size_bytes()) ;	// 小さい合成値のbyte数
	const auto capacity = *size ;											// 実読取用の容量
	*type				= value.type ;
	*size				= bytes ;
	// RegQueryValueExWの容量照会は読取りを行わず成功する
	if( !buffer) {
		return ERROR_SUCCESS ;
	}

	// 用意された領域を越えて書き込まない
	if( capacity < bytes) {
		return ERROR_MORE_DATA ;
	}

	// 容量照会後の消失等を初回から不在だった場合と区別する
	if( value.readError != ERROR_SUCCESS) {
		return static_cast<LSTATUS>( value.readError) ;
	}

	std::memcpy( buffer, value.value.data(), bytes) ;
	*type = value.returnedType != 0U ? value.returnedType : value.type ;
	*size = value.returnedBytes.value_or( bytes) ;
	return ERROR_SUCCESS ;
}

//------------------------------------------------------------------------------
/**
 * @brief 開いた人工クラスキーとコインストーラーキーの閉鎖を記録する
 * @param[in] key この試験のopenが発行した人工ハンドル
 * @return 同試験の二種類のハンドルの閉鎖ならERROR_SUCCESS
 */
//------------------------------------------------------------------------------
LSTATUS WINAPI fixtureCloseClassKey( HKEY key)
{
	// クラスキーの読取ハンドルの閉鎖を確認する
	if( key == reinterpret_cast<HKEY>( &setupClassReadFixture.classHandles)) {
		++setupClassReadFixture.classCloses ;
		return ERROR_SUCCESS ;
	}

	// 独立キーの読取ハンドルはクラスキーと区別して集計する
	if( key == reinterpret_cast<HKEY>( &setupClassReadFixture.coHandles)) {
		++setupClassReadFixture.coCloses ;
		return ERROR_SUCCESS ;
	}

	setupClassReadFixture.callsValid = false ;
	return ERROR_INVALID_HANDLE ;
}

// SDKと同じ型を持つ、レジストリやデバイスへの書込み口を含まない表
constexpr SetupClassReadApi FIXTURE_SETUP_CLASS_API{
	decltype( SetupClassReadApi::className){fixtureSetupClassName},
	decltype( SetupClassReadApi::classGuids){fixtureSetupClassGuids},
	decltype( SetupClassReadApi::openClassKey){fixtureOpenSetupClass},
	decltype( SetupClassReadApi::classProperty){fixtureSetupClassProperty},
	decltype( SetupClassReadApi::deviceProperty){fixtureSetupDeviceProperty},
	decltype( SetupClassReadApi::openKey){fixtureOpenClassCoKey},
	decltype( SetupClassReadApi::readValue){fixtureReadClassCoValue},
	decltype( SetupClassReadApi::closeKey){fixtureCloseClassKey},
} ;

//------------------------------------------------------------------------------
/**
 * @brief 人工APIだけでクラスを観測し、元端末とリソースの不変条件を確認する
 * @param[in,out] context 呼び出し契約を集計する所有先
 * @param[out] observation 登録と作用の観測結果
 * @return 製品の観測関数が返す元HRESULT、または正常時の0
 */
//------------------------------------------------------------------------------
NativeError observeFixtureSetupClass( TestContext &context, DeclarativeClassEffects &observation)
{
	SP_DEVINFO_DATA device{static_cast<DWORD>( sizeof( SP_DEVINFO_DATA)), FIXTURE_SOURCE_CLASS, 71U,
						   0U} ;	// 別クラスに属する人工端末
	const auto		error = observeDeclarativeClassEffects(
		 &setupClassReadFixture, device, FIXTURE_TARGET_CLASS, FIXTURE_TARGET_NAME,
		 FIXTURE_SETUP_CLASS_API, observation) ;	// 選択時の元情報を製品の観測入口へ渡す
	DRIVERCRATE_EXPECT( context, IsEqualGUID( device.ClassGuid, FIXTURE_SOURCE_CLASS)) ;
	DRIVERCRATE_EXPECT( context, device.DevInst == 71U) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.callsValid) ;
	DRIVERCRATE_EXPECT( context,
					   setupClassReadFixture.classCloses == setupClassReadFixture.classHandles) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.coCloses == setupClassReadFixture.coHandles) ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示クラスと要求時開始KMDFの同一媒体で許可する参照だけを確認する
 * @param[in,out] context 合成ファイルでの構造と保護媒体の照合結果を集計する
 * @note 先行署名検査の範囲はこの局所構造fixtureから分離する
 */
//------------------------------------------------------------------------------
void scopedDeclarativeKernelMatrix( TestContext &context)
{
	// 同じサイズと参照を検査する架空カーネル表示ドライバーの正常な元INF
	constexpr std::string_view BASE =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=FixtureKernelDisplay\r\n"
		"ClassGuid={02be5c88-5674-4ff9-8898-8b123451727e}\r\nProvider=%ProviderName%\r\n"
		"CatalogFile=fixture.cat\r\nDriverVer=11/20/2026,1.0.0.0\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=12\r\nEmptyCopy=11\r\n"
		"[ClassInstall32]\r\nAddReg=ClassValues\r\n[ClassValues]\r\n"
		"HKR,,,,%FriendlyClass%\r\nHKR,,Icon,,-5\r\n"
		"[SourceDisksNames]\r\n1=\"Fixture media\",,,\r\n[SourceDisksFiles]\r\nfixture.sys=1,,\r\n"
		"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
		"Device=Install,PCI\\VEN_FFFF&DEV_FFF1\r\nOther=Install,PCI\\VEN_FFFF&DEV_FFF2\r\n"
		"[Install.NT]\r\nCopyFiles=Files\r\n[Files]\r\nfixture.sys\r\n"
		"[Install.NT.Services]\r\nAddService=FixtureKernel,%Association%,Kernel\r\n[Kernel]\r\n"
		"DisplayName=\"Fixture driver\"\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\fixture.sys\r\n"
		"[Install.NT.CoInstallers]\r\nAddReg=EmptyReg\r\nCopyFiles=EmptyCopy\r\n"
		"[EmptyReg]\r\n[EmptyCopy]\r\n[Install.NT.Wdf]\r\nKmdfService=FixtureKernel,Library\r\n"
		"[Library]\r\nKmdfLibraryVersion=1.15\r\n[Strings]\r\n"
		"Association=2\r\nProviderName=\"Fixture vendor\"\r\nFriendlyClass=\"Fixture display\"\r\n" ;
	// 許可する表示情報と、同じINFで拒否する追加登録を組み合わせた対照データ
	const std::array cases{
		std::pair<std::string_view, std::string_view>{"", ""},
		std::pair<std::string_view, std::string_view>{"HKR,,Icon,,-5",
													  "HKR,,Installer32,,fixture.dll"},
		std::pair<std::string_view, std::string_view>{"[EmptyReg]",
													  "[EmptyReg]\r\nHKR,,Value,,Changed"},
		std::pair<std::string_view, std::string_view>{"[EmptyCopy]", "[EmptyCopy]\r\nfixture.sys"},
		std::pair<std::string_view, std::string_view>{"DefaultDestDir=12", "DefaultDestDir=11"},
		std::pair<std::string_view, std::string_view>{"StartType=3", "StartType=2"},
		std::pair<std::string_view, std::string_view>{"Association=2", "Association=0"},
		std::pair<std::string_view, std::string_view>{"KmdfService=FixtureKernel",
													  "KmdfService=Other"},
		std::pair<std::string_view, std::string_view>{"KmdfLibraryVersion=1.15",
													  "KmdfLibraryVersion=1.33"},
		std::pair<std::string_view, std::string_view>{"[Strings]", "[Extra]\r\n[Strings]"},
	} ;
	constexpr OfficialInfModelsPlatform platform{10U, 0U, 17763U,
												 9U,  3U, 0U} ;			// 元明示Server x64観測点
	const std::array   ids{std::wstring( L"PCI\\VEN_FFFF&DEV_FFF1")} ;	// 公式範囲の架空一件
	IMAGE_DOS_HEADER   dos{} ;											// 試験用の実行しない形式header
	IMAGE_NT_HEADERS64 pe{} ;											// 同じfixtureのAMD64 header
	dos.e_magic							  = IMAGE_DOS_SIGNATURE ;
	dos.e_lfanew						  = sizeof( dos) ;
	pe.Signature						  = IMAGE_NT_SIGNATURE ;
	pe.FileHeader.Machine				  = IMAGE_FILE_MACHINE_AMD64 ;
	pe.FileHeader.SizeOfOptionalHeader	  = sizeof( IMAGE_OPTIONAL_HEADER64) ;
	pe.OptionalHeader.Magic				  = IMAGE_NT_OPTIONAL_HDR64_MAGIC ;
	pe.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES ;
	std::string binary( sizeof( dos) + sizeof( pe), '\0') ;	// 形式照合だけに使うバイト列
	std::memcpy( binary.data(), &dos, sizeof( dos)) ;
	std::memcpy( binary.data() + sizeof( dos), &pe, sizeof( pe)) ;
	std::uint64_t identity = 1790U ;	// 各条件の一時所有領域

	// 全正負を同じ読取り検査へ渡し、正例の媒体ハッシュを別の負例でも確認する
	for( const auto &[before, after] : cases) {
		std::string source( BASE) ;	// 条件ごとの独立した元INF
		// 否定対照では指定した一つの元作用だけを変える
		if( !before.empty()) {
			source.replace( source.find( before), before.size(), after) ;
		}

		OfficialDownloadWorkspace workspace ;										// この一件に限る保護領域
		const auto initialized = workspace.initialize( L"kmdf-refs", identity++) ;	// この例の所有領域
		DRIVERCRATE_EXPECT( context, initialized == 0U) ;
		// 所有領域を作れないときは元ファイルの負例と混同しない
		if( initialized != 0U) {
			return ;
		}

		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"fixture.inf", source)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"fixture.sys", binary)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"fixture.cat", "fixture")) ;
		std::array entries{
			OfficialZipEntry{L"fixture.inf", source.size()},
			OfficialZipEntry{L"fixture.sys", binary.size()},
			OfficialZipEntry{L"fixture.cat", 7U}} ;	// 元ファイルの順とハッシュを固定する一覧
		// 全三媒体を読んで元ハッシュと位置を結ぶ
		for( auto &entry : entries) {
			DRIVERCRATE_EXPECT(
				context, computeFileSha256( workspace.path( entry.relativePath), entry.sha256) == 0U) ;
		}

		OfficialInfScopedModelsEvidence models ;	// 架空一IDが有効な実対象へ結ばれた証拠
		DRIVERCRATE_EXPECT( context, readOfficialInfScopedModels( workspace, L"fixture.inf",
																entries.front().sha256, &platform,
																ids, models) == 0U) ;
		OfficialInfPackage package ;	// 先行検査の結果型に結ぶ局所fixture
		package.inspectionPurpose	= OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
		package.role				= DriverPlanRole::BASE_DRIVER ;
		package.infRelativePath		= L"fixture.inf" ;
		package.catalogRelativePath = L"fixture.cat" ;
		package.className			= L"FixtureKernelDisplay" ;
		package.classGuid			= L"{02be5c88-5674-4ff9-8898-8b123451727e}" ;
		package.sourceFiles			= {L"fixture.sys"} ;
		package.scopedModels		= std::move( models) ;
		DRIVERCRATE_EXPECT( context, verifyScopedDeclarativeKernelReferences(
										workspace, entries, package) == before.empty()) ;
		// 元媒体と展開一覧のhashを別にした場合は同じ構造でも成功を返さない
		if( before.empty()) {
			entries[1].sha256.assign( 64U, L'0') ;
			DRIVERCRATE_EXPECT(
				context, !verifyScopedDeclarativeKernelReferences( workspace, entries, package)) ;
		}
	}
}

// 単一文字列やレジストリの空リストの一重終端
constexpr wchar_t EMPTY_EFFECT[]{L'\0'} ;
// 型付き空リストの二重終端
constexpr wchar_t EMPTY_EFFECT_LIST[]{L'\0', L'\0'} ;
// 登録済み作用として保持する終端付きの文字列
constexpr wchar_t EXISTING_EFFECT[] = L"fixture.dll,Entry" ;
// 登録済み作用として保持する二つの要素と二重終端
constexpr wchar_t EXISTING_EFFECT_LIST[] = L"FixtureFilter\0SecondFixture\0" ;

//------------------------------------------------------------------------------
/**
 * @brief 初回クラス未登録と登録済みの作用が型と元値を保つことを検証する
 * @param[in,out] context 作用と読み取り元の期待値を集計する所有先
 */
//------------------------------------------------------------------------------
void			  declarativeClassEffectValues( TestContext &context)
{
	using State		   = MtdHandlerState ;
	using Registration = SetupClassRegistration ;
	DeclarativeClassEffects observation ;	// 各呼出しで再初期化する観測

	// 独立キー自体がない初回クラスでも、元端末の四つの作用を実際に照会する
	setupClassReadFixture = {} ;
	DRIVERCRATE_EXPECT( context, observeFixtureSetupClass( context, observation) == 0U) ;
	DRIVERCRATE_EXPECT( context, observation.registration == Registration::UNREGISTERED) ;
	DRIVERCRATE_EXPECT( context, IsEqualGUID( observation.sourceClass, FIXTURE_SOURCE_CLASS)) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.classReads == 0U) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.deviceReads == DEVICE_EFFECT_KEYS.size()) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.coOpens == 1U) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.coReads == 0U) ;
	const std::array values{
		&observation.classInstaller,	 &observation.classCoInstallers,
		&observation.classPropPage,		 &observation.classUpperFilters,
		&observation.classLowerFilters,	 &observation.deviceCoInstallers,
		&observation.devicePropPage,	 &observation.deviceUpperFilters,
		&observation.deviceLowerFilters,
	} ; // 固定の型付き観測先を二つの条件で再利用する
	// 全ての既存作用を正式不在と確認し、未観測の既定値と区別する
	for( const auto *value : values) {
		DRIVERCRATE_EXPECT( context, value->state == State::ABSENT && value->bytes.empty()) ;
	}

	// 名前の文字大小だけが異なる同一GUIDの既登録と、独立キーに値がない場合
	setupClassReadFixture = {.registration = REGISTERED_CLASS_FIXTURE,
							 .coKeyStatus  = ERROR_SUCCESS} ;
	DRIVERCRATE_EXPECT( context, observeFixtureSetupClass( context, observation) == 0U) ;
	DRIVERCRATE_EXPECT( context, observation.registration == Registration::REGISTERED) ;
	DRIVERCRATE_EXPECT( context, observation.classCoInstallers.state == State::ABSENT) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.classReads == CLASS_EFFECT_KEYS.size()) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.deviceReads == DEVICE_EFFECT_KEYS.size()) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.coReads == 1U) ;

	// 別の正式不在コードを使う初回クラスでも、独立キーに残った作用を見落とさない
	setupClassReadFixture = {
		.registration = {.guidError = ERROR_FILE_NOT_FOUND, .classKeyError = ERROR_FILE_NOT_FOUND},
		.coKeyStatus  = ERROR_SUCCESS,
		.coInstaller  = {.type = REG_MULTI_SZ, .value = EXISTING_EFFECT_LIST},
	} ;
	DRIVERCRATE_EXPECT( context, observeFixtureSetupClass( context, observation) == 0U) ;
	DRIVERCRATE_EXPECT( context, observation.registration == Registration::UNREGISTERED) ;
	DRIVERCRATE_EXPECT( context, observation.classCoInstallers.state == State::PRESENT) ;
	DRIVERCRATE_EXPECT( context, std::ranges::equal( observation.classCoInstallers.bytes,
												   std::as_bytes( std::span{EXISTING_EFFECT_LIST}))) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.classReads == 0U) ;
	DRIVERCRATE_EXPECT( context, setupClassReadFixture.coReads == 2U) ;

	// 既登録クラスと元端末の全作用で、空値と非空値の型・全byteを照合する
	const ClassEffectValueFixture emptyString{.type	 = DEVPROP_TYPE_STRING,
											  .value = EMPTY_EFFECT} ;	// 空の単一文字列
	const ClassEffectValueFixture emptyList{.type  = DEVPROP_TYPE_STRING_LIST,
											.value = EMPTY_EFFECT_LIST} ;	// 空の文字列リスト
	const ClassEffectValueFixture presentString{.type  = DEVPROP_TYPE_STRING,
												.value = EXISTING_EFFECT} ;	// 既存の実行設定
	const ClassEffectValueFixture presentList{.type	 = DEVPROP_TYPE_STRING_LIST,
											  .value = EXISTING_EFFECT_LIST} ;	// 既存フィルター列
	const ClassEffectValueFixture unknownSizingType{
		.type		  = DEVPROP_TYPE_EMPTY,
		.value		  = EMPTY_EFFECT,
		.returnedType = DEVPROP_TYPE_STRING} ;	// 容量照会では型を報告しない正常な単一文字列
	// レジストリの空リストは一重と二重の両方の終端を元byteとして保持する
	for( const auto emptyCoList :
		{std::span<const wchar_t>{EMPTY_EFFECT}, std::span<const wchar_t>{EMPTY_EFFECT_LIST}}) {
		setupClassReadFixture = {
			.registration  = REGISTERED_CLASS_FIXTURE,
			.classEffects  = {emptyString, presentString, presentList, emptyList},
			.deviceEffects = {presentList, unknownSizingType, emptyList, presentList},
			.coKeyStatus   = ERROR_SUCCESS,
			.coInstaller   = {.type = REG_MULTI_SZ, .value = emptyCoList},
		} ;
		DRIVERCRATE_EXPECT( context, observeFixtureSetupClass( context, observation) == 0U) ;
		DRIVERCRATE_EXPECT( context, observation.registration == Registration::REGISTERED) ;
		const std::array expectedStates{
			State::EMPTY_STRING, State::EMPTY_LIST, State::PRESENT,
			State::PRESENT,		 State::EMPTY_LIST, State::PRESENT,
			State::EMPTY_STRING, State::EMPTY_LIST, State::PRESENT,
		} ; // 読取元が混ざると空と非空が入れ替わる
		const std::array expectedValues{
			emptyString,
			ClassEffectValueFixture{.type = DEVPROP_TYPE_STRING_LIST, .value = emptyCoList},
			presentString,
			presentList,
			emptyList,
			presentList,
			emptyString,
			emptyList,
			presentList,
		} ; // APIの型と全UTF-16値
		// 同じ順の観測先で型と内容を全て確かめる
		for( std::size_t index = 0U; index < values.size(); ++index) {
			DRIVERCRATE_EXPECT( context, values[index]->state == expectedStates[index]) ;
			DRIVERCRATE_EXPECT( context, values[index]->type == expectedValues[index].type) ;
			DRIVERCRATE_EXPECT( context,
							   std::ranges::equal( values[index]->bytes,
												  std::as_bytes( expectedValues[index].value))) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 不明・矛盾・破損・照会中変化を正常な登録証拠として返さないことを検証する
 * @param[in,out] context 条件名と拒否結果を集計する所有先
 */
//------------------------------------------------------------------------------
void declarativeClassEffectFailures( TestContext &context)
{
	constexpr wchar_t TRUNCATED_LIST[]{L'F', L'\0'} ;	// 非空リストの二重終端が欠けた値
	const struct {
		/// 失敗した場合に示す人工条件の名前
		std::string_view	  name ;
		/// 一呼出しの独立した人工状態
		SetupClassReadFixture fixture ;
		/// 元診断を固定する条件のWin32 error。0なら拒否だけを照合する
		DWORD				  error{} ;
	} cases[]{
		{"GUID lookup denied",
		 {.registration = {.guidError = ERROR_ACCESS_DENIED}},
		 ERROR_ACCESS_DENIED},
		{"GUID lookup fails with zero error", {.registration = {.guidError = ERROR_SUCCESS}}},
		{"reverse lookup cannot prove zero",
		 {.registration = {.reverseError = ERROR_INVALID_CLASS}}},
		{"reverse lookup fails with zero error", {.registration = {.reverseError = ERROR_SUCCESS}}},
		{"target GUID has another registered name",
		 {.registration = {.guidError = std::nullopt, .name = L"OtherFixture"}}},
		{"name success without returned length",
		 {.registration = {.guidError = std::nullopt, .reportNameLength = false}}},
		{"target name already maps to another GUID",
		 {.registration = {.reverseGuid = FIXTURE_SOURCE_CLASS, .reverseCount = 1U}}},
		{"name lookup conflicts with registered target",
		 {.registration = {.guidError	  = std::nullopt,
						   .classKeyError = std::nullopt,
						   .reverseGuid	  = FIXTURE_SOURCE_CLASS,
						   .reverseCount  = 1U}}},
		{"name maps to multiple GUIDs",
		 {.registration = {.guidError	  = std::nullopt,
						   .classKeyError = std::nullopt,
						   .reverseCount  = 2U}}},
		{"class key unreadable",
		 {.registration = {.classKeyError = ERROR_ACCESS_DENIED}},
		 ERROR_ACCESS_DENIED},
		{"class key fails with zero error", {.registration = {.classKeyError = ERROR_SUCCESS}}},
		{"target names agree but class key is missing",
		 {.registration = {.guidError = std::nullopt, .reverseCount = 1U}},
		 ERROR_RETRY},
		{"target name is absent but class key exists",
		 {.registration = {.classKeyError = std::nullopt}},
		 ERROR_RETRY},
		{"independent CoDeviceInstallers key denied",
		 {.coKeyStatus = ERROR_ACCESS_DENIED},
		 ERROR_ACCESS_DENIED},
		{"independent co-installer value denied",
		 {.coKeyStatus = ERROR_SUCCESS, .coInstaller = {.queryError = ERROR_ACCESS_DENIED}},
		 ERROR_ACCESS_DENIED},
		{"independent co-installer wrong registry type",
		 {.coKeyStatus = ERROR_SUCCESS, .coInstaller = {.type = REG_SZ, .value = EMPTY_EFFECT}}},
		{"independent co-installer registry type changes after sizing",
		 {.coKeyStatus = ERROR_SUCCESS,
		  .coInstaller = {.type = REG_SZ, .value = EMPTY_EFFECT, .returnedType = REG_MULTI_SZ}},
		 ERROR_INVALID_DATA},
		{"independent co-installer read loses previously sized value",
		 {.coKeyStatus = ERROR_SUCCESS,
		  .coInstaller = {.type		 = REG_MULTI_SZ,
						  .value	 = EMPTY_EFFECT,
						  .readError = ERROR_FILE_NOT_FOUND}}},
		{"class installer cannot be read",
		 {.registration = REGISTERED_CLASS_FIXTURE,
		  .classEffects = {ClassEffectValueFixture{.queryError = ERROR_ACCESS_DENIED}}},
		 ERROR_ACCESS_DENIED},
		{"device property fails with zero error",
		 {.deviceEffects = {ClassEffectValueFixture{.queryError = ERROR_SUCCESS}}}},
		{"device co-installer with incompatible typed empty",
		 {.deviceEffects = {ClassEffectValueFixture{.type  = DEVPROP_TYPE_STRING,
													.value = EMPTY_EFFECT}}}},
		{"device co-installer has truncated list terminator",
		 {.deviceEffects = {ClassEffectValueFixture{.type  = DEVPROP_TYPE_STRING_LIST,
													.value = TRUNCATED_LIST}}}},
		{"device co-installer read reports fewer bytes than sized",
		 {.deviceEffects = {ClassEffectValueFixture{.type  = DEVPROP_TYPE_STRING_LIST,
													.value = EMPTY_EFFECT_LIST,
													.returnedBytes =
														static_cast<DWORD>( sizeof( wchar_t))}}}},
		{"device co-installer type changes after sizing",
		 {.deviceEffects = {ClassEffectValueFixture{.type		  = DEVPROP_TYPE_STRING,
													.value		  = EMPTY_EFFECT_LIST,
													.returnedType = DEVPROP_TYPE_STRING_LIST}}},
		 ERROR_INVALID_DATA},
		{"unregistered class appears during effects",
		 {.nextRegistration = REGISTERED_CLASS_FIXTURE},
		 ERROR_RETRY},
		{"registered class disappears during effects",
		 {.registration		= REGISTERED_CLASS_FIXTURE,
		  .nextRegistration = SetupClassRegistrationFixture{}},
		 ERROR_RETRY},
	} ;

	// 各拒否例を新しい人工状態で読み、既存の成功を出力に残さない
	for( const auto &example : cases) {
		setupClassReadFixture = example.fixture ;
		DeclarativeClassEffects observation ;	// 前の成功が残った場合を検出する出力先
		observation.registration		 = SetupClassRegistration::REGISTERED ;
		observation.sourceClass			 = FIXTURE_SOURCE_CLASS ;
		observation.devicePropPage.state = MtdHandlerState::PRESENT ;
		const auto error = observeFixtureSetupClass( context, observation) ;	// 拒否の元診断
		context.expect(
			error != 0U && (example.error == 0U ||
							error == static_cast<NativeError>( HRESULT_FROM_WIN32( example.error))),
			std::string( example.name) + " error " + std::to_string( error), __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context, observation.registration == SetupClassRegistration::UNOBSERVED) ;
		DRIVERCRATE_EXPECT( context, IsEqualGUID( observation.sourceClass, GUID_NULL)) ;
		DRIVERCRATE_EXPECT( context, observation.devicePropPage.state == MtdHandlerState::FAILED) ;
	}
}

// 架空の一般deviceと同INFの元コピーだけを持つfixtureです
constexpr std::string_view ATTACHED_INF =
	"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Display\r\n"
	"ClassGUID={4d36e968-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture Vendor\r\n"
	"DriverVer=11/05/2026,2.0.0.0\r\nCatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
	"Device=Install,PCI\\SYNTH_ATTACHED_CONTENT\r\n"
	"[Install.NT]\r\nCopyFiles=DriverFiles,ProgramFiles\r\n"
	"[Install.NT.Services]\r\nAddService=FixtureKernel,2,KernelService\r\n"
	"[KernelService]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%12%\\sample.sys\r\n"
	"[DestinationDirs]\r\nDriverFiles=12\r\nProgramFiles=13\r\nCoFiles=11\r\n"
	"[DriverFiles]\r\nsample.sys\r\n[ProgramFiles]\r\nhelper.exe\r\n"
	"[CoFiles]\r\nhelper.dll\r\n[SourceDisksNames]\r\n1=fixture,,,\r\n"
	"[SourceDisksFiles]\r\nsample.sys=1\r\nhelper.exe=1\r\nhelper.dll=1\r\n" ;

//------------------------------------------------------------------------------
/**
 * @brief 一つの正負条件を元fixtureへ適用し、全内容と未評価flagを確認します
 * @param[in,out] context 一processの有限集計先です
 * @param[in] suffix 元deviceへ追加する原softwareまたはCoInstaller節です
 * @param[in] before 元fixture内で置換する完全な文字列です。空なら置換しません
 * @param[in] after 置換後の完全値です
 * @param[in] contentOnly 非実行内容だけを許可する場合trueです
 * @param[in] accepted 全構造検査が成功すべき場合trueです
 * @param[in] unassessed 成功時の未評価program flagです
 * @param[in] identity この条件だけの所有workspace番号です
 */
//------------------------------------------------------------------------------
void attachedCase( TestContext &context, std::string_view suffix, std::string_view before,
				  std::string_view after, bool contentOnly, bool accepted, bool unassessed,
				  std::uint64_t identity)
{
	OfficialDownloadWorkspace workspace ;	// 条件ごとの有限な原byte所有者です
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"attached-content-test", identity) == 0) ;
	std::string body( ATTACHED_INF) ;	// 別条件から変異を持ち越しません
	body.append( suffix) ;
	// 正確な原文字列が存在する場合だけ一箇所を変更します
	if( !before.empty()) {
		const auto position = body.find( before) ;	// 固定原fixtureの完全一致位置です
		DRIVERCRATE_EXPECT( context, position != body.npos) ;
		// 前提欠損を別位置の編集へ補正しません
		if( position != body.npos) {
			body.replace( position, before.size(), after) ;
		}
	}

	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"helper.exe", "program")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"helper.dll", "library")) ;
	const std::array entries{
		OfficialZipEntry{L"sample.inf", body.size()}, OfficialZipEntry{L"sample.cat", 8U},
		OfficialZipEntry{L"sample.sys", 6U}, OfficialZipEntry{L"helper.exe", 7U},
		OfficialZipEntry{L"helper.dll", 7U}} ;	// 元全file集合です
	constexpr std::array		classes{std::wstring_view( L"Display"),
									// 一般deviceと旧役割です
									std::wstring_view( L"SoftwareComponent")} ;
	constexpr std::array		signatures{std::wstring_view( L"$Windows NT$")} ;	// 構文識別だけです
	OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;			// 各条件の共通policyです
	policy.acceptAnyProvider					= true ;
	policy.requireDriverBinary					= false ;
	policy.rejectUnreferencedPrograms			= false ;
	policy.rejectInstallActions					= true ;
	policy.allowRequiredDriverComponents		= true ;
	policy.allowReferencedExecutablesForContent = contentOnly ;
	OfficialInfPackage package ;	// 全成功時だけ返る元内容です
	const auto		   error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
														 package) ;	// 原構造診断です
	context.expect( (error == 0) == accepted,
				   "attached fixture " + std::to_string( identity) + " error " +
					   std::to_string( error),
				   __FILE__, __LINE__) ;
	// 内容受理でも未署名CATを信頼したり、未評価programを導入可能へ変換しません
	if( accepted && error == 0) {
		DRIVERCRATE_EXPECT( context, package.hasUnassessedProgramReferences == unassessed) ;
		DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Windows-only scopeを元byteのcopy/service/softwareから検査します
 * @param[in,out] context 一processの有限集計先です
 * @param[in] before 元fixtureの置換対象です。空は正例です
 * @param[in] after 元値を置換する負例です
 * @param[in] accepted scopeが成立すべき場合trueです
 * @param[in] identity 条件ごとの保護workspace番号です
 * @param[in] contentRejected trueは既知autorunが全内容の既存guardで先に拒否される条件です
 * @param[in] storageEvent trueは選択SCSIAdapterのSystemイベント付き補助サービスを使います
 */
//------------------------------------------------------------------------------
void windowsScopeCase( TestContext &context, std::string_view before, std::string_view after,
					  bool accepted, std::uint64_t identity, bool contentRejected = false,
					  bool storageEvent = false)
{
	std::string body( ATTACHED_INF) ;	// 原一般deviceの同INF関係です
	body.replace( body.find( "CopyFiles=DriverFiles,ProgramFiles"),
				 std::string_view( "CopyFiles=DriverFiles,ProgramFiles").size(),
				 "CopyFiles=DriverFiles,ProgramFiles,DataFiles") ;
	body.replace(
		body.find( "AddService=FixtureKernel,2,KernelService"),
		std::string_view( "AddService=FixtureKernel,2,KernelService").size(),
		"AddService=FixtureKernel,2,KernelService\r\nAddService=FixtureHelper,0,HelperService") ;
	body +=
		"[DestinationDirs]\r\nDataFiles=13\r\n[DataFiles]\r\nrecovery.bat\r\n"
		"[SourceDisksFiles]\r\nrecovery.bat=1\r\n"
		"[HelperService]\r\nServiceType=16\r\nStartType=2\r\nErrorControl=1\r\nServiceBinary=%13%\\helper.exe --data recovery.bat\r\n" ;
	// 一般クラスでだけ既存のSoftware関係を組み合わせて検証します
	if( !storageEvent) {
		body +=
			"[Install.NT.Software]\r\nAddSoftware=RelatedDeviceProgram,0,RelatedSoftware\r\n"
			"[RelatedSoftware]\r\nSoftwareType=1\r\nSoftwareVersion=2.0.0.0\r\nSoftwareBinary=%13%\\helper.exe\r\n"
			"SoftwareArguments=--device <<DeviceInstanceID>>, --driver\r\n" ;
	}

	body += "[PassiveReg]\r\nHKR,,Opaque,0x00010000" ;
	// 元NVIDIA同様の324 fieldsでも、opaque値の完全棚卸しをscopeの前提へ流用しません
	for( unsigned field = 0U; field < 320U; ++field) {
		body += ",\"opaque\"" ;
	}

	body += "\r\n" ;
	// 元の構造を共有し、ストレージのfixtureだけを名前付きSystemイベントと引数なしに変更します
	if( storageEvent) {
		constexpr std::string_view displayClass{"Class=Display"} ;							// 原Display宣言
		constexpr std::string_view displayGuid{"{4d36e968-e325-11ce-bfc1-08002be10318}"} ;	// 原GUID
		constexpr std::string_view arguments{" --data recovery.bat"} ;						// 元の補助引数
		constexpr std::string_view service{"AddService=FixtureHelper,0,HelperService"} ;	// 原補助行
		body.replace( body.find( displayClass), displayClass.size(), "Class=SCSIAdapter") ;
		body.replace( body.find( displayGuid), displayGuid.size(),
					 "{4d36e97b-e325-11ce-bfc1-08002be10318}") ;
		body.erase( body.find( arguments), arguments.size()) ;
		body.insert( body.find( service) + service.size(), ",HelperEvent,System,Fixture Middleware") ;
		body += "[HelperEvent]\r\nAddReg=HelperEventReg\r\n"
				"[HelperEventReg]\r\nHKR,,TypesSupported,0x00010001,0x1F\r\n" ;
	}

	// 原既知禁止位置を負例だけへ置き、無関係な正例の内容前提を汚染しません
	if( contentRejected) {
		body +=
			"[AutorunReg]\r\nHKLM,\"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\",Fixture,0,\"foreign.exe\"\r\n"
			"[UserAutorunReg]\r\nHKCU,\"Software\\Microsoft\\Windows\\CurrentVersion\\rUn\",Fixture,0,\"foreign.exe\"\r\n" ;
	}

	// 一条件の原文字列だけを書換え、他条件へ持ち越しません
	if( !before.empty()) {
		const auto position = body.find( before) ;	// 固定元値の一意位置です
		DRIVERCRATE_EXPECT( context, position != body.npos) ;
		// 前提が欠けた条件を正例として進めません
		if( position == body.npos) {
			return ;
		}

		body.replace( position, before.size(), after) ;
	}

	OfficialDownloadWorkspace workspace ;	// 同元byteだけの保護ownerです
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"windows-scope-fixture", identity) == 0) ;
	const std::array					   names{L"sample.inf", L"sample.cat", L"sample.sys",
							 L"helper.exe", L"helper.dll", L"recovery.bat"} ;	// 同元全参照です
	const std::array<std::string_view, 6U> payloads{
		body,	   "unsigned", "driver",
		"program", "library",  "opaque recovery data"} ;	// 実行しないfixtureです
	std::vector<OfficialZipEntry> entries ;					// 実size/hashを保持するがCATは未署名です
	// 全fixture byteを独立sourceへ書き、実SHA256を取得します
	for( std::size_t index = 0U; index < names.size(); ++index) {
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, names[index], payloads[index])) ;
		OfficialZipEntry entry{names[index], payloads[index].size()} ;	// 元実byteです
		DRIVERCRATE_EXPECT( context,
						   computeFileSha256( workspace.path( names[index]), entry.sha256) == 0) ;
		entries.push_back( std::move( entry)) ;
	}

	constexpr std::array		classes{std::wstring_view( L"Display"),
									// 元fixtureのクラス
									std::wstring_view( L"SCSIAdapter")} ;
	constexpr std::array		signatures{std::wstring_view( L"$Windows NT$")} ;	// 構文識別だけです
	OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;			// 全同元内容policyです
	// ストレージfixtureでは正式SCSIAdapterを扱う端末読取り用途を選びます
	if( storageEvent) {
		policy.purpose = OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
	}

	policy.acceptAnyProvider					   = true ;
	policy.rejectUnreferencedPrograms			   = false ;
	policy.rejectInstallActions					   = true ;
	policy.allowReferencedExecutablesForContent	   = true ;
	policy.allowRequiredDriverComponents		   = true ;
	policy.allowWindowsManagedDriverDataForContent = true ;
	OfficialInfPackage package ;	// 全内容構造の元metadataです
	const auto		   parsed = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
														  package) ;	// 実元readerです
	context.expect( parsed == (contentRejected ? nativeErrorFromWin32( ERROR_NOT_SUPPORTED) : 0),
				   "Windows scope content " + std::to_string( identity) + " error " +
					   std::to_string( parsed),
				   __FILE__, __LINE__) ;
	// 内容構造の前提に失敗した条件をscope拒否成功へ数えません
	if( parsed != 0) {
		return ;
	}

	OfficialInfPackage selected ;	// 同current Models/Windows節からの原関係です
	DRIVERCRATE_EXPECT( context, inspectSelectedOfficialInfRelations( workspace, entries, package,
																	L"Install", selected) == 0) ;
	RequiredInfBindingDiagnostic diagnostic ;	// 選択scopeの最初の固定理由です
	diagnostic.path	 = 2U ;
	const auto scope = inspectSelectedWindowsDriverPackageScope(
		workspace, entries, selected, &diagnostic) ;	// 内容と実行能力は別です
	context.expect( (scope == 0) == accepted,
				   "Windows scope " + std::to_string( identity) + " error " + std::to_string( scope),
				   __FILE__, __LINE__) ;
	DRIVERCRATE_EXPECT( context, selected.hasUnassessedProgramReferences) ;
	DRIVERCRATE_EXPECT( context, diagnostic.path == 2U &&
									(accepted ? diagnostic.rejection == InfBindingReject::NONE
											  : diagnostic.rejection != InfBindingReject::NONE)) ;
	const auto first	= diagnostic.rejection ;	// 元の最初の拒否だけです
	const auto observed = diagnostic.observed ;		// native観測値を再分類しません
	const auto forwarded =
		diagnostic.reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED), InfBindingReject::DEPENDENCY,
						  999U) ;	// guardと原codeは不変です
	DRIVERCRATE_EXPECT( context, forwarded == nativeErrorFromWin32( ERROR_NOT_SUPPORTED) &&
									(accepted || (diagnostic.rejection == first &&
												  diagnostic.observed == observed))) ;
	DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, selected) != 0) ;
	selected.activeRequiredInfPaths.push_back( L"foreign.inf") ;
	DRIVERCRATE_EXPECT( context,
					   inspectSelectedWindowsDriverPackageScope( workspace, entries, selected) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 受動コピーと既知外部操作を異なる原条件で局所検証します
 * @param[in,out] context このprocessの有限集計先です
 */
//------------------------------------------------------------------------------
void windowsScopeMatrix( TestContext &context)
{
	windowsScopeCase( context, {}, {}, true, 71220U, false, true) ;
	windowsScopeCase( context, ",System,Fixture Middleware", ",Application,Fixture Middleware",
					 false, 71221U, false, true) ;
	windowsScopeCase( context, "Fixture Middleware", "Fixture\\Middleware", false, 71222U, false,
					 true) ;
	windowsScopeCase( context, "[HelperService]\r\nServiceType=16\r\nStartType=2",
					 "[HelperService]\r\nServiceType=16\r\nStartType=3", false, 71223U, false,
					 true) ;
	windowsScopeCase( context, "ServiceBinary=%13%\\helper.exe\r\n",
					 "ServiceBinary=%13%\\helper.exe --argument\r\n", false, 71224U, false, true) ;
	windowsScopeCase( context, "ProgramFiles=13", "ProgramFiles=11", false, 71225U, false, true) ;
	windowsScopeCase( context, {}, {}, true, 71201U) ;
	windowsScopeCase( context, "DataFiles=13", "DataFiles=16422", false, 71202U) ;
	windowsScopeCase( context, "ServiceBinary=%13%\\helper.exe --data recovery.bat",
					 "ServiceBinary=%11%\\cmd.exe /c recovery.bat", false, 71203U) ;
	windowsScopeCase( context, "SoftwareType=1",
					 "SoftwareType=2\r\nSoftwareID=pfn://Fixture.DriverSupport_abcdefghjkmnp",
					 false, 71204U) ;
	windowsScopeCase( context, "SoftwareArguments=--device <<DeviceInstanceID>>",
					 "SoftwareArguments=--standalone-app", false, 71205U) ;
	windowsScopeCase( context, "[ProgramFiles]\r\nhelper.exe",
					 "[ProgramFiles]\r\nhelper.exe\r\nrenamed.dll,helper.dll", true, 71206U) ;
	windowsScopeCase( context, "CopyFiles=DriverFiles,ProgramFiles,DataFiles",
					 "CopyFiles=DriverFiles,ProgramFiles,DataFiles\r\nAddReg=AutorunReg", false,
					 71207U, true) ;
	windowsScopeCase( context, "[HelperService]\r\nServiceType=16",
					 "[HelperService]\r\nAddReg=AutorunReg\r\nServiceType=16", false, 71208U, true) ;
	windowsScopeCase( context, "[RelatedSoftware]\r\nSoftwareType=1",
					 "[RelatedSoftware]\r\nAddReg=AutorunReg\r\nSoftwareType=1", false, 71209U,
					 true) ;
	windowsScopeCase( context, "CopyFiles=DriverFiles,ProgramFiles,DataFiles",
					 "CopyFiles=DriverFiles,ProgramFiles,DataFiles\r\nAddReg=PassiveReg", true,
					 71210U) ;
	windowsScopeCase( context, "CopyFiles=DriverFiles,ProgramFiles,DataFiles",
					 "CopyFiles=DriverFiles,ProgramFiles,DataFiles\r\nAddReg=UserAutorunReg", false,
					 71211U, true) ;
	windowsScopeCase(
		context, "CopyFiles=DriverFiles,ProgramFiles,DataFiles",
		"CopyFiles=DriverFiles,ProgramFiles,DataFiles\r\nAddReg=PassiveReg\r\nAddReg=AutorunReg",
		false, 71212U, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 空媒体のSDHostから元選択節だけを収集へ渡す条件を確認する
 * @param[in,out] context 実行した局所assertionを集計します
 * @note CATのない人工内容に署名成功の結果を作りません
 */
//------------------------------------------------------------------------------
void inboxSdHostRootMatrix( TestContext &context)
{
	// 二つの空媒体表と、三つの実在する委譲節を持つ人工原本です
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SDHost\r\n"
		"ClassGUID={a0a588a4-c46f-4b37-b7ea-c82fe89870c6}\r\nProvider=Fixture\r\n"
		"CatalogFile=sample.cat\r\nDriverVer=11/19/2026,1.0.0.0\r\n"
		"[Manufacturer]\r\nFixture=Models,NTamd64\r\n"
		"[Models.NTamd64]\r\nFixture=Install,PCI\\VEN_1234&DEV_5678\r\n"
		"[SourceDisksFiles]\r\n[SourceDisksNames]\r\n"
		"[Install.NT]\r\nInclude=sdbus.inf\r\nNeeds=Example.NT\r\n"
		"[Install.NT.HW]\r\nInclude=sdbus.inf\r\nNeeds=Example.NT.HW\r\n"
		"[Install.NT.Services]\r\nInclude=sdbus.inf\r\nNeeds=Example.NT.Services\r\n" ;
	// 先頭だけを正例とし、個別の追加で各拒否条件を確認します
	constexpr std::array additions{
		std::string_view{},
		std::string_view{"CopyFiles=@unverified.sys\r\n"},
		std::string_view{"[SourceDisksFiles.amd64]\r\nunverified.sys=1\r\n"},
		std::string_view{"[Install.NT.CoInstallers]\r\n"},
		std::string_view{"[Version]\r\nClassGUID={a0a588a4-c46f-4b37-b7ea-c82fe89870c6}\r\n"},
		std::string_view{"[Version]\r\nLayoutFile=foreign.inf\r\n"}} ;
	constexpr std::array classes{
		std::wstring_view{L"System"}} ;	// 一般クラス一覧にSDHostは入れません
	constexpr std::array signatures{
		std::wstring_view{L"$Windows NT$"}} ;	// INFのWindows形式識別子です
	OfficialInfInspectionPolicy policy{
		32U, 32U, classes, {}, signatures} ;	// 同じ構造条件で全例を比較します
	policy.acceptAnyProvider			 = true ;
	policy.rejectInstallActions			 = true ;
	policy.allowRequiredDriverComponents = true ;
	policy.purpose						 = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;

	// 各例を独立したworkspaceで展開して状態を持ち越しません
	for( std::size_t index = 0U; index < additions.size(); ++index) {
		OfficialDownloadWorkspace workspace ;	// この例の元INFとCATを所有します
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"inbox-sdhost", 71500U + index) == 0) ;
		std::string body{INF} ;	// 正例に差分を加える前の元本文です
		body += additions[index] ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		const std::array entries{
			OfficialZipEntry{L"sample.inf", body.size()},
			OfficialZipEntry{L"sample.cat", 8U}} ;	// この例に存在するファイルです
		OfficialInfPackage package ;				// 共通構造検査の結果です
		// 本番と同じ構造検査の元HRESULTを各例で確認します
		const auto		   parsed =
			inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ;
		context.expect( (parsed == 0) == (index == 0U),
					   "inbox SDHost root " + std::to_string( index) + " error " +
						   std::to_string( parsed),
					   __FILE__, __LINE__) ;
		// 正例では検査へ渡す節の中身と、署名および端末用途の独立性も確認します
		if( index == 0U && parsed == 0) {
			const std::vector<std::vector<std::wstring>> expected{
				{L"Install.NT", L"Install.NT.HW",
				 L"Install.NT.Services"}} ;	// 現在OSの実選択と同じ修飾の付随節です
			DRIVERCRATE_EXPECT( context, package.collectorInboxInstallGroups == expected &&
											package.sourceFiles.empty() &&
											package.hasExternalDependencies) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;

			auto devicePolicy	 = policy ;	// 同じ原本を端末候補の用途で検査します
			devicePolicy.purpose = OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
			DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"sample.inf",
																  devicePolicy, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元Portsのページを同じDDInstallが所有する単独登録に限定する条件を確認する
 * @param[in,out] context 非実行の原構造試験の集計です
 * @note 人工CATを実署名済みとして扱いません
 */
//------------------------------------------------------------------------------
void inboxPortsRootMatrix( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Ports\r\n"
		"ClassGUID={4d36e978-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture\r\n"
		"CatalogFile=sample.cat\r\nDriverVer=11/19/2026,1.0.0.0\r\n"
		"[Manufacturer]\r\nFixture=Models,NTamd64\r\n"
		"[Models.NTamd64]\r\nFixture=Install,PCI\\VEN_1234&DEV_5678\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=11\r\n"
		"[Install.NT]\r\nAddReg=Page\r\nInclude=msports.inf\r\nNeeds=Serial.NT\r\n"
		"[Install.NT.HW]\r\nInclude=msports.inf\r\nNeeds=ComPort.NT.HW\r\n"
		"[Install.NT.Services]\r\nInclude=msports.inf\r\nNeeds=ComPort.NT.Services\r\n"
		"[Page]\r\nHKR,,EnumPropPages32,,\"MsPorts.dll,SerialPortPropPageProvider\"\r\n" ;	// 一つの選択と元のページ設定です
	using Mutation = std::pair<std::string_view, std::string_view> ;
	constexpr std::array changes{
		Mutation{},
		Mutation{"HKR,,EnumPropPages32", "HKLM,,EnumPropPages32"},
		Mutation{"HKR,,EnumPropPages32", "HKR,Other,EnumPropPages32"},
		Mutation{"EnumPropPages32,,", "EnumPropPages32,0x10000,"},
		Mutation{"MsPorts.dll,SerialPortPropPageProvider", "other.dll,SerialPortPropPageProvider"},
		Mutation{"MsPorts.dll,SerialPortPropPageProvider",
				 "MsPorts.dll,serialPortPropPageProvider"},
		Mutation{"Include=msports.inf", "Include=foreign.inf"},
		Mutation{"[Install.NT.HW]\r\n", "[Install.NT.HW]\r\nAddReg=Page\r\n"},
		Mutation{"[Page]\r\n",
				 "[Page]\r\nHKR,,Another,,value\r\n"}} ;		// 各例で元設定の一箇所だけを変えます
	constexpr std::array classes{std::wstring_view{L"Ports"}} ;	// 通常のPorts許可一覧です
	constexpr std::array signatures{
		std::wstring_view{L"$Windows NT$"}} ;	// INFのWindows形式識別子です
	OfficialInfInspectionPolicy policy{
		32U, 32U, classes, {}, signatures} ;	// 試験中の収集構造条件です
	policy.acceptAnyProvider			 = true ;
	policy.rejectInstallActions			 = true ;
	policy.allowRequiredDriverComponents = true ;
	policy.purpose						 = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;

	// 各元値を別の保護領域で検査し、他の例のデータを持ち越しません
	for( std::size_t index = 0U; index < changes.size(); ++index) {
		OfficialDownloadWorkspace workspace ;	// この例のINFと試験CATだけを保持します
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"inbox-ports", 71600U + index) == 0) ;
		std::string body{INF} ;							// 変化を適用する前の元本文です
		const auto &[before, after] = changes[index] ;	// この例の元値と変更先です
		// 正例は一切の置換をしません
		if( !before.empty()) {
			body.replace( body.find( before), before.size(), after) ;
		}

		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		const std::array   entries{OfficialZipEntry{L"sample.inf", body.size()},
								   OfficialZipEntry{L"sample.cat", 8U}} ;	// この例の配置済み内容です
		OfficialInfPackage package ;										// 成功時だけ返る元構造です
		const auto parsed = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
													  package) ;	// 通常の構造検査です
		context.expect( (parsed == 0) == (index == 0U),
					   "inbox Ports root " + std::to_string( index) + " error " +
						   std::to_string( parsed),
					   __FILE__, __LINE__) ;
		// 同じ元台帳にパッケージ同梱DLLのコピーを作らず、端末用途の対象にも加えません
		if( index == 0U && parsed == 0) {
			DRIVERCRATE_EXPECT( context, package.collectorInboxPropertyPageSection == L"Page" &&
											package.collectorInboxInstallGroups.size() == 1U &&
											!package.collectorPropertyPage &&
											package.sourceFiles.empty()) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
			auto devicePolicy	 = policy ;	// 同じ内容を元の端末用設定で検査します
			devicePolicy.purpose = OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
			DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"sample.inf",
																  devicePolicy, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 自己媒体Portsの元選択と標準ページの登録を正負で確認する
 * @param[in,out] context 保護領域を使う非実行試験の集計
 * @note 人工CATをWindowsの署名証拠へ使わない
 */
//------------------------------------------------------------------------------
void nativePortsPropertyPageMatrix( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Ports\r\n"
		"ClassGUID={4d36e978-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture\r\n"
		"CatalogFile=sample.cat\r\nDriverVer=11/21/2026,1.0.0.0\r\n"
		"[Manufacturer]\r\nFixture=Models,NTamd64\r\n"
		"[Models.NTamd64]\r\nOne=Install,USB\\VID_1234&PID_5678&MI_01\r\n"
		"Two=Install,USB\\VID_1234&PID_5678&MI_03\r\n"
		"Three=Install,USB\\VID_1234&PID_5678&MI_05\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=13\r\n"
		"[SourceDisksNames.amd64]\r\n1=Fixture,,,\r\n"
		"[SourceDisksFiles]\r\nserialtest.sys=1\r\n"
		"[Install.NT]\r\nCopyFiles=CopyDriver\r\nAddReg=DriverReg,PageReg\r\n"
		"[CopyDriver]\r\nserialtest.sys\r\n"
		"[Install.NT.Services]\r\nAddService=SerialTest,2,Service\r\n"
		"[Service]\r\nDisplayName=Fixture\r\nServiceType=1\r\n"
		"StartType=3\r\nErrorControl=1\r\nServiceBinary=%13%\\serialtest.sys\r\n"
		"[DriverReg]\r\nHKR,,NTMPDriver,,serialtest.sys\r\n"
		"[PageReg]\r\nHKR,,PortSubClass,1,01\r\n"
		"HKR,,EnumPropPages32,,\"MsPorts.dll,SerialPortPropPageProvider\"\r\n" ;	// 一媒体と三つの元登録
	using Mutation = std::pair<std::string_view, std::string_view> ;
	constexpr std::array cases{
		Mutation{},
		Mutation{"Class=Ports", "Class=System"},
		Mutation{"4d36e978-e325", "4d36e977-e325"},
		Mutation{"Three=Install,", "Three=Other,"},
		Mutation{"CopyFiles=CopyDriver", "CopyFiles=@CopyDriver"},
		Mutation{"DefaultDestDir=13", "DefaultDestDir=12"},
		Mutation{"serialtest.sys\r\n[Install.NT.Services]",
				 "serialtest.sys,other.sys\r\n[Install.NT.Services]"},
		Mutation{"AddReg=DriverReg,PageReg", "AddReg=DriverReg,PageReg,PageReg"},
		Mutation{"AddReg=DriverReg,PageReg\r\n",
				 "AddReg=DriverReg\r\n[Install.NT.HW]\r\nAddReg=PageReg\r\n"},
		Mutation{"AddReg=DriverReg,PageReg", "AddReg=DriverReg,PageReg\r\nInclude=msports.inf"},
		Mutation{"NTMPDriver,,serialtest.sys", "NTMPDriver,,other.sys"},
		Mutation{"HKR,,PortSubClass,1,01", "HKR,Other,PortSubClass,1,01"},
		Mutation{"HKR,,PortSubClass,1,01", "HKR,,PortSubClass,1,02"},
		Mutation{"HKR,,PortSubClass,1,01", "HKR,,PortSubClass,1,01,02"},
		Mutation{"EnumPropPages32,,", "EnumPropPages32,1,"},
		Mutation{"MsPorts.dll,SerialPortPropPageProvider", "Other.dll,SerialPortPropPageProvider"},
		Mutation{"MsPorts.dll,SerialPortPropPageProvider",
				 "MsPorts.dll,serialPortPropPageProvider"},
		Mutation{"AddService=SerialTest,2,", "AddService=SerialTest,0,"},
		Mutation{"StartType=3", "StartType=2"},
		Mutation{"ServiceBinary=%13%\\serialtest.sys", "ServiceBinary=%13%\\other.sys"},
		Mutation{"[PageReg]\r\n",
				 "[PageReg]\r\nHKR,,Other,,value\r\n"}} ;							// 一例につき一つの元条件を変更
	constexpr std::array		classes{std::wstring_view{L"Ports"}} ;				// 正式Portsだけを検査する
	constexpr std::array		signatures{std::wstring_view{L"$Windows NT$"}} ;	// 対象INFの識別子
	OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;			// 試験用の収集内容用途
	policy.acceptAnyProvider			 = true ;
	policy.rejectInstallActions			 = true ;
	policy.allowRequiredDriverComponents = true ;
	policy.purpose						 = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;

	// 各変異を独立した保護領域へ置き、収集の元構造だけを観測する
	for( std::size_t index = 0U; index < cases.size(); ++index) {
		OfficialDownloadWorkspace workspace ;	// この例の元INF、人工CATとSYSを保持
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"native-ports", 72100U + index) == 0) ;
		std::string body{INF} ;							// この例だけに適用する元本文
		const auto &[before, after] = cases[index] ;	// 元値と変異値の対
		// 正例は元の行を保持する
		if( !before.empty()) {
			const auto offset = body.find( before) ;	// 変異対象の元位置
			DRIVERCRATE_EXPECT( context, offset != body.npos) ;
			// 存在しない変異を有効な反例として続行しない
			if( offset == body.npos) {
				continue ;
			}

			body.replace( offset, before.size(), after) ;
		}

		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"serialtest.sys", "kernel")) ;
		const std::array   entries{OfficialZipEntry{L"sample.inf", body.size()},
								   OfficialZipEntry{L"sample.cat", 8U},
								   OfficialZipEntry{L"serialtest.sys", 6U}} ;	// 元媒体にある三ファイル
		OfficialInfPackage package ;											// 全構造が成立した場合に備える出力
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
													 package) ;	// 元INFの非実行検査
		context.expect( (error == 0U && package.nativePortsPage.has_value()) == (index == 0U),
					   "native Ports structure " + std::to_string( index) + " error " +
						   std::to_string( error),
					   __FILE__, __LINE__) ;
		// 正例は元SYSを通常の署名閉包へ残し、空媒体の委譲へ送らない
		if( index == 0U && package.nativePortsPage) {
			DRIVERCRATE_EXPECT(
				context, package.nativePortsPage->basicSection == L"Install" &&
							 CompareStringOrdinal( package.nativePortsPage->installSection.c_str(),
												  -1, L"Install.NT", -1, TRUE) == CSTR_EQUAL &&
							 package.nativePortsPage->registrySection == L"PageReg" &&
							 package.sourceFiles == std::vector<std::wstring>{L"serialtest.sys"} &&
							 package.collectorInboxInstallGroups.empty() &&
							 !package.collectorPropertyPage) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief NVMeの元三節と実在する空リストを収集専用構造として確認する
 * @param[in,out] context 保護領域を使う非実行試験の集計です
 * @note 人工CATでは後段の署名条件が成立しません
 */
//------------------------------------------------------------------------------
void inboxNvmeRootMatrix( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SCSIAdapter\r\n"
		"ClassGUID={4d36e97b-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture\r\n"
		"CatalogFile=sample.cat\r\nDriverVer=11/20/2026,1.0.0.0\r\n"
		"[Manufacturer]\r\nFixture=Models,NTamd64\r\n"
		"[Models.NTamd64]\r\nFixture=Install,PCI\\VEN_1234&DEV_5678&SUBSYS_01001234\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=12\r\n"
		"[SourceDisksFiles]\r\n[SourceDisksNames]\r\n1=Fixture,,,\"\"\r\n"
		"[Install.NT]\r\nCopyFiles=EmptyCopy\r\nDelFiles=EmptyRemove\r\n"
		"Include=stornvme.inf\r\nNeeds=Stornvme_Inst\r\n"
		"[Install.NT.HW]\r\nInclude=stornvme.inf\r\nNeeds=Stornvme_Inst.HW\r\n"
		"[Install.NT.Services]\r\nInclude=stornvme.inf\r\nNeeds=Stornvme_Inst.Services\r\n"
		"[EmptyCopy]\r\n[EmptyRemove]\r\n" ;	// 公開原INFと同じ元構造です
	using Mutation = std::pair<std::string_view, std::string_view> ;
	constexpr std::array changes{
		Mutation{},
		Mutation{"[EmptyCopy]\r\n", "[EmptyCopy]\r\nother.sys\r\n"},
		Mutation{"[EmptyRemove]\r\n", "[EmptyRemove]\r\nother.sys\r\n"},
		Mutation{"[EmptyRemove]\r\n", ""},
		Mutation{"DelFiles=EmptyRemove", "DelFiles=EmptyCopy"},
		Mutation{"CopyFiles=EmptyCopy", "CopyFiles=@EmptyCopy"},
		Mutation{"[EmptyRemove]\r\n", "[EmptyRemove]\r\n[EmptyCopy.security]\r\n"},
		Mutation{"CopyFiles=EmptyCopy", "CopyFiles=EmptyCopy,EmptyRemove"},
		Mutation{"1=Fixture,,,\"\"", "1=Fixture,disk.tag,,alternate"},
		Mutation{"Needs=Stornvme_Inst.HW", "Needs=Stornvme_Inst.Other"},
		Mutation{"Include=stornvme.inf", "Include=stornvme.inf,pci.inf"},
		Mutation{"[SourceDisksFiles]\r\n", ""}} ;							// 空・欠落・別作用を独立に区別します
	constexpr std::array classes{std::wstring_view{L"SCSIAdapter"}} ;		// 元の標準classです
	constexpr std::array signatures{std::wstring_view{L"$Windows NT$"}} ;	// 通常の形式識別子です
	OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;	// 収集側だけの条件です
	policy.acceptAnyProvider			 = true ;
	policy.rejectInstallActions			 = true ;
	policy.allowRequiredDriverComponents = true ;
	policy.purpose						 = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;

	// 各変化を別の保護領域に置き、元選択・元一覧を別の例へ借用しません
	for( std::size_t index = 0U; index < changes.size(); ++index) {
		OfficialDownloadWorkspace workspace ;	// この例だけの原INFと人工CATです
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"inbox-nvme", 71700U + index) == 0) ;
		std::string body{INF} ;							// 元節を再現する本文です
		const auto &[before, after] = changes[index] ;	// この例だけの変更です
		// 正例では元本文をそのまま使います
		if( !before.empty()) {
			body.replace( body.find( before), before.size(), after) ;
		}

		// 同名の空節があっても、直接コピーと付随する権限節を区別します
		if( after == "CopyFiles=@EmptyCopy") {
			body.replace( body.find( "[EmptyCopy]"), std::string_view{"[EmptyCopy]"}.size(),
						 "[@EmptyCopy]") ;
		}
		// 削除先を空の付随権限節に変えて、全節の閉集合が成立する形でも拒否します
		else if( after.find( ".security]") != after.npos) {
			body.replace( body.find( "DelFiles=EmptyRemove"),
						 std::string_view{"DelFiles=EmptyRemove"}.size(),
						 "DelFiles=EmptyCopy.security") ;
			body.replace( body.find( "[EmptyRemove]\r\n"),
						 std::string_view{"[EmptyRemove]\r\n"}.size(), "") ;
		}

		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		const std::array entries{
			OfficialZipEntry{L"sample.inf", body.size()},
			OfficialZipEntry{L"sample.cat", 8U}} ;	// 元アーカイブの全二ファイルです
		OfficialInfPackage package ;				// 収集側の検査結果です
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
													 package) ;	// 通常の読取経路で処理します
		context.expect( (error == 0) == (index == 0U),
					   "inbox NVMe root " + std::to_string( index) + " error " +
						   std::to_string( error),
					   __FILE__, __LINE__) ;
		// 正常構造だけで署名や端末用途を許可しないことも確認します
		if( index == 0U && error == 0) {
			DRIVERCRATE_EXPECT( context,
							   package.collectorInboxNvmeLists &&
								   package.collectorInboxNvmeLists->copy == L"EmptyCopy" &&
								   package.collectorInboxNvmeLists->remove == L"EmptyRemove" &&
								   package.collectorInboxInstallGroups.size() == 1U &&
								   package.collectorInboxInstallGroups.front().size() == 3U &&
								   package.sourceFiles.empty()) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
			auto devicePolicy	 = policy ;	// 収集専用の元構造を端末用途でも渡す対照です
			devicePolicy.purpose = OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
			DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"sample.inf",
																  devicePolicy, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 正式HDCの空媒体と元の三参照が収集専用で認められることを確認する
 * @param[in,out] context 元構造の正負例の集計先
 * @note 架空CATは元署名を持たず、端末用途と署名の検査結果は成功させない
 */
//------------------------------------------------------------------------------
void inboxAhciRootMatrix( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=hdc\r\n"
		"ClassGUID={4d36e96a-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture\r\n"
		"CatalogFile=sample.cat\r\nDriverVer=11/21/2026,1.0.0.0\r\n"
		"[Manufacturer]\r\nFixture=Models,NTamd64\r\n"
		"[Models.NTamd64]\r\nFixture=Install,PCI\\VEN_1234&DEV_5678&SUBSYS_01001234\r\n"
		"[SourceDisksNames]\r\n[SourceDisksFiles]\r\n"
		"[PackageInfo]\r\nName=Chipset\r\nCondition=Provider(Microsoft)||InstalledDriverName(Chipset)||Provider()\r\n"
		"[Install.NT]\r\nInclude=mshdc.inf\r\nNeeds=msahci_Inst\r\nFeatureScore=80\r\n"
		"[Install.NT.HW]\r\nInclude=mshdc.inf\r\nNeeds=msahci_Inst.HW\r\n"
		"[Install.NT.Services]\r\nInclude=mshdc.inf\r\nNeeds=msahci_Inst.Services\r\n" ;	// Windows標準AHCIを指す元の閉じた構造
	using Mutation = std::pair<std::string_view, std::string_view> ;
	constexpr std::array changes{
		Mutation{},
		Mutation{"Class=hdc", "Class=System"},
		Mutation{"4d36e96a", "4d36e97b"},
		Mutation{"FeatureScore=80", "FeatureScore=81"},
		Mutation{"FeatureScore=80", "FeatureScore=80,81"},
		Mutation{"FeatureScore=80\r\n", "FeatureScore=80\r\nCopyFiles=@sample.sys\r\n"},
		Mutation{"Needs=msahci_Inst.HW", "Needs=msahci_Inst.Services"},
		Mutation{"Include=mshdc.inf", "Include=mshdc.inf,other.inf"},
		Mutation{"[SourceDisksFiles]\r\n", "[SourceDisksFiles]\r\nother.sys=1\r\n"},
		Mutation{"Provider()", "Provider(Other)"},
		Mutation{"[PackageInfo]\r\n", "[AlternateInfo]\r\n"}} ;				// 元構造の異なる各一箇所だけを変える
	constexpr std::array classes{std::wstring_view{L"System"}} ;			// 一般クラスへHDCを加えない対照
	constexpr std::array signatures{std::wstring_view{L"$Windows NT$"}} ;	// 標準INFの形式識別子
	OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;	// 共通の元検査設定
	policy.acceptAnyProvider			 = true ;
	policy.rejectInstallActions			 = true ;
	policy.allowRequiredDriverComponents = true ;
	policy.purpose						 = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;

	// 元の正例と各不一致を独立した保護領域で確認する
	for( std::size_t index = 0U; index < changes.size(); ++index) {
		OfficialDownloadWorkspace workspace ;	// この例だけの元ファイル
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"inbox-ahci", 71800U + index) == 0) ;
		std::string body{INF} ;							// この例の元本文
		const auto &[before, after] = changes[index] ;	// 一箇所の元差分
		// 正例は同じ本文を保持する
		if( !before.empty()) {
			body.replace( body.find( before), before.size(), after) ;
		}

		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		const std::array entries{
			OfficialZipEntry{L"sample.inf", body.size()},
			OfficialZipEntry{L"sample.cat", 8U}} ;	// 元の二ファイルだけを記録する
		OfficialInfPackage package ;				// 元構造の成功時だけ得る結果
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
													 package) ;	// 通常の元INF検査
		context.expect( (error == 0) == (index == 0U),
					   "inbox AHCI root " + std::to_string( index) + " error " +
						   std::to_string( error),
					   __FILE__, __LINE__) ;
		// 正例でも実署名と端末の選択用途を別に拒否する
		if( index == 0U && error == 0) {
			const std::vector<std::vector<std::wstring>> expected{
				{L"Install.NT", L"Install.NT.HW", L"Install.NT.Services"}} ;	// 一つの元選択と付随節
			DRIVERCRATE_EXPECT( context, package.collectorInboxInstallGroups == expected &&
											!package.collectorInboxNvmeLists &&
											package.sourceFiles.empty()) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
			auto devicePolicy	 = policy ;	// 同じ本文を端末用途へ渡す対照
			devicePolicy.purpose = OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
			DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"sample.inf",
																  devicePolicy, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 原software参照と限定CoInstallerの正負例を確認します
 * @param[in,out] context 一processの有限集計先です
 */
//------------------------------------------------------------------------------
void attachedMatrix( TestContext &context)
{
	constexpr std::string_view SOFTWARE =
		"[Install.NT.Software]\r\nAddSoftware=FixtureProgram,0,Software\r\n"
		"[Software]\r\nSoftwareType=1\r\nSoftwareBinary=%13%\\helper.exe\r\nSoftwareVersion=2.0.0.0\r\n"
		"[UnreferencedStore]\r\nSoftwareType=2\r\nSoftwareID=pfn://fixture_unused\r\n" ;	// 未参照Type2は必要appへ変換しません
	constexpr std::string_view COINSTALLER =
		"[Install.NT.CoInstallers]\r\nAddReg=Registration\r\nCopyFiles=CoFiles\r\n"
		// 元DLL/entrypointのdevice-local登録です
		"[Registration]\r\nHKR,,CoInstallers32,0x00010000,\"helper.dll,FixtureEntry\"\r\n" ;
	std::uint64_t			   identity = 71000U ;	// 条件間で単独所有を区別します
	constexpr std::string_view TYPE2 =
		"[Install.NT.Software]\r\nAddSoftware=FixtureStore,0,Store\r\n"
		// 架空PFNだけの元Store metadataです
		"[Store]\r\nSoftwareType=2\r\nSoftwareID=pfn://Fixture.DriverSupport_abcdefghjkmnp\r\n" ;
	attachedCase( context, TYPE2, {}, {}, true, true, true, identity++) ;
	attachedCase( context, TYPE2, {}, {}, false, false, false, identity++) ;
	attachedCase( context, TYPE2, "pfn://Fixture.DriverSupport_abcdefghjkmnp",
				 "https://invalid.example/app", true, false, false, identity++) ;
	attachedCase( context, TYPE2, "pfn://Fixture.DriverSupport_abcdefghjkmnp", "pfn://invalid", true,
				 false, false, identity++) ;
	std::string metadataOnly( ATTACHED_INF) ;	// program参照がない場合も作用flagを保持します
	metadataOnly.replace( metadataOnly.find( "CopyFiles=DriverFiles,ProgramFiles"),
						 std::string_view( "CopyFiles=DriverFiles,ProgramFiles").size(),
						 "CopyFiles=DriverFiles") ;
	metadataOnly.erase( metadataOnly.find( "helper.exe=1\r\n"),
					   std::string_view( "helper.exe=1\r\n").size()) ;
	attachedCase( context, TYPE2, ATTACHED_INF, metadataOnly, true, true, true, identity++) ;
	std::string duplicate( SOFTWARE) ;	// 同じ節の二番目AddSoftwareも検査します
	duplicate.replace( duplicate.find( "[Software]"), 0U,
					  "[Install.NT.Software]\r\nAddSoftware=FixtureStore,0,Store\r\n") ;
	duplicate +=
		"[Store]\r\nSoftwareType=2\r\nSoftwareID=pfn://Fixture.DriverSupport_abcdefghjkmnp\r\n" ;
	attachedCase( context, duplicate,
				 "Class=Display\r\nClassGUID={4d36e968-e325-11ce-bfc1-08002be10318}",
				 "Class=SoftwareComponent\r\nClassGUID={5c4c3332-344d-483c-8739-259e934c9cc8}",
				 true, true, true, identity++) ;
	attachedCase( context, duplicate, "pfn://Fixture.DriverSupport_abcdefghjkmnp", "pfn://invalid",
				 true, false, false, identity++) ;
	attachedCase( context, SOFTWARE, {}, {}, true, true, true, identity++) ;
	attachedCase( context, SOFTWARE, {}, {}, false, false, false, identity++) ;
	attachedCase( context, SOFTWARE, "ProgramFiles=13", "ProgramFiles=11", true, false, false,
				 identity++) ;
	attachedCase( context, SOFTWARE, "SoftwareType=1", "SoftwareType=2", true, false, false,
				 identity++) ;
	attachedCase( context, SOFTWARE, "SoftwareBinary=%13%\\helper.exe",
				 "SoftwareBinary=%13%\\other.exe", true, false, false, identity++) ;
	attachedCase( context, SOFTWARE, "Install.NT.Software", "Orphan.Software", true, false, false,
				 identity++) ;
	// 標準値・不透明な別名・正式な等価system directoryを区別して確認します
	attachedCase( context, COINSTALLER, {}, {}, true, true, true, identity++) ;
	attachedCase( context, COINSTALLER, "CoInstallers32", "CoInstallers64", true, true, true,
				 identity++) ;
	attachedCase( context, COINSTALLER, "CoFiles=11", "CoFiles=10,system32", true, true, true,
				 identity++) ;
	attachedCase( context, COINSTALLER, "HKR,,CoInstallers32", "HKLM,,CoInstallers32", true, false,
				 false, identity++) ;
	attachedCase( context, COINSTALLER, "HKR,,CoInstallers32",
				 "HKR,Software\\CurrentVersion\\Run,CoInstallers32", true, false, false,
				 identity++) ;
	attachedCase( context, COINSTALLER, "CoFiles=11", "CoFiles=12", true, false, false, identity++) ;
	attachedCase( context, COINSTALLER, "CoFiles=11", "CoFiles=10,other", true, false, false,
				 identity++) ;
	attachedCase( context, COINSTALLER, "helper.dll,FixtureEntry", "helper.dll,cmd /c execute", true,
				 false, false, identity++) ;
	attachedCase( context, COINSTALLER, "helper.dll,FixtureEntry", "..\\helper.dll,FixtureEntry",
				 true, false, false, identity++) ;
	attachedCase( context, COINSTALLER, "[CoFiles]\r\nhelper.dll",
				 "[CoFiles]\r\nhelper.dll,other.dll", true, false, false, identity++) ;
	attachedCase( context, COINSTALLER, "Install.NT.CoInstallers", "Orphan.CoInstallers", true,
				 false, false, identity++) ;
	attachedCase( context, COINSTALLER, "0x00010000,\"helper.dll", "0,\"helper.dll", true, false,
				 false, identity++) ;
}
} // namespace
} // namespace drivercrate::test

//------------------------------------------------------------------------------
/**
 * @brief 非対話の局所回帰または明示INFの最初の構造診断を実行します
 * @param[in] count 実行fileを含む引数数です
 * @param[in] arguments --diagnose-infと私有原INF、または引数なしです
 * @return 全試験成功0、不正入力2、fixtureまたは診断段階の失敗1です
 * @note CRT/OSの非対話設定を入力やassertionより前に適用します
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
		// 明示元INFだけの構造を診断し、virtual source一覧に内容/CAT合格を発行しません
		if( (count == 3 && std::wstring_view( arguments[1]) == L"--diagnose-structure") ||
		   (count == 4 && std::wstring_view( arguments[1]) == L"--diagnose-scope")) {
			std::ifstream						   input( std::filesystem::path( arguments[2]),
														 std::ios::binary) ;	// 原小INFだけです
			const std::string					   bytes( std::istreambuf_iterator<char>{input},
														 {}) ;	// 元byteを変更しません
			drivercrate::OfficialDownloadWorkspace workspace ;	// 診断専用の原INF保護領域です
			// 原読取失敗や上限超過を空構造の成功へ変換しません
			if( !input || bytes.empty() || bytes.size() > 4U * 1024U * 1024U ||
			   workspace.initialize( L"structure-only-test", 712U) != 0 ||
			   !drivercrate::test::writeWorkspaceFile( workspace, L"sample.inf", bytes)) {
				return 1 ;
			}

			const drivercrate::UniqueInf inf( SetupOpenInfFileW(
				workspace.path( L"sample.inf").c_str(), nullptr,
				INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;	// 元Windows readerだけです
			std::wstring				 catalog ;						// 原CAT file宣言です
			std::vector<std::wstring>	 sources ;						// 原全SDF位置です。実byte確認ではありません
			// 不正構造をvirtual一覧の都合へ合わせません
			if( inf.get() == INVALID_HANDLE_VALUE ||
			   drivercrate::readCatalogFile( inf.get(), catalog) != 0 ||
			   drivercrate::readOfficialInfSourcePaths( workspace, L"sample.inf", 8192U, sources) !=
				   0) {
				return 1 ;
			}

			std::vector<drivercrate::OfficialZipEntry> entries{
				{L"sample.inf", bytes.size()}, {catalog, 1U}} ;	// 存在宣言だけの非権限一覧です
			// 原全source名を保持し、構造以外の成功を表しません
			for( const auto &source : sources) {
				entries.push_back( {source, 1U}) ;
			}

			constexpr std::array classes{
				std::wstring_view( L"Display"), std::wstring_view( L"MEDIA"),
				std::wstring_view(
					// 今回の元三Classを比較する診断値です。製品allowlistではありません
					L"USB")} ;
			constexpr std::array signatures{std::wstring_view( L"$Windows NT$")} ;	// 構文だけです
			drivercrate::OfficialInfInspectionPolicy policy{
				4096U, 8192U, classes, {}, signatures} ;	// 元内容modeと同じ構造条件です
			policy.acceptAnyProvider					   = true ;
			policy.requireDriverBinary					   = false ;
			policy.rejectUnreferencedPrograms			   = false ;
			policy.rejectInstallActions					   = true ;
			policy.allowReferencedExecutablesForContent	   = true ;
			policy.allowRequiredDriverComponents		   = true ;
			policy.allowWindowsManagedDriverDataForContent = true ;
			drivercrate::OfficialInfPackage package ;	// 内容合格へ転用しない元構造です
			const auto						error = drivercrate::inspectOfficialInfPackage(
				 workspace, entries, L"sample.inf", policy, package) ;	// 元構造診断だけです
			std::cout << "structureError=" << error << " sourceDeclarations=" << sources.size()
					  << " fullContentProof=0\n" ;
			// 原selected棚卸しAPIの失敗だけを内容/CATと独立して診断します
			if( count == 4) {
				static_cast<void>( drivercrate::computeFileSha256( workspace.path( L"sample.inf"),
																 entries.front().sha256)) ;
				drivercrate::OfficialInfInstallInventory
						   inventory ;	// 導入許可を持たない原棚卸しです
				const auto inventoryError = drivercrate::inspectOfficialInfInstallInventory(
					workspace, entries, L"sample.inf", arguments[3],
					inventory) ;	// 元API返値を保持します
				std::cout << "selectedInventoryError=" << inventoryError << " fullContentProof=0\n" ;
				std::size_t maximumFields{} ;	// 元一行の最大field数だけを観測します
				// 本文や値を出さず、原全節の最大構文容量だけを読みます
				for( UINT ordinal = 0U; ordinal < 4096U; ++ordinal) {
					std::array<wchar_t, 256U> section{} ;	// 原節名の有限読取領域です
					// 元Windows列挙の終端で終了します
					if( !SetupEnumInfSectionsW( inf.get(), ordinal, section.data(),
											  static_cast<UINT>( section.size()), nullptr)) {
						break ;
					}

					INFCONTEXT row{} ;	// 元行を読取り専用で走査します
					// 明示空節をfield不足へ変換しません
					if( SetupFindFirstLineW( inf.get(), section.data(), nullptr, &row)) {
						// 原全行のfield数だけを集計します
						do {
							maximumFields = (std::max)(
								maximumFields, static_cast<std::size_t>( SetupGetFieldCount( &row))) ;
						} while( SetupFindNextLine( &row, &row)) ;
					}
				}

				std::cout << "maximumRawFields=" << maximumFields << " executed=0\n" ;
				drivercrate::OfficialInfPackage selected ;	// 元選択の非権限構造だけです
				const auto relationError = drivercrate::inspectSelectedOfficialInfRelations(
					workspace, entries, package, arguments[3], selected) ;	// 実元読取です
				const auto scopeError =
					relationError != 0
						? relationError
						: drivercrate::inspectSelectedWindowsDriverPackageScope(
							  workspace, entries, selected) ;	// 全内容証拠ではありません
				std::cout << "selectedScopeError=" << scopeError << " fullContentProof=0\n" ;
				drivercrate::OfficialInfInstallInventory
						   formal ;	// 全registryを辿らない元正式関係です
				const auto formalError = drivercrate::readWindowsDriverScopeReferences(
					// 原関係診断です
					inf.get(), selected, formal) ;
				std::cout << "formalReferencesError=" << formalError
						  << " copies=" << formal.references.size() << '\n' ;
				std::vector<drivercrate::WindowsDriverCopy> copies ;	// 同元位置の静的結合だけです
				// 先頭の不成立copyの正式list/nameを示し、内容成功へ変換しません
				for( const auto &reference : formal.references) {
					// 直接fileは本実測の対象外として後段の元診断へ残します
					if( reference.kind !=
					   drivercrate::OfficialInfInstallReferenceKind::LOCAL_SECTION) {
						continue ;
					}

					const auto lines =
						// 元copy行数です
						SetupGetLineCountW( inf.get(), reference.target.c_str()) ;
					// 全元行の同位置結合を原順で検査します
					for( LONG index = 0L; index < lines; ++index) {
						INFCONTEXT	 line{} ;	// 同元行のcursorです
						std::wstring target ;	// 元target leafです
						std::wstring source ;	// 元rename sourceです
						// 診断でも読取失敗を空fieldへ補完しません
						if( !SetupGetLineByIndexW( inf.get(), reference.target.c_str(),
												 static_cast<DWORD>( index), &line) ||
						   drivercrate::readInfField( line, 1U, target) != 0 ||
						   (SetupGetFieldCount( &line) > 1U &&
							drivercrate::readInstallInventoryField( line, 2U, source) != 0)) {
							return 1 ;
						}

						const auto copyError = drivercrate::bindWindowsDriverCopy(
							inf.get(), workspace, entries, selected, reference.target, target,
							// 元静的関係だけです
							source.empty() ? target : source, copies) ;
						// 最初の不成立で停止し、値本文を出しません
						if( copyError != 0) {
							std::wcout << L"firstCopyList=" << reference.target << L" file="
									   << target << L" error=" << copyError << L'\n' ;
							return 1 ;
						}
					}
				}

				std::cout << "formalCopyBindings=" << copies.size() << " fullContentProof=0\n" ;
				return inventoryError == 0 ? 0 : 1 ;
			}

			return error == 0 ? 0 : 1 ;
		}

		// 明示された原INFの先頭段階だけを読み、payloadを実行しません
		if( count == 3 && std::wstring_view( arguments[1]) == L"--diagnose-inf") {
			const drivercrate::UniqueInf inf(
				SetupOpenInfFileW( arguments[2], nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
								  nullptr)) ;	// 同期中だけ所有する原INFです
			// 原INFを開けない条件を別段階の成功へ変換しません
			if( inf.get() == INVALID_HANDLE_VALUE) {
				std::cout << "open=" << GetLastError() << '\n' ;
				return 1 ;
			}

			bool	   dependencies{} ;	// 存在だけの観測です
			const auto actions = drivercrate::validateInfInstallActions(
				// 内容modeの原診断です
				inf.get(), false, dependencies, true, true) ;
			std::wstring className ;	// 原VersionのClassだけです
			const auto	 classError = drivercrate::readInfDirective(
				  // 原取得診断です
				  inf.get(), L"Version", L"Class", 1U, className) ;
			std::vector<std::wstring> executables ;	// 既知の必要参照だけです
			const auto services = classError == 0 ? drivercrate::collectRequiredServiceExecutables(
														inf.get(), className, executables, true)
												  : classError ;	// 内容modeです
			const auto copies =
				services == 0
					? drivercrate::collectRequiredCopyExecutables( inf.get(), className, executables)
					: services ;	// 原コピー診断です
			std::cout << "actions=" << actions << " services=" << services << " copies=" << copies
					  << " knownExecutables=" << executables.size() << '\n' ;
			std::wstring catalog ;	// 元CAT指定の取得だけです
			const auto	 catalogError =
				// 原CAT directive診断です
				drivercrate::readCatalogFile( inf.get(), catalog) ;
			std::vector<std::wstring> ids ;	// 原Modelsだけから取得する診断用集合です
			const auto				  modelsError = drivercrate::collectHardwareIds(
				   // 既存native選択の診断です
				   inf.get(), 4096U, ids) ;
			std::cout << "catalogDeclaration=" << catalogError << " models=" << modelsError
					  << " modelIds=" << ids.size() << '\n' ;
			INFCONTEXT sourceRow{} ;	// 元amd64優先SourceDisksFilesの先頭です
			// 存在する元sourceだけのfield/形式診断とし、全closure合格の代用にしません
			if( SetupFindFirstLineW( inf.get(), L"SourceDisksFiles.amd64", nullptr, &sourceRow) ||
			   SetupFindFirstLineW( inf.get(), L"SourceDisksFiles", nullptr, &sourceRow)) {
				std::size_t sources{} ;	// 診断の有限行予算です
				// 原位置readerと内容modeの拡張子境界を各sourceへ適用します
				do {
					std::wstring file ;			// 原SDF keyの公開配布file名だけです
					std::wstring directory ;	// 元source subdirです
					std::wstring media ;		// 元媒体相対位置です
					const auto	 keyError =
						// 原key診断です
						drivercrate::readInfField( sourceRow, 0U, file) ;
					const auto sourceError = keyError == 0 ? drivercrate::readInfSourceDirectories(
																 inf.get(), file, directory, media)
														   : keyError ;	// 原位置診断です
					const auto extension =
						// 同原fileの形式だけです
						drivercrate::lowerExtension( file) ;
					const bool passive = extension == L".bin" || extension == L".dfu" ||
										 extension == L".mbn" ||
										 // 既存driver data形式です
										 extension == L".elf" ;
					const bool program = extension == L".exe" || extension == L".msi" ||
										 // 内容modeの原参照です
										 extension == L".cab" ;
					const bool rejected =
						!passive && !program &&
						std::ranges::find( drivercrate::REJECTED_REFERENCED_EXTENSIONS, extension) !=
							// 既存拒否集合です
							drivercrate::REJECTED_REFERENCED_EXTENSIONS.end() ;
					// 最初の元診断または未知形式だけを示して停止します
					if( ++sources > 8192U || sourceError != 0 || rejected) {
						std::wcout << L"firstSourceOrdinal=" << sources << L" sourceError="
								   << sourceError << L" extensionRejected=" << rejected
								   << L" extension=" << extension << L'\n' ;
						break ;
					}
				} while( SetupFindNextLine( &sourceRow, &sourceRow)) ;
				std::cout << "sourceDeclarationsObserved=" << sources << " closureProof=0\n" ;
			}

			// 元software失敗をClass限定と別の実コピー制約へ分離します
			if( actions != 0) {
				// 全節の最初の不成立AddSoftwareだけを私有診断へ出します
				for( UINT index = 0U; index < 4096U; ++index) {
					std::array<wchar_t, 257U> section{} ;	// 有限の原section名です
					// 元列挙の終端で診断走査も終えます
					if( !SetupEnumInfSectionsW( inf.get(), index, section.data(),
											  static_cast<UINT>( section.size()), nullptr)) {
						break ;
					}

					INFCONTEXT software{} ;	// 同元AddSoftwareです
					// software参照がない節から別の作用を推測しません
					if( !SetupFindFirstLineW( inf.get(), section.data(), L"AddSoftware", &software)) {
						continue ;
					}

					const auto error = drivercrate::validateRequiredSoftwareDeclaration(
						// 元必要参照の診断です
						inf.get(), section.data(), software, true) ;
					// 最初の失敗に対応するDDInstallとコピーを直接確認します
					if( error != 0) {
						std::wstring	   declaration ;	// 同元software-install節です
						std::wstring	   binary ;			// 元binary全値です
						const std::wstring install =
							std::wstring( section.data())
								.substr( 0U, std::wstring_view( section.data()).size() -
												9U) ;	// 元Software suffixを外します
						const auto named =
							// 原参照診断です
							drivercrate::readInfField( software, 3U, declaration) ;
						const auto binaryError =
							named == 0 ? drivercrate::readRequiredServiceField(
											 inf.get(), declaration, L"SoftwareBinary", binary)
									   : named ;	// 原binary診断です
						const auto file =
							binary.substr( binary.find_last_of( L'\\') == binary.npos
											  ? 0U
											  : binary.find_last_of( L'\\') + 1U) ;	// 同元leafです
						std::wstring source ;										// 私有診断だけの位置です
						const auto	 relaxedCopy =
							  binaryError == 0 ? drivercrate::inspectRequiredServiceCopy(
													 inf.get(), install, file, L"", source)
											   : binaryError ;	// 実行を伴わない位置検査だけです
						std::wstring directory ;				// 同元source subdirです
						std::wstring media ;					// 同元source媒体です
						const auto	 sourceError = drivercrate::readRequiredServiceSourceDirectory(
							  // 元SDF診断です
							  inf.get(), file, directory, media) ;
						std::wcout << L"firstSoftwareSection=" << section.data() << L" error="
								   << error << L" modelsLinked="
								   << drivercrate::hasModelsInstallReference( inf.get(), install)
								   << L" copiedSourceOnlyError=" << relaxedCopy << L" sourceError="
								   << sourceError << L'\n' ;
						break ;
					}
				}
			}

			return actions == 0 && services == 0 && copies == 0 ? 0 : 1 ;
		}

		// 元INFから採った全Models行を読み取り専用で役割確認する
		if( count == 4 && std::wstring_view( arguments[1]) == L"--diagnose-model-roles") {
			return drivercrate::test::diagnoseOriginalModelRoles( arguments[2], arguments[3]) ;
		}

		// 不正CLIを試験成功へ読み替えません
		if( count != 1) {
			return 2 ;
		}

		drivercrate::test::TestContext context ;	// 実行した局所assertionだけの集計です
		drivercrate::test::testEmptyCoInstallerReferences( context) ;
		drivercrate::test::testStandardComponentActions( context) ;
		drivercrate::test::attachedMatrix( context) ;
		drivercrate::test::windowsScopeMatrix( context) ;
		drivercrate::test::inboxSdHostRootMatrix( context) ;
		drivercrate::test::inboxPortsRootMatrix( context) ;
		drivercrate::test::nativePortsPropertyPageMatrix( context) ;
		drivercrate::test::inboxNvmeRootMatrix( context) ;
		drivercrate::test::inboxAhciRootMatrix( context) ;
		drivercrate::test::registeredDriverStorePackageMatrix( context) ;
		drivercrate::test::declarativeSetupClassMatrix( context) ;
		drivercrate::test::scopedDeclarativeKernelMatrix( context) ;
		drivercrate::test::activeAmd64SourceMatrix( context) ;
		drivercrate::test::selectedModelRoleMatrix( context) ;
		drivercrate::test::nativeModelIdBufferMatrix( context) ;
		drivercrate::test::declarativeClassEffectValues( context) ;
		drivercrate::test::declarativeClassEffectFailures( context) ;
		std::cout << "Assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
	} catch( const std::bad_alloc &) {
		std::cerr << "INF fixture allocation failed.\n" ;
		return 1 ;
	} catch( const std::exception &) {
		std::cerr << "INF fixture exception.\n" ;
		return 1 ;
	} catch( ...) {
		std::cerr << "INF fixture unknown exception.\n" ;
		return 1 ;
	}
}
