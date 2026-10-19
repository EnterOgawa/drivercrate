//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_catalog_parser_tests.cpp
 * @brief NVIDIA Networking WinOF-2公式検索単体試験実装。
 * @version 01.00.01
 * @date 2026/09/06
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 実Hardware ID、instance path、serial numberをfixtureへ含めません。公式形式を模した架空versionとhashを使い、network
 *       requestは実行しません。
 */
//------------------------------------------------------------------------------

#include "nvidia_winof2_catalog_parser_tests.h"

#include "core/provider_registry.h"
#include "platform/nvidia_winof2_catalog_parser.h"
#include "platform/nvidia_winof2_update_provider.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr ScanSessionId		SESSION = 83U ;				// 合成WinOF-2検索で使用するsession ID。
constexpr std::wstring_view VERSION = L"26.9.54321" ;	// 公式形式を模した架空package版。
// 公式委譲構造だけを再現した、実通信に使用しないHTML fixture。
constexpr std::wstring_view LANDING_PAGE =
	LR"(<html><h1>WinOF-2 / WinOF Drivers</h1>)"
	LR"(<p>For <b>ConnectX-4 and onwards adapter cards</b> drivers download )"
	LR"(<b>WinOF-2.</b></p><iframe src=")"
	LR"(https://downloaders.azurewebsites.net/downloaders/winof2_downloader/)"
	LR"(downloader4.html"></iframe></html>)" ;
// LatestとGAの照合を検証する架空release一覧。
constexpr std::wstring_view VERSIONS_JSON =
	LR"({"latest":"26.9.54321","versions":["26.8.10000","26.9.54321"],)"
	LR"("ga":["26.9.54321"]})" ;
// File名・URL・hashを結合して検証する架空配布metadata。
constexpr std::wstring_view DOWNLOAD_JSON =
	LR"({"files":[{"file":"MLNX_WinOF2-26_9_54321_All_x64.exe",)"
	LR"("desc":"WinOF Driver","size":"401 MB",)"
	LR"("sha":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",)"
	LR"("md5sum":"","url":)"
	LR"("https://www.mellanox.com/downloads/WinOF/)"
	LR"(MLNX_WinOF2-26_9_54321_All_x64.exe"}],"docs":[)"
	LR"({"desc":"Release Notes","url":)"
	LR"("https://networking-docs.nvidia.com/winof2driverum/26.9.54321/release-notes"},)"
	LR"({"desc":"User Manual","url":)"
	LR"("https://networking-docs.nvidia.com/winof2driverum/26.9.54321/user-manual"}]})" ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Hardware ID、instance path、serial numberを含めない。
 *
 * @param[in] identity 架空のopaque device identity。
 * @return ConnectX-6を示す非機密snapshotの所有値。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice winof2Device( std::wstring identity)
{
	OfficialCatalogDevice device ;	// 試験ごとに変更できるlocal snapshot。
	device.deviceIdentity  = std::move( identity) ;
	device.manufacturer	   = L"Mellanox Technologies" ;
	device.model		   = L"ConnectX-6 Dx Ethernet Adapter" ;
	device.driverClass	   = L"Net" ;
	device.deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
	device.currentProvider = L"NVIDIA Corporation" ;
	device.currentVersion  = L"1.2.3.4" ;
	return device ;
}

//------------------------------------------------------------------------------
/**
 * @brief Server 2025経路の五段階とpercent encodeを完全一致で検証する。
 *
 * @param[in] formBody Provider helperが生成した固定form body。
 * @return 対応する合成JSON。不正field順または未知actionでは空。
 */
//------------------------------------------------------------------------------
std::wstring metadataResponse( const std::string_view formBody)
{
	// version一覧の正確な要求にだけ架空version応答を返す。
	if( formBody == "action=get_versions") {
		return std::wstring( VERSIONS_JSON) ;
	}

	// 選択versionを含むdistribution要求にだけ架空OS系列一覧を返す。
	if( formBody == "action=get_distros&version=26.9.54321") {
		return LR"(["Windows Server","Windows Client 10","Windows Client 11"])" ;
	}

	// Server系列がpercent encodeされた要求にだけ対象OS一覧を返す。
	if( formBody == "action=get_oses&version=26.9.54321&distro=Windows%20Server") {
		return LR"(["2016 / 2019 / 2022 / 2025"])" ;
	}

	// version・系列・OSが一致するarchitecture要求にだけx64を返す。
	if( formBody == "action=get_arches&version=26.9.54321&distro=Windows%20Server&"
				   "os=2016%20%2F%202019%20%2F%202022%20%2F%202025") {
		return LR"("x64")" ;
	}

	// 全選択条件が一致した取得情報要求にだけ架空payload metadataを返す。
	if( formBody == "action=get_download_info&version=26.9.54321&"
				   "distro=Windows%20Server&os=2016%20%2F%202019%20%2F%202022%20%2F%202025&"
				   "arch=x64") {
		return std::wstring( DOWNLOAD_JSON) ;
	}

	return {} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 委譲page、version、選択肢、download情報と明示OS buildを検証する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testValidParsersAndOsSelection( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, parseNvidiaWinof2LandingPage( LANDING_PAGE)) ;
	std::wstring version ;	// Parserが選んだcurrent package版。
	DRIVERCRATE_EXPECT( context, parseNvidiaWinof2Versions( VERSIONS_JSON, version)) ;
	DRIVERCRATE_EXPECT( context, version == VERSION) ;

	std::vector<std::wstring> values ;	// String／array応答の所有選択肢。
	DRIVERCRATE_EXPECT( context, parseNvidiaWinof2StringList( LR"("x64")", values)) ;
	DRIVERCRATE_EXPECT( context, values.size() == 1U && values[0] == L"x64") ;
	DRIVERCRATE_EXPECT( context, parseNvidiaWinof2StringList( LR"(["x64","arm64"])", values)) ;
	DRIVERCRATE_EXPECT( context, values.size() == 2U) ;

	NvidiaWinof2Release release ;	// 検証済み合成配布情報。
	DRIVERCRATE_EXPECT( context, parseNvidiaWinof2DownloadInfo( DOWNLOAD_JSON, VERSION, release)) ;
	DRIVERCRATE_EXPECT( context, release.packageVersion == VERSION) ;
	DRIVERCRATE_EXPECT( context, release.displaySize == L"401 MB") ;
	DRIVERCRATE_EXPECT( context,
					   release.sha256 ==
						   L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ;

	NvidiaWinof2OsSelection selection ;	// 実buildに対応する公開選択値。
	DRIVERCRATE_EXPECT( context, selectNvidiaWinof2Os( true, 14'393U, selection)) ;
	DRIVERCRATE_EXPECT( context, selection.distribution == L"Windows Server") ;
	DRIVERCRATE_EXPECT( context, selectNvidiaWinof2Os( true, 26'100U, selection)) ;
	DRIVERCRATE_EXPECT( context, selectNvidiaWinof2Os( false, 19'044U, selection)) ;
	DRIVERCRATE_EXPECT( context, selection.distribution == L"Windows Client 10") ;
	DRIVERCRATE_EXPECT( context, selectNvidiaWinof2Os( false, 22'631U, selection)) ;
	DRIVERCRATE_EXPECT( context, selection.distribution == L"Windows Client 11") ;
	DRIVERCRATE_EXPECT( context, !selectNvidiaWinof2Os( false, 19'045U, selection)) ;
	DRIVERCRATE_EXPECT( context, !selectNvidiaWinof2Os( true, 20'349U, selection)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 委譲重複、latest不整合、選択肢重複、別host、別版、複数fileを拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testRejectedMetadata( TestContext &context)
{
	std::wstring duplicateLanding( LANDING_PAGE) ;	// Iframe委譲を二件持つpage。
	duplicateLanding.append(
		L"https://downloaders.azurewebsites.net/downloaders/winof2_downloader/downloader4.html") ;
	DRIVERCRATE_EXPECT( context, !parseNvidiaWinof2LandingPage( duplicateLanding)) ;

	std::wstring version ;	// 各拒否後に空であるべき版。
	DRIVERCRATE_EXPECT(
		context,
		!parseNvidiaWinof2Versions(
			LR"({"latest":"26.9.54321","versions":["26.9.54321"],"ga":["26.8.10000"]})", version)) ;
	DRIVERCRATE_EXPECT( context, version.empty()) ;

	std::vector<std::wstring> values ;	// 重複または型違いで空に戻る選択肢。
	DRIVERCRATE_EXPECT( context, !parseNvidiaWinof2StringList( LR"(["x64","x64"])", values)) ;
	DRIVERCRATE_EXPECT( context, values.empty()) ;
	DRIVERCRATE_EXPECT( context, !parseNvidiaWinof2StringList( LR"(["x64",1])", values)) ;

	NvidiaWinof2Release release ;										// 拒否時に初期値へ戻る配布情報。
	std::wstring		wrongHost( DOWNLOAD_JSON) ;						// Payload hostだけを変更したmetadata。
	const std::size_t	host = wrongHost.find( L"www.mellanox.com") ;	// Host置換位置。
	DRIVERCRATE_EXPECT( context, host != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( host != std::wstring::npos) {
		wrongHost.replace( host, 16U, L"mirror.example.test") ;
		DRIVERCRATE_EXPECT( context, !parseNvidiaWinof2DownloadInfo( wrongHost, VERSION, release)) ;
	}

	DRIVERCRATE_EXPECT( context,
					   !parseNvidiaWinof2DownloadInfo( DOWNLOAD_JSON, L"26.9.54322", release)) ;
	std::wstring	  multipleFiles( DOWNLOAD_JSON) ;					// Files arrayへ二件目を挿入するmetadata。
	const std::size_t filesEnd = multipleFiles.find( L"}],\"docs\"") ;	// Files末尾位置。
	DRIVERCRATE_EXPECT( context, filesEnd != std::wstring::npos) ;
	// file一覧の終端を取得できた場合に別payloadを追加して複数file拒否を検証する。
	if( filesEnd != std::wstring::npos) {
		multipleFiles.insert( filesEnd + 1U, LR"(,{"file":"extra.exe","desc":"WinOF Driver"})") ;
		DRIVERCRATE_EXPECT( context,
						   !parseNvidiaWinof2DownloadInfo( multipleFiles, VERSION, release)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 二deviceが同じpackageを共有し、端末情報なしで五段階POSTすることを検証する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testDeviceProbeAndScan( TestContext &context)
{
	OfficialCatalogDevice device = winof2Device( L"net-a") ;	// 正常なlocal probe入力。
	DRIVERCRATE_EXPECT( context, isNvidiaWinof2Device( device)) ;
	device.model = L"ConnectX-4 Ethernet Adapter" ;
	DRIVERCRATE_EXPECT( context, !isNvidiaWinof2Device( device)) ;
	device			   = winof2Device( L"net-a") ;
	device.driverClass = L"System" ;
	DRIVERCRATE_EXPECT( context, !isNvidiaWinof2Device( device)) ;
	device				   = winof2Device( L"net-a") ;
	device.manufacturer	   = L"Generic" ;
	device.currentProvider = L"Generic" ;
	DRIVERCRATE_EXPECT( context, !isNvidiaWinof2Device( device)) ;

	const std::array					devices{winof2Device( L"net-a"),
								// 二台の合成inventory。
								winof2Device( L"net-b")} ;
	std::size_t							landingReads{} ;	// 製品page readerの呼出し回数。
	std::vector<std::string>			forms ;				// Metadata readerが受けた機密情報なしのbody。
	std::vector<ProviderProgress>		progressValues ;	// 確定済み進捗通知の記録。
	const NvidiaWinof2LandingPageReader landingReader = [&landingReads]( const ScanSessionId session,
																		std::wstring	   &html) {
		++landingReads ;
		html.assign( LANDING_PAGE) ;
		return session == SESSION ? NativeError{0} : static_cast<NativeError>( E_INVALIDARG) ;
	} ; // Networkを使用しない合成landing取得境界。
	const NvidiaWinof2MetadataReader metadataReader =
		[&forms]( const ScanSessionId session, const std::string_view formBody, std::wstring &json) {
			forms.emplace_back( formBody) ;
			json = metadataResponse( formBody) ;
			return session == SESSION && !json.empty() ? NativeError{0}
													   : static_cast<NativeError>( E_INVALIDARG) ;
		} ; // Form完全一致に対応する合成JSON取得境界。
	const ProviderProgressCallback progress = [&progressValues]( const ProviderProgress &value) {
		progressValues.push_back( value) ;
	} ; // 確定値を順序付きで保持する通知先。

	// 架空Server deviceとfake readerを組み合わせたread-only scan結果。
	const ScanResult result = scanNvidiaWinof2Catalog( SESSION, devices, true, 26'100U,
													  landingReader, metadataReader, progress) ;
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, result.coverage.eligibleDeviceCount == 2U) ;
	DRIVERCRATE_EXPECT( context, result.coverage.assessedDeviceCount == 2U) ;
	DRIVERCRATE_EXPECT( context, landingReads == 1U) ;
	DRIVERCRATE_EXPECT( context, forms.size() == 5U) ;
	DRIVERCRATE_EXPECT( context, !progressValues.empty()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.candidates.size() == 2U) {
		const UpdateCandidate &first  = result.candidates[0] ;	// 一台目の表示候補。
		const UpdateCandidate &second = result.candidates[1] ;	// 二台目の表示候補。
		DRIVERCRATE_EXPECT( context, first.providerId == NVIDIA_WINOF2_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, first.packageIdentity == second.packageIdentity) ;
		DRIVERCRATE_EXPECT( context, first.deviceIdentity != second.deviceIdentity) ;
		DRIVERCRATE_EXPECT( context, first.version.empty()) ;
		DRIVERCRATE_EXPECT( context, !first.installable && !first.recommended) ;
		DRIVERCRATE_EXPECT( context, first.action == DriverAction::NONE) ;
		DRIVERCRATE_EXPECT( context, first.title.find( L"26.9.54321") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, first.title.find( L"401 MB") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   first.sourceLocation.find( L"payload未取得") != std::wstring::npos) ;
	}

	// POST bodyがlocal snapshotの表示値またはopaque identityを含まないことを確認する。
	for( const std::string &form : forms) {
		DRIVERCRATE_EXPECT( context, form.find( "net-a") == std::string::npos) ;
		DRIVERCRATE_EXPECT( context, form.find( "ConnectX") == std::string::npos) ;
		DRIVERCRATE_EXPECT( context, form.find( "Mellanox") == std::string::npos) ;
	}

	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !progressValues.empty()) {
		DRIVERCRATE_EXPECT( context, progressValues.back().percentComplete == 100U) ;
		DRIVERCRATE_EXPECT( context, progressValues.back().completedItems == 2U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 対象外無通信、重複identity、途中schema変更、install要求を拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testFailClosedContracts( TestContext &context)
{
	std::size_t							reads{} ;	// 対象外では0のままであるreader呼出し回数。
	const NvidiaWinof2LandingPageReader landingReader = [&reads]( const ScanSessionId,
																 std::wstring &html) {
		++reads ;
		html.assign( LANDING_PAGE) ;
		return NativeError{0} ;
	} ; // 呼出し有無を観測する合成landing reader。
	const NvidiaWinof2MetadataReader metadataReader =
		[&reads]( const ScanSessionId, const std::string_view formBody, std::wstring &json) {
			++reads ;
			json = metadataResponse( formBody) ;
			return NativeError{0} ;
		} ; // 呼出し有無を観測する合成metadata reader。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 通知は破棄する。

	OfficialCatalogDevice		   unrelated = winof2Device( L"other") ;	// 系列外のNet device。
	unrelated.model							 = L"Unrelated Ethernet Adapter" ;
	const std::array unrelatedDevices{unrelated} ;	// 通信対象外inventory。
	// 対象外deviceだけを渡した場合のscan結果。
	const ScanResult noTarget = scanNvidiaWinof2Catalog( SESSION, unrelatedDevices, true, 26'100U,
														landingReader, metadataReader, progress) ;
	DRIVERCRATE_EXPECT( context, noTarget.succeeded) ;
	DRIVERCRATE_EXPECT( context, noTarget.state == ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT( context, reads == 0U) ;

	const std::array duplicateDevices{winof2Device( L"same"),
									  // Identity重複inventory。
									  winof2Device( L"same")} ;
	// 重複device入力を渡した場合のscan結果。
	const ScanResult duplicate = scanNvidiaWinof2Catalog( SESSION, duplicateDevices, true, 26'100U,
														 landingReader, metadataReader, progress) ;
	DRIVERCRATE_EXPECT( context, !duplicate.succeeded) ;
	DRIVERCRATE_EXPECT( context, duplicate.error == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, reads == 0U) ;

	const std::array				 devices{winof2Device( L"net-a")} ;	// 一台の正常な対象inventory。
	const NvidiaWinof2MetadataReader rejectedReader =
		[]( const ScanSessionId, const std::string_view formBody, std::wstring &json) {
			json = metadataResponse( formBody) ;
			// architecture応答だけをARM64へ差し替え、途中の適用条件変更を検証する。
			if( formBody.starts_with( "action=get_arches")) {
				json = LR"("arm64")" ;
			}

			return NativeError{0} ;
		} ; // Architecture段階だけx64を欠落させるreader。
	// Metadata readerが拒否を返す場合のscan結果。
	const ScanResult rejected = scanNvidiaWinof2Catalog( SESSION, devices, true, 26'100U,
														landingReader, rejectedReader, progress) ;
	DRIVERCRATE_EXPECT( context, !rejected.succeeded) ;
	DRIVERCRATE_EXPECT( context, rejected.state == ProviderScanState::METADATA_REJECTED) ;

	NvidiaWinof2UpdateProvider		  provider ;						// Capability外installを直接確認するProvider。
	const std::array<std::wstring, 1> identities{L"opaque-candidate"} ;	// 架空candidate ID。
	// 未対応の導入要求が実driver操作へ進まないことを確認する結果。
	const InstallResult				  install = provider.install( SESSION, identities, 0U, progress) ;
	DRIVERCRATE_EXPECT( context, !install.succeeded) ;
	DRIVERCRATE_EXPECT( context, install.downloadError == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, install.installError == static_cast<NativeError>( E_NOTIMPL)) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @copydoc drivercrate::test::runNvidiaWinof2CatalogParserTests
 */
//------------------------------------------------------------------------------
void runNvidiaWinof2CatalogParserTests( TestContext &context)
{
	testValidParsersAndOsSelection( context) ;
	testRejectedMetadata( context) ;
	testDeviceProbeAndScan( context) ;
	testFailClosedContracts( context) ;
}

} // namespace drivercrate::test
