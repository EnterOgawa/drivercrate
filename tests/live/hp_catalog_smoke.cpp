//------------------------------------------------------------------------------
/**
 * @file hp_catalog_smoke.cpp
 * @brief HP公式reference catalog読み取り専用試験。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得根拠session接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Provider ID直接include追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note HP公開sample Platform IDのplatform listとreference CABを取得し、Authenticode、CAB境界、schemaだけを検証します。
 *       Payloadは取得せず、端末情報も送信または出力しません。
 */
//------------------------------------------------------------------------------

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/hp_catalog_parser.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_http_client.h"
#include "platform/windows_error.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view PLATFORM_URL =
	L"https://hpia.hpcloud.hp.com/ref/platformList.cab" ;	// 公式platform list。
constexpr std::wstring_view REFERENCE_URL =
	L"https://hpia.hpcloud.hp.com/ref/8a05/8a05_64_11.0.22h2.cab" ;						// 公開sample。
constexpr std::array<std::wstring_view, 1> ACCEPTED_PUBLISHERS{L"HP Inc."} ;			// Publisher。
constexpr std::uint64_t				   MAXIMUM_CAB_BYTES = 32ULL * 1024ULL * 1024ULL ;	// CAB上限。
constexpr std::uint64_t				   MAXIMUM_XML_BYTES = 64ULL * 1024ULL * 1024ULL ;	// XML上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief HP署名付きCABを保護fileへ取得する。
 *
 * Metadata cache経路を通し、SoftPaq payloadは取得しない。
 *
 * @param[in,out] client 取得根拠を記録する公式HTTP client。
 * @param[in] url 固定HP公式reference URL。
 * @param[in,out] workspace CREATE_NEWする保護一時領域。
 * @param[in] fileName 外部値を含まない固定basename。
 * @return Downloadとhandle close成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] drivercrate::NativeError downloadCab(
	drivercrate::OfficialHttpClient &client, const std::wstring_view url,
	drivercrate::OfficialDownloadWorkspace &workspace, const std::wstring_view fileName)
{
	HANDLE						   file{INVALID_HANDLE_VALUE} ;								// CloseHandleで解放する保存先file。
	const drivercrate::NativeError createError = workspace.createFile( fileName, file) ;	// 結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( createError != 0) {
		return createError ;
	}

	const drivercrate::NativeError downloadError = client.downloadCatalogForSource(
		url, drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, MAXIMUM_CAB_BYTES, file,
		[]( const std::uint64_t, const std::uint64_t) {}) ;	// CAB取得結果。
	const BOOL closeResult = CloseHandle( file) ;			// File close結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( downloadError != 0) {
		return downloadError ;
	}

	return closeResult == FALSE
			   ? static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( GetLastError()))
			   : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief HP署名付きCABを検証しUTF-8 XMLとして読み取る。
 *
 * HP publisher確認後だけ単一・平坦・有限XMLを展開する。
 *
 * @param[in] cabPath Download済みCAB絶対path。
 * @param[in] xmlPath 保護workspace内の未作成XML path。
 * @param[out] xml 成功時のUTF-16 XML。
 * @return 署名、展開、encodingの全検証成功時は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] drivercrate::NativeError readSignedCabXml( const std::wstring_view cabPath,
														const std::wstring_view xmlPath,
														std::wstring		   &xml)
{
	drivercrate::NativeError error =
		// 署名結果。
		drivercrate::verifyAuthenticodePublisher( cabPath, ACCEPTED_PUBLISHERS) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = drivercrate::extractOfficialCatalogXml( cabPath, xmlPath, MAXIMUM_XML_BYTES) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = drivercrate::readOfficialUtf8Xml( xmlPath, MAXIMUM_XML_BYTES, xml) ;
	}

	return error ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief HP公式reference CABを読み取り専用で検証する。
 *
 * 固定sample Platformだけを要求し、端末inventoryとpayloadを扱わない。WinHTTP自動Proxy/PAC経路の接続確認も兼ねる。
 * @return Platformと一つ以上のdriver SoftPaqを検証できた場合は0。
 */
//------------------------------------------------------------------------------
int wmain()
{
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// MSXML用COM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wcerr << L"COM initialization failed.\n" ;
		return 1 ;
	}

	drivercrate::OfficialHttpClient		   client ;		// 自動Proxyを使用する公式HTTP client。
	drivercrate::OfficialDownloadWorkspace workspace ;	// CAB保存用保護一時領域。
	drivercrate::NativeError			   error =
		// 取得根拠session開始結果。
		client.beginSourceSession( 1U, drivercrate::HP_PROVIDER_ID) ;
	// 公式取得元sessionを作れなければ、取得根拠なしで通信検証を始めない。
	if( error != 0) {
		std::wcerr << L"Official source session creation failed.\n" ;
		return 1 ;
	}

	// 作成結果。
	error = workspace.initialize( L"hp-live", 1) ;
	// 保護workspaceが作れない場合は、別の非保護領域へ展開先を切り替えない。
	if( error != 0) {
		std::wcerr << L"Protected workspace creation failed.\n" ;
		return 1 ;
	}

	error = downloadCab( client, PLATFORM_URL, workspace, L"platform.cab") ;
	// platform一覧の通信失敗を明示し、未取得の内容で後続検証を進めない。
	if( error != 0) {
		std::wcerr << L"HP platform connection failed: " << drivercrate::formatNativeError( error)
				   << L'\n' ;
		return 1 ;
	}

	std::wstring platformXml ;	// 検証済みplatform list XML。
	error = readSignedCabXml( workspace.path( L"platform.cab"), workspace.path( L"platform.xml"),
							 platformXml) ;
	// platform取得物の署名または形式の検証失敗を、catalogの正常受入れにしない。
	if( error != 0) {
		std::wcerr << L"HP platform signature or schema boundary failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	drivercrate::HpPlatformReference platform ;	// 公開sample platform照合結果。
	error = drivercrate::parseHpPlatformCatalog( platformXml, L"8A05", 22621, platform) ;
	// platformの解析を完了できなければ、参照catalogを推測して取得しない。
	if( error != 0) {
		std::wcerr << L"HP platform catalog validation failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	error = downloadCab( client, REFERENCE_URL, workspace, L"reference.cab") ;
	// 参照catalogの通信失敗を保持し、空応答を候補なしとして合格にしない。
	if( error != 0) {
		std::wcerr << L"HP reference connection failed: " << drivercrate::formatNativeError( error)
				   << L'\n' ;
		return 1 ;
	}

	std::wstring referenceXml ;	// 検証済みplatform reference XML。
	error = readSignedCabXml( workspace.path( L"reference.cab"), workspace.path( L"reference.xml"),
							 referenceXml) ;
	// 参照catalogの署名と形式を検証できなければ、そのmetadataを解析へ渡さない。
	if( error != 0) {
		std::wcerr << L"HP reference signature or schema boundary failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	std::vector<drivercrate::HpDriverRelease> releases ;	// DeviceId付きdriver SoftPaq群。
	error = drivercrate::parseHpReferenceCatalog( referenceXml, platform, releases) ;
	// 対象driver行を確認できない参照catalogは、代表経路のlive検証を合格にしない。
	if( error != 0 || releases.empty()) {
		std::wcerr << L"HP reference schema validation failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	// 公式metadataの取得根拠が同じsessionに残っていることを要求する。
	if( !client.hasSourceEvidence( 1U, drivercrate::HP_PROVIDER_ID,
								 drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) {
		std::wcerr << L"HP official source evidence validation failed.\n" ;
		return 1 ;
	}

	std::wcout << L"HP official platform/reference CAB signatures and schemas succeeded. "
			   << L"Driver SoftPaqs with DeviceId: " << releases.size() << L'\n' ;
	return 0 ;
}
