//------------------------------------------------------------------------------
/**
 * @file vaio_catalog_smoke.cpp
 * @brief VAIO Global公式catalog読み取り専用試験。
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
 * @note 固定公式JSONと小容量の公開driver sampleを取得し、schema、size、hash、VAIO Authenticode publisherを検証します。実行または端末
 *       照合しません。
 */
//------------------------------------------------------------------------------

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_http_client.h"
#include "platform/vaio_catalog_parser.h"
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

constexpr std::array<std::wstring_view, 1> PUBLISHERS{L"VAIO Corporation"} ;	// Publisher。
constexpr std::wstring_view				   MODELS_URL =
	L"https://support.vaio.com/products/Models.json" ;	// Model JSON。
constexpr std::wstring_view PREINSTALLED_URL =
	L"https://support.vaio.com/global/sustaining/preinstDriversGlobal.json" ;	// Driver表。
constexpr std::wstring_view UPDATES_URL =
	L"https://support.vaio.com/global/sustaining/UpdateListGlobal.json" ;	// Update JSON。
constexpr std::wstring_view SAMPLE_URL =
	L"https://dlcdnglobal.support.vaio.com/supportfiles-global/update/SP000877.exe" ;	// Sample。
constexpr std::wstring_view SAMPLE_SHA256 =
	L"4273a9ba8045457177cf164d98c534639681cb1062e8531b9e9c2c9bac1f9f3e" ;	// Hash。
constexpr std::uint64_t				   SAMPLE_SIZE = 5'964'080 ;			// Sample payload byte数。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief VAIO sample payloadを保護workspaceへ取得する。
 *
 * 固定sampleを取得するだけでprocessとして実行しない。
 *
 * @param[in,out] client 取得根拠を記録する公式HTTP client。
 * @param[in,out] workspace CREATE_NEWする保護一時領域。
 * @return Downloadとhandle close成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] drivercrate::NativeError downloadSample(
	drivercrate::OfficialHttpClient &client, drivercrate::OfficialDownloadWorkspace &workspace)
{
	HANDLE						   file{INVALID_HANDLE_VALUE} ;	// CloseHandleで解放する保存先file。
	const drivercrate::NativeError createError = workspace.createFile( L"sample.exe", file) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( createError != 0) {
		return createError ;
	}

	const drivercrate::NativeError downloadError = client.downloadForSource(
		SAMPLE_URL, drivercrate::OFFICIAL_PAYLOAD_RESOURCE_ID, SAMPLE_SIZE, file,
		[]( const std::uint64_t, const std::uint64_t) {}) ;	// Payload取得結果。
	const BOOL closeResult = CloseHandle( file) ;			// File close結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( downloadError != 0) {
		return downloadError ;
	}

	return closeResult == FALSE
			   ? static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( GetLastError()))
			   : 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief VAIO公式JSONとdriver sampleを読み取り専用で検証する。
 *
 * 固定requestだけを送り、端末inventoryとserialを送信せず、installerを実行しない。
 * @return 三JSONとsampleの全検証成功時は0、それ以外は1。
 */
//------------------------------------------------------------------------------
int wmain()
{
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// JSON用COM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wcerr << L"COM initialization failed.\n" ;
		return 1 ;
	}

	drivercrate::OfficialHttpClient client ;			// 自動Proxyを使用する公式HTTP client。
	std::wstring					modelsJson ;		// UTF-16変換済みmodel JSON。
	std::wstring					preinstalledJson ;	// UTF-16変換済みdriver表JSON。
	std::wstring					updatesJson ;		// UTF-16変換済みupdate JSON。
	drivercrate::NativeError		error =
		// 取得根拠session開始結果。
		client.beginSourceSession( 1U, drivercrate::VAIO_PROVIDER_ID) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = client.getUtf8TextForSource( MODELS_URL,
											drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
											512ULL * 1024ULL, modelsJson) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = client.getUtf8TextForSource( PREINSTALLED_URL,
											drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
											2ULL * 1024ULL * 1024ULL, preinstalledJson) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = client.getUtf8TextForSource( UPDATES_URL,
											drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
											1ULL * 1024ULL * 1024ULL, updatesJson) ;
	}

	// 公式catalogの通信が成立しなければ、未取得の内容でschema試験を続けない。
	if( error != 0) {
		std::wcerr << L"VAIO catalog connection failed: " << drivercrate::formatNativeError( error)
				   << L'\n' ;
		return 1 ;
	}

	// metadataとsample本体の両方について、同じsessionの公式取得根拠を確認する。
	if( !client.hasSourceEvidence( 1U, drivercrate::VAIO_PROVIDER_ID,
								 drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ||
	   !client.hasSourceEvidence( 1U, drivercrate::VAIO_PROVIDER_ID,
								 drivercrate::OFFICIAL_PAYLOAD_RESOURCE_ID)) {
		std::wcerr << L"VAIO official source evidence validation failed.\n" ;
		return 1 ;
	}

	std::vector<drivercrate::VaioModel>				 models ;		// Global model集合。
	std::vector<drivercrate::VaioPreinstalledDriver> preinstalled ;	// Driver表項目群。
	std::vector<drivercrate::VaioDriverRelease>		 releases ;		// Driver update群。
	error = drivercrate::parseVaioModelCatalog( modelsJson, models) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = drivercrate::parseVaioPreinstalledCatalog( preinstalledJson, preinstalled) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = drivercrate::parseVaioUpdateCatalog( updatesJson, releases) ;
	}

	// model・初期搭載情報・releaseがそろわないcatalogを、代表経路の合格としない。
	if( error != 0 || models.empty() || preinstalled.empty() || releases.empty()) {
		std::wcerr << L"VAIO catalog schema validation failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	drivercrate::OfficialDownloadWorkspace workspace ;	// Sample保存用保護一時領域。
	error = workspace.initialize( L"vaio-live", 1) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = downloadSample( client, workspace) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = drivercrate::verifyOfficialFile(
			workspace.path( L"sample.exe"),
			{.expectedSize = SAMPLE_SIZE, .expectedSha256 = SAMPLE_SHA256}, PUBLISHERS) ;
	}

	// sampleのsize・hash・署名を検証できない場合は、download成功だけで合格にしない。
	if( error != 0) {
		std::wcerr << L"VAIO sample size, hash, or signature validation failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	std::wcout << L"VAIO official JSON schemas and signed sample succeeded. Models: "
			   << models.size() << L", pre-installed rows: " << preinstalled.size()
			   << L", driver updates: " << releases.size() << L'\n' ;
	return 0 ;
}
