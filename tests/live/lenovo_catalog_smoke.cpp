//------------------------------------------------------------------------------
/**
 * @file lenovo_catalog_smoke.cpp
 * @brief Lenovo公式catalog読み取り専用試験。
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
 * @note Lenovoが公開する試験用model catalogからdriver descriptorを取得し、hash、XML署名、certificate chainだけを検証します。
 *       Payloadは取得せず、端末情報も送信または出力しません。
 */
//------------------------------------------------------------------------------

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/lenovo_catalog_parser.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_http_client.h"
#include "platform/windows_error.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view CATALOG_URL =
	L"https://download.lenovo.com/catalog/21NT_Win11.xml" ;						// 公開sample model catalog。
constexpr std::array<std::wstring_view, 1> ACCEPTED_PUBLISHERS{L"Lenovo"} ;		// Publisher。
constexpr std::uint64_t MAXIMUM_CATALOG_BYTES	 = 8ULL * 1024ULL * 1024ULL ;	// Catalog上限。
constexpr std::uint64_t MAXIMUM_DESCRIPTOR_BYTES = 2ULL * 1024ULL * 1024ULL ;	// XML上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 一つのdescriptorを保護fileへ取得する。
 *
 * Metadata cache経路を通し、payloadは取得しない。
 *
 * @param[in,out] client 取得根拠を記録する公式HTTP client。
 * @param[in] url Model catalogから検証済みの公式URL。
 * @param[in,out] workspace CREATE_NEWする保護一時領域。
 * @param[in] fileName 外部値を含まない固定basename。
 * @return Downloadとhandle close成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] drivercrate::NativeError downloadDescriptor(
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
		url, drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, MAXIMUM_DESCRIPTOR_BYTES, file,
		[]( const std::uint64_t, const std::uint64_t) {}) ;	// Descriptor取得結果。
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
 * @brief Lenovo公式descriptorのhashとXML署名を読み取り専用で検証する。
 *
 * 公式sample modelだけを送信し、端末inventoryとpayloadを扱わない。WinHTTP自動Proxy/PAC経路の接続確認も兼ねる。
 * @return 一つ以上のdriver descriptorを完全検証できた場合は0。
 */
//------------------------------------------------------------------------------
int wmain()
{
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// MSXML/CryptXML用COM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wcerr << L"COM initialization failed.\n" ;
		return 1 ;
	}

	drivercrate::OfficialHttpClient client ;		// 自動Proxyを使用する公式HTTP client。
	std::wstring					catalogXml ;	// UTF-8から変換したmodel catalog。
	drivercrate::NativeError		error =
		// 取得根拠session開始結果。
		client.beginSourceSession( 1U, drivercrate::LENOVO_PROVIDER_ID) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = client.getUtf8TextForSource( CATALOG_URL,
											drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
											MAXIMUM_CATALOG_BYTES, catalogXml) ;
	}

	// model catalogの通信失敗を保持し、未取得内容からdescriptorを推測しない。
	if( error != 0) {
		std::wcerr << L"Lenovo catalog connection failed: " << drivercrate::formatNativeError( error)
				   << L'\n' ;
		return 1 ;
	}

	std::vector<drivercrate::LenovoCatalogReference> references ;	// 検証済み参照群。
	error = drivercrate::parseLenovoModelCatalog( catalogXml, references) ;
	// modelの参照を正常に解析できないcatalogでは、後続のdescriptor試験を開始しない。
	if( error != 0 || references.empty()) {
		std::wcerr << L"Lenovo model catalog validation failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	drivercrate::OfficialDownloadWorkspace workspace ;	// Descriptor保存用保護一時領域。
	error = workspace.initialize( L"lenovo-live", 1) ;
	// 保護領域を作れなければ、取得物の保存先を緩めて試験を続けない。
	if( error != 0) {
		std::wcerr << L"Protected workspace creation failed.\n" ;
		return 1 ;
	}

	std::size_t verifiedDriverCount{} ;	// 完全検証できたdriver descriptor数。
	// 公開catalog順に調べ、最初のdriver descriptorを完全検証した時点で終了する。
	for( std::size_t index = 0; index < references.size() && verifiedDriverCount == 0; ++index) {
		const drivercrate::LenovoCatalogReference &reference = references[index] ;	// 現在参照。
		const std::wstring						   fileName =
			L"descriptor-" + std::to_wstring( index) + L".xml" ;	// 固定規則basename。
		error = downloadDescriptor( client, reference.descriptorUrl, workspace, fileName) ;
		// descriptor取得の失敗を明示し、空の内容でhash検証を代替しない。
		if( error != 0) {
			std::wcerr << L"Lenovo descriptor connection failed: "
					   << drivercrate::formatNativeError( error) << L'\n' ;
			return 1 ;
		}

		const std::wstring path = workspace.path( fileName) ;	// 検証対象絶対path。
		error					= drivercrate::verifyOfficialFileMetadata(
			  path, {.expectedSize = std::nullopt, .expectedSha256 = reference.sha256}) ;
		// 公開hashと一致しないdescriptorを、XMLとして受理する前に拒否する。
		if( error != 0) {
			std::wcerr << L"Lenovo descriptor hash validation failed.\n" ;
			return 1 ;
		}

		std::wstring descriptorXml ;	// 厳格UTF-8変換済みdescriptor。
		error = drivercrate::readOfficialUtf8Xml( path, MAXIMUM_DESCRIPTOR_BYTES, descriptorXml) ;
		// 宣言した文字コードとして読めないdescriptorを、暗黙変換して受理しない。
		if( error != 0) {
			std::wcerr << L"Lenovo descriptor encoding validation failed.\n" ;
			return 1 ;
		}

		std::optional<drivercrate::LenovoDriverRelease> release ;	// Driver metadata解析結果。
		error = drivercrate::parseLenovoPackageDescriptor( descriptorXml, reference.descriptorUrl,
														  release) ;
		// schemaを満たさないdescriptorの値から、候補や署名の検証条件を作らない。
		if( error != 0) {
			std::wcerr << L"Lenovo descriptor schema validation failed.\n" ;
			return 1 ;
		}

		// driver releaseに該当しないdescriptorは、driver検証件数へ含めない。
		if( !release.has_value()) {
			continue ;
		}

		error = drivercrate::verifyXmlSignaturePublisher(
			path, MAXIMUM_DESCRIPTOR_BYTES, release->signingFiletime, ACCEPTED_PUBLISHERS) ;
		// XML署名を検証できないdriver descriptorを、検証済みの件数へ数えない。
		if( error != 0) {
			std::wcerr << L"Lenovo XML signature validation failed: "
					   << drivercrate::formatNativeError( error) << L'\n' ;
			return 1 ;
		}

		++verifiedDriverCount ;
	}

	// 検証できたdriverが一件もない場合は、catalogへの到達だけを合格にしない。
	if( verifiedDriverCount == 0) {
		std::wcerr << L"Lenovo catalog contained no verifiable driver descriptor.\n" ;
		return 1 ;
	}

	// metadataの公式取得根拠を同じsessionへ照合し、取得元検証の接続も確認する。
	if( !client.hasSourceEvidence( 1U, drivercrate::LENOVO_PROVIDER_ID,
								 drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) {
		std::wcerr << L"Lenovo official source evidence validation failed.\n" ;
		return 1 ;
	}

	std::wcout << L"Lenovo official catalog connection, hash, and XML signature succeeded. "
			   << L"Descriptors: " << references.size() << L", verified drivers: "
			   << verifiedDriverCount << L'\n' ;
	return 0 ;
}
