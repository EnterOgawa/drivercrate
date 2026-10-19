//------------------------------------------------------------------------------
/**
 * @file dell_server_catalog_source.cpp
 * @brief Dell PowerEdge署名済みcatalog取得実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元policy registry接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得根拠記録追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note `downloads.dell.com`以外へ接続せず、Catalogと署名を別々の固定名でCREATE_NEWします。署名検証失敗時は圧縮dataを解析しません。
 */
//------------------------------------------------------------------------------

#include "platform/dell_server_catalog_source.h"

#include "core/official_source_policy.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_download_workspace.h"
#include "platform/official_gzip.h"
#include "platform/openpgp_signature_verifier.h"

#include <Windows.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view CATALOG_URL =
	L"https://downloads.dell.com/catalog/Catalog.gz" ;	// Enterprise catalog URL。
constexpr std::wstring_view SIGNATURE_URL =
	L"https://downloads.dell.com/catalog/Catalog.gz.sha512.sign" ;						// Detached署名URL。
constexpr std::uint64_t		MAXIMUM_CATALOG_BYTES	   = 8ULL * 1024ULL * 1024ULL ;		// GZip上限。
constexpr std::uint64_t		MAXIMUM_SIGNATURE_BYTES	   = 32ULL * 1024ULL ;				// ASCII Armor上限。
constexpr std::uint64_t		MAXIMUM_EXPANDED_XML_BYTES = 64ULL * 1024ULL * 1024ULL ;	// XML上限。
constexpr std::wstring_view DELL_SIGNING_FINGERPRINT =
	L"42550ABD1E80D7C1BC0BAD851285491434D8786F" ;	// Dell Release Engineering鍵。
// 固定fingerprintと照合してcatalog署名を検証する、組み込み公開鍵packetのBase64表現。
constexpr std::string_view DELL_SIGNING_KEY_BODY_BASE64 =
	"BE9RLYYBEADEAmJvn2y182B6ZUr+u9I29f2ue87p6HQreVvPbTjiXG4z2/k0l/Ov0DLImXFckaeVSSrqjFnEGUd3"
	"DiRr9pPb1FqxOseHRZv5IgjCTKZyj9Jvu6bxU9WL8u4+GIsFzrgS5G44g1g5eD4Li4sV46pNBTp8d7QEF4e2zg9x"
	"k2mcZKaT+STlO0Q2WKI7qN8PAoGd1SfyW4XDsyfaMrJKmIJTgUxe9sHGj+UmTf86ZIKYh4pRzUQCWBOxMd4sPgqV"
	"fwwykg/y2CQjrorZcnUNdWucZkeXR0+UCR6WbDtmGfvN5H3htTfmNl84Rwzvk4NT/By4bHy0nnX+WojeKuygCZrx"
	"fpSqJWOKhQeH+YHKm1oVqg95jvClvBYTtDNkpJDbt4eBAaVhuEPwjCBsfff/bxGCrzocoKlh0+hgWDrr2S9ePdrw"
	"v+rv2cgYfUcXEHltD5Ryz3u5LpiC5zDzNYGFfV092xbpG/B9YJz5GGj8VKMslRhYpUjAIpBDlYhOJ+0uVAAKPeeZ"
	"GBuFx0A1y/9iutERinPx8B9jYjO9iETzhKSHCWEov/ypX6k17T8IHfVj4TSwL6xTIYFGtYXIzhInBXa/aUPIpMjw"
	"t5OpMVaJpcgHxLam6xPNFYulIjKAD07FJ3U83G2fn9W0lmr11hVsFIMvo9JpQq9aryr9CRoAvRv7OwARAQAB" ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Dell catalog resourceを保護workspaceへ取得する。
 *
 * Catalog cacheを使用しても、後段の署名検証を毎回実行する。
 *
 * @param[in] client 公式HTTP client。
 * @param[in] url 固定Dell HTTPS URL。
 * @param[in] resourceId Catalogまたはdetached signature用途ID。
 * @param[in] maximumBytes 応答body上限。
 * @param[in] workspace 作成済み保護workspace。
 * @param[in] name Provider固定basename。
 * @return Downloadとhandle close成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError downloadCatalogFile( OfficialHttpClient		&client,
											  const std::wstring_view	 url,
											  const std::wstring_view	 resourceId,
											  const std::uint64_t		 maximumBytes,
											  OfficialDownloadWorkspace &workspace,
											  const std::wstring_view	 name)
{
	HANDLE		file{INVALID_HANDLE_VALUE} ;				// CloseHandleで解放するdownload先handle。
	NativeError error = workspace.createFile( name, file) ;	// CREATE_NEW結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	error = client.downloadCatalogForSource(
		url, resourceId, maximumBytes, file,
		[]( const std::uint64_t, const std::uint64_t) {}) ;	// Download結果。
	// 先行取得の診断を上書きせず、closeだけが失敗した場合に保持する。
	if( CloseHandle( file) == FALSE && error == 0) {
		error = static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	return error ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_server_catalog_source.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
DellServerCatalogLoadResult loadDellServerCatalog( OfficialHttpClient			 &client,
												  const ScanSessionId			  scanSessionId,
												  const ProviderProgressCallback &progressCallback)
{
	DellServerCatalogLoadResult result ;	// Catalog取得・検証・展開の結果。
	// 未発行sessionでは公式catalogの取得を開始しない。
	if( scanSessionId == 0) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	OfficialDownloadWorkspace workspace ;	// Scope終了時に既知fileだけを削除する領域。
	result.error = workspace.initialize( L"dell-server", scanSessionId) ;
	// source sessionの準備失敗を保持し、catalog取得へ進まない。
	if( result.error != 0) {
		return result ;
	}

	result.error = downloadCatalogFile( client, CATALOG_URL, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
									   MAXIMUM_CATALOG_BYTES, workspace, L"catalog.gz") ;
	// 保護workspaceの準備失敗を保持し、取得fileを作らない。
	if( result.error != 0) {
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 20}) ;
	result.error =
		downloadCatalogFile( client, SIGNATURE_URL, OFFICIAL_DETACHED_SIGNATURE_RESOURCE_ID,
							MAXIMUM_SIGNATURE_BYTES, workspace, L"catalog.sign") ;
	// catalogと署名の取得に失敗した場合は検証を続けない。
	if( result.error != 0) {
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 35}) ;
	const OpenPgpRsaPublicKey publicKey{.packetBodyBase64 = DELL_SIGNING_KEY_BODY_BASE64,
										.expectedFingerprint =
											DELL_SIGNING_FINGERPRINT} ;	// 固定Dell署名鍵。
	result.error = verifyOpenpgpDetachedFile( workspace.path( L"catalog.gz"), MAXIMUM_CATALOG_BYTES,
											 workspace.path( L"catalog.sign"),
											 MAXIMUM_SIGNATURE_BYTES, publicKey) ;
	// 署名検証の失敗をmetadata拒否として返し、未検証catalogを展開しない。
	if( result.error != 0) {
		result.metadataRejected = true ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 50}) ;

	HANDLE xmlFile{INVALID_HANDLE_VALUE} ;	// CloseHandleで解放する展開先file handle。
	result.error = workspace.createFile( L"catalog.xml", xmlFile) ;
	// XML展開先の準備失敗を保持し、不正handleへ出力しない。
	if( result.error != 0) {
		return result ;
	}

	result.error = decompressOfficialGzipFile( workspace.path( L"catalog.gz"), MAXIMUM_CATALOG_BYTES,
											  MAXIMUM_EXPANDED_XML_BYTES, xmlFile) ;
	// 展開の先行失敗を上書きせず、XML fileのclose失敗を保存する。
	if( CloseHandle( xmlFile) == FALSE && result.error == 0) {
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	// 展開またはfile確定に失敗したcatalogをmetadata拒否として返す。
	if( result.error != 0) {
		result.metadataRejected = true ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 65}) ;
	result.error = readOfficialUtf16Xml( workspace.path( L"catalog.xml"), MAXIMUM_EXPANDED_XML_BYTES,
										result.xml) ;
	// XML読込みに失敗した場合はmetadata拒否を結果へ残す。
	if( result.error != 0) {
		result.metadataRejected = true ;
	}

	return result ;
}

} // namespace drivercrate
