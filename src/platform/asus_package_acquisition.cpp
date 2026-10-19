//------------------------------------------------------------------------------
/**
 * @file asus_package_acquisition.cpp
 * @brief ASUS公式driver package検査用取得実装。
 * @version 01.00.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note ASUS公式CDN、公開SHA-256、有限sizeを再検証して共通取得境界へ渡します。本処理ではarchive内容、PnP適用性、rankまたは署名合格を決定しません。
 */
//------------------------------------------------------------------------------

#include "platform/asus_package_acquisition.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t		MAXIMUM_PLAN_ENTRIES = 64U ;			// 一scanで計画できるASUS archive数上限。
constexpr std::size_t		MAXIMUM_OPAQUE_ID_CHARACTERS = 512U ;	// 内部record ID文字数上限。
constexpr std::size_t		MAXIMUM_URL_CHARACTERS		 = 2'048U ;	// Payload URL文字数上限。
// 一つのASUS payloadを保護workspaceへ取得する際のbyte上限。
constexpr std::uint64_t		MAXIMUM_PAYLOAD_BYTES = 4ULL * 1024ULL * 1024ULL * 1024ULL ;
constexpr std::wstring_view PAYLOAD_URL_PREFIX =
	L"https://dlcdnets.asus.com/pub/ASUS/" ;	// 許可するASUS Global CDN path prefix。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII小文字hexのSHA-256か判定する。
 *
 * Parser契約の破損をnetwork処理前にfail-closedで拒否する。
 *
 * @param[in] value ASUS pageから正規化済みの公開hash。
 * @return 64桁のASCII小文字hexだけで構成される場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLowerSha256( const std::wstring_view value) noexcept
{
	// SHA-256の固定64桁を満たさない文字列を取得identityに使用しない。
	if( value.size() != 64U) {
		return false ;
	}

	// Hash全文字を確認し、Unicode類似文字と大文字を受理しない。
	return std::all_of( value.begin(), value.end(), []( const wchar_t character) {
		return (character >= L'0' && character <= L'9') || (character >= L'a' && character <= L'f') ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS payload URLとarchive形式を再検証する。
 *
 * Query、fragment、userinfo、path traversal、非ASCIIをworkspace名生成前に拒否する。
 *
 * @param[in] url Parserが生成したASUS CDN絶対URL。
 * @param[out] extension 成功時の「.zip」または「.cab」。
 * @return 固定origin／pathと許可archive形式を満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidPayloadUrl( const std::wstring_view url,
									 std::wstring_view		&extension) noexcept
{
	extension = {} ;
	// 固定URL起点からの逸脱、traversal、別解釈を生む区切りを拒否する。
	if( !url.starts_with( PAYLOAD_URL_PREFIX) || url.size() > MAXIMUM_URL_CHARACTERS ||
	   url.find_first_of( L"?#\\\0") != std::wstring_view::npos ||
	   url.find( L"//", PAYLOAD_URL_PREFIX.size()) != std::wstring_view::npos ||
	   url.find( L"/../") != std::wstring_view::npos ||
	   url.find( L"/./") != std::wstring_view::npos || url.ends_with( L"/..") ||
	   url.ends_with( L"/.")) {
		return false ;
	}

	// URL全体をASCIIに限定し、別表現によるauthorityまたはpath解釈差を受理しない。
	for( const wchar_t character : url) {
		// 非ASCII文字、空白、userinfo、percent encodeをpayload URLに許可しない。
		if( character < 0x21 || character > 0x7e || character == L'@' || character == L'%') {
			return false ;
		}
	}

	const std::size_t slash = url.find_last_of( L'/') ;	// Payload file名の開始境界。
	const std::size_t dot	= url.find_last_of( L'.') ;	// Archive拡張子の開始境界。
	// basenameと三文字拡張子を分離できないURLを受理しない。
	if( slash == std::wstring_view::npos || dot == std::wstring_view::npos || dot <= slash ||
	   dot + 4U != url.size()) {
		return false ;
	}

	const std::wstring_view candidate = url.substr( dot) ;	// 大小文字を確認する拡張子。
	const wchar_t			first	  = candidate[1U] ;		// 拡張子先頭のASCII英字。
	const wchar_t			second	  = candidate[2U] ;		// 拡張子二文字目のASCII英字。
	const wchar_t			third	  = candidate[3U] ;		// 拡張子三文字目のASCII英字。
	const auto isAsciiLetter		  = []( const wchar_t value, const wchar_t lowercase) noexcept {
		 return value == lowercase || value == lowercase - (L'a' - L'A') ;
	} ; // 大小文字一致判定。
	// 拡張子がZIPに一致した場合だけZIPの固定形式として扱う。
	if( isAsciiLetter( first, L'z') && isAsciiLetter( second, L'i') && isAsciiLetter( third, L'p')) {
		extension = L".zip" ;
		return true ;
	}

	// 拡張子がCABに一致した場合だけCABの固定形式として扱う。
	if( isAsciiLetter( first, L'c') && isAsciiLetter( second, L'a') && isAsciiLetter( third, L'b')) {
		extension = L".cab" ;
		return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護workspace用のopaque file名を生成する。
 *
 * 外部file名を保護領域pathへ複写せず、有限連番だけを使う。
 *
 * @param[in] index 計画内の0始まりindex。
 * @param[in] extension 検証済みの「.zip」または「.cab」。
 * @return `payload-001`形式の安全なASCII相対file名。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring workspaceFileName( const std::size_t		 index,
											 const std::wstring_view extension)
{
	const std::size_t number = index + 1U ;		// 利用者表示に使わない1始まり連番。
	std::wstring	  name	 = L"payload-" ;	// Workspace内で固定するfile名prefix。
	// 一桁のordinalを三桁に揃え、安定したopaque file名を生成する。
	if( number < 10U) {
		name += L"00" ;
	}
	// 二桁のordinalも三桁に揃え、安定したopaque file名を生成する。
	else if( number < 100U) {
		name += L'0' ;
	}

	name += std::to_wstring( number) ;
	name += extension ;
	return name ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_package_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError makeAsusPackageAcquisitionPlan( const std::span<const AsusDriverPageEntry>	 entries,
										   std::vector<AsusPackageAcquisitionPlanEntry> &plan)
{
	plan.clear() ;
	// 空または固定件数上限を超える取得計画を作らない。
	if( entries.empty() || entries.size() > MAXIMUM_PLAN_ENTRIES) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::unordered_set<std::wstring> opaqueIds ;	// Record ID重複検出集合。
		std::unordered_set<std::wstring> urls ;			// Payload URL重複検出集合。
		opaqueIds.reserve( entries.size()) ;
		urls.reserve( entries.size()) ;
		plan.reserve( entries.size()) ;
		// Parser順を保ったまま全entryを検証し、一件の不整合でも全計画を拒否する。
		for( std::size_t index = 0U; index < entries.size(); ++index) {
			const AsusDriverPageEntry &entry = entries[index] ;	// 現在検証するmetadata。
			std::wstring_view		   extension ;				// 検証済みarchive拡張子。
			// ID・URL・hash・容量の不正と重複を検出したら部分計画を全て破棄する。
			if( entry.opaqueId.empty() || entry.opaqueId.size() > MAXIMUM_OPAQUE_ID_CHARACTERS ||
			   !isValidPayloadUrl( entry.downloadUrl, extension) || !isLowerSha256( entry.sha256) ||
			   entry.maximumDownloadBytes == 0U ||
			   entry.maximumDownloadBytes > MAXIMUM_PAYLOAD_BYTES ||
			   !opaqueIds.insert( entry.opaqueId).second || !urls.insert( entry.downloadUrl).second) {
				plan.clear() ;
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			plan.push_back( {.opaqueId		   = entry.opaqueId,
							.downloadUrl	   = entry.downloadUrl,
							.publishedSha256   = entry.sha256,
							.workspaceFileName = workspaceFileName( index, extension),
							.maximumFileBytes  = entry.maximumDownloadBytes}) ;
		}
	} catch( const std::bad_alloc &) {
		plan.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		plan.clear() ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_package_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError acquireAsusPackageForInspection(
	const AsusPackageAcquisitionPlanEntry &entry, const bool restrictedNetworkApproved,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialAcquisitionTransport &transport, IOfficialNetworkCostReader &costReader,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback &cancellationCallback, OfficialAcquisitionResult &result)
{
	const OfficialAcquisitionRequest request{.url				= entry.downloadUrl,
											 .providerId		= ASUS_PROVIDER_ID,
											 .resourceId		= OFFICIAL_PAYLOAD_RESOURCE_ID,
											 .workspaceFileName = entry.workspaceFileName,
											 .maximumFileBytes	= entry.maximumFileBytes,
											 .publishedSize		= std::nullopt,
											 .publishedSha256	= entry.publishedSha256,
											 .restrictedNetworkApproved =
												 restrictedNetworkApproved} ;	// 固定ASUS取得要求。
	return session.acquire( request, workspace, transport, costReader, progressCallback,
						   cancellationCallback, result) ;
}

} // namespace drivercrate
