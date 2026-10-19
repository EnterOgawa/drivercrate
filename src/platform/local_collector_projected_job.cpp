//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_job.cpp
 * @brief 共有jobの全対象scopeを公式GETとcache identityに固定します。
 * @version 01.00.02
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  全対象scopeと公式policyの非通信結合を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/07  旧GETカテゴリとIntelの空値の役割説明を追加。
 * Ver.01.00.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 本経路はmetadata GETの準備のみであり、payload取得・導入を行いません。
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_projected_job.h"

#include "core/official_source_policy.h"
#include "platform/intel_collector_identity_parser.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/local_collector_legacy.h"
#include "platform/official_file_verifier.h"
#include <winrt/base.h>

#include <algorithm>
#include <set>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

/**
 * @brief 小文字SHA-256の固定表現だけを認めます。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @return 64桁小文字ASCII hexの場合true。それ以外はfalse。
 */
[[nodiscard]] bool hashName( const std::wstring_view value) noexcept
{
	return value.size() == 64U && std::all_of( value.begin(), value.end(), []( const wchar_t c) {
			   return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ;
		   }) ;
}

/**
 * @brief 公開fieldを有限長・制御文字なしに制限します。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @return 1～256 UTF-16 code unitで制御文字を含まない場合true。それ以外はfalse。
 */
[[nodiscard]] bool publicField( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 256U &&
		   std::none_of( value.begin(), value.end(),
						[]( const wchar_t c) { return c < L' ' || c == L'\x7f' ; }) ;
}

/**
 * @brief 長さ付きUTF-8値を曖昧さなくcanonical列に追加します。
 * @param[in,out] bytes UTF-8 byte長、colon、値を追記するcanonical列。例外時は途中状態を保持する。
 * @param[in] value UTF-8へ変換して追記するUnicode view。同期中だけ借用する。
 */
void appendField( std::string &bytes, const std::wstring_view value)
{
	const auto utf8 = winrt::to_string( winrt::hstring( value)) ;	// 元Unicodeを厳密UTF-8化する。
	bytes += std::to_string( utf8.size()) ;
	bytes += ':' ;
	bytes += utf8 ;
}

/**
 * @brief 有限canonical列を小文字SHA-256に変換します。
 * @param[in] bytes Hash対象canonical byteの借用view。
 * @param[out] hash 最初に空へ戻す。Hash成功時のdigestを保持し、false時は利用しない。
 * @return CNG成功かつ小文字SHA-256表記の確認成功時true。それ以外はfalse。
 */
[[nodiscard]] bool hashFields( const std::string_view bytes, std::wstring &hash)
{
	hash.clear() ;
	return computeBytesSha256( bytes, hash) == 0U && hashName( hash) ;
}

} // namespace

/** @see local_collector_projected_job.h */
bool makeCollectorProjectedJobInput( const CollectorCampaignManifest &manifest,
									const std::size_t				 jobIndex,
									const std::wstring_view			 artifactSha256,
									CollectorProjectedJobInput		&input)
{
	input = {} ;
	try {
		// Manifestの上限と実byte hashを旧parserの出力契約へ再結合する。
		if( !hashName( manifest.manifestSha256) || !hashName( artifactSha256) ||
		   manifest.targets.empty() || manifest.targets.size() > 300U ||
		   manifest.jobs.size() > 300U || jobIndex >= manifest.jobs.size()) {
			return false ;
		}

		const auto	&job = manifest.jobs[jobIndex] ;	// 一回GETに対応する元共有job。
		std::wstring checkedJobKey ;					// Manifest後の改変を再検査する。
		// Job同一性と現在profileの有限request条件をまとめて再照合する。
		if( !makeCollectorCampaignJobKey( job, checkedJobKey) || job.key != checkedJobKey ||
		   job.targetIndices.empty() || job.targetIndices.size() > 300U || job.locale != L"en-US" ||
		   job.page != 1U || job.source.maximumResponseBytes == 0U ||
		   job.source.maximumResponseBytes > 8U * 1024U * 1024U ||
		   !publicField( job.publicLocator) || !publicField( job.source.parserRevision)) {
			return false ;
		}

		// 初期の二sourceだけを、既存公式request builderへ渡す。
		const bool asus	 = job.source.sourceId == L"ASUS_CATALOG" ;				// ASUS公開model起点。
		const bool intel = job.source.sourceId == L"INTEL_ETHERNET_WINDOWS11" ;	// 固定727998起点。
		// 未登録sourceや別pageを公式入口として扱わない。
		if( (!asus && !intel) || (intel && job.publicLocator != L"727998")) {
			return false ;
		}

		CollectorProjectedJobInput result ;	// 全検査後にだけcallerへ移す所有値。
		result.manifestSha256 = manifest.manifestSha256 ;
		result.jobIndex		  = jobIndex ;
		result.jobKey		  = job.key ;
		result.source		  = job.source ;
		result.publicLocator  = job.publicLocator ;
		result.locale		  = job.locale ;
		result.page			  = job.page ;
		result.recordParser =
			asus ? L"ASUS_COLLECTOR_PAGE_V1"
				 : std::wstring( INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_ID) + L":" +
					   std::to_wstring( INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_REVISION) ;
		result.identityParser = asus
									? L"ASUS_SAME_STORE_V1"
									: L"INTEL_COLLECTOR_IDENTITY:" +
										  std::to_wstring( INTEL_COLLECTOR_IDENTITY_PARSER_REVISION) ;
		result.matchingRule	  = asus ? L"ASUS_ASCII_SPACE_V1" : L"INTEL_NFC_EXACT_V1" ;
		// 元要求表記とparserの照合表記は別々に固定する。
		const auto requestOs = std::wstring_view( L"Windows 11 64-bit") ;	// 旧GET identity。
		// 旧GET identityへ渡すカテゴリ。ASUSはLAN、Intel固定pageでは空でカテゴリ指定なしを表す。
		const auto category = asus ? std::wstring_view( L"LAN") : std::wstring_view{} ;
		// 旧request identityと同じ公開fieldからtarget keyを得る。
		if( !makeLocalCollectorTarget( job.source.sourceId,
									 asus ? std::wstring_view( job.publicLocator)
										  : std::wstring_view{},
									 requestOs, category, result.requestTarget)) {
			return false ;
		}

		LocalCollectorRequest request ;	// 固定policyとresourceを元GETから解決する。
		// 共有jobのsource/resource/groupを公式builder出力と一致させる。
		if( !makeLocalCollectorRequest( result.requestTarget, request) ||
		   request.source != job.source.sourceId || request.resource != job.source.resourceId ||
		   request.group != job.source.rateLimitGroup || request.requestKey.empty()) {
			return false ;
		}

		const auto *policy = officialSourcePolicyForProvider( request.provider) ;	// 組み込み定義。
		// Sourceラベルとpolicy IDを混同せず組み込みregistryへ照合する。
		if( policy == nullptr || findOfficialSourceResource( *policy, request.resource) == nullptr ||
		   (asus && policy->id != ASUS_OFFICIAL_SOURCE_POLICY_ID) ||
		   (intel && policy->id != INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID)) {
			return false ;
		}

		result.providerId = request.provider ;
		result.policyId	  = policy->id ;
		result.requestKey = request.requestKey ;

		// 現profileは一つの明示sliceで全targetを一本文から評価する。
		CollectorProjectedSliceScope slice ;	// source別の目的とOS照合表記。
		slice.category		  = asus ? L"LAN" : L"Ethernet" ;
		slice.purpose		  = slice.category ;
		slice.operatingSystem = asus ? L"Windows 11 64-bit" : L"Windows 11" ;
		slice.architecture	  = L"x64" ;
		std::string sliceBytes( "collector-projection-slice-v1") ;	// 一sliceのcanonical入力。
		appendField( sliceBytes, job.source.sourceId) ;
		appendField( sliceBytes, job.source.resourceId) ;
		appendField( sliceBytes, slice.category) ;
		appendField( sliceBytes, slice.purpose) ;
		appendField( sliceBytes, slice.operatingSystem) ;
		appendField( sliceBytes, slice.architecture) ;
		// 空のslice keyを成功として保存しない。
		if( !hashFields( sliceBytes, slice.key)) {
			return false ;
		}

		result.slices.push_back( std::move( slice)) ;

		std::set<std::size_t> indices ;	// 共有job内の同一公開対象を拒否する。
		// 入力順と全対象を保持し、先頭だけの代表評価へ縮めない。
		for( const auto index : job.targetIndices) {
			// 先頭一件だけでなく元順序の全参照を所有する。
			if( index >= manifest.targets.size() || !indices.insert( index).second) {
				return false ;
			}

			const auto &target = manifest.targets[index] ;	// Manifestの元公開field。
			// 改変された公開fieldをcache identityへ取り込まない。
			if( !publicField( target.id) || !publicField( target.maker) ||
			   !publicField( target.model) || !publicField( target.kind) ||
			   !publicField( target.purpose)) {
				return false ;
			}

			result.targets.push_back(
				{index, target, asus ? L"Windows 11 64-bit" : L"Windows 11", L"x64", L""}) ;
		}

		// 元job・source・全target・sliceのcanonicalを同じ予約前に固定する。
		std::string scopeBytes( "collector-projection-scope-v1") ;	// 全対象scopeの入力。
		appendField( scopeBytes, result.manifestSha256) ;
		appendField( scopeBytes, result.jobKey) ;
		appendField( scopeBytes, result.requestKey) ;
		appendField( scopeBytes, result.source.sourceId) ;
		appendField( scopeBytes, result.source.resourceId) ;
		appendField( scopeBytes, result.source.rateLimitGroup) ;
		appendField( scopeBytes, result.providerId) ;
		appendField( scopeBytes, result.policyId) ;
		appendField( scopeBytes, result.publicLocator) ;
		appendField( scopeBytes, result.locale) ;
		appendField( scopeBytes, std::to_wstring( result.page)) ;
		appendField( scopeBytes, std::to_wstring( result.targets.size())) ;
		// 対象順・全公開field・明示OS条件をscopeへ束ねる。
		for( const auto &target : result.targets) {
			appendField( scopeBytes, std::to_wstring( target.index)) ;
			appendField( scopeBytes, target.target.id) ;
			appendField( scopeBytes, target.target.maker) ;
			appendField( scopeBytes, target.target.model) ;
			appendField( scopeBytes, target.target.kind) ;
			appendField( scopeBytes, target.target.purpose) ;
			appendField( scopeBytes, target.operatingSystem) ;
			appendField( scopeBytes, target.architecture) ;
			appendField( scopeBytes, target.chip) ;
		}

		// 各slice identityも同じscopeに固定する。
		for( const auto &item : result.slices) {
			appendField( scopeBytes, item.key) ;
		}

		// Scope hash API失敗を既存cache値で補完しない。
		if( !hashFields( scopeBytes, result.scopeSha256)) {
			return false ;
		}

		std::string bindingBytes( "collector-projection-binding-v1") ;	// cache専用契約。
		appendField( bindingBytes, result.scopeSha256) ;
		appendField( bindingBytes, artifactSha256) ;
		appendField( bindingBytes, result.source.parserRevision) ;
		appendField( bindingBytes, result.recordParser) ;
		appendField( bindingBytes, result.identityParser) ;
		appendField( bindingBytes, result.matchingRule) ;
		appendField( bindingBytes, std::to_wstring( result.source.maximumResponseBytes)) ;
		// Artifactと全parser版を含む別cache bindingを固定する。
		if( !hashFields( bindingBytes, result.cacheBinding)) {
			return false ;
		}

		input = std::move( result) ;
		return true ;
	} catch( ...) {
		input = {} ;
		return false ;
	}
}
} // namespace drivercrate
