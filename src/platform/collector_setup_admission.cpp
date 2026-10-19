//------------------------------------------------------------------------------
/**
 * @file collector_setup_admission.cpp
 * @brief 既存validatorとrequest builderからnative排他leaseを構築します。
 * @version 01.00.00
 * @date 2026/10/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/17 全旧scopeと非作成leaseを再利用。
 * </pre>
 *
 * @note 新DB、日残量の推測、共有native予約の代替は作成しません。
 */
//------------------------------------------------------------------------------
#include "collector_setup_admission.h"

#include "official_file_verifier.h"

#include <winrt/base.h>
#include <algorithm>
#include <new>
#include <set>
#include <utility>

namespace drivercrate {

DWORD acquireCollectorSetupAdmission( const std::filesystem::path &root,
									 const std::uint64_t		  utcMillis,
									 CollectorSetupAdmission	 &admission,
									 std::wstring				 &reason) noexcept
{
	admission = {} ;
	reason.clear() ;
	try {
		reason = L"NATIVE_ORIGIN_INVALID" ;
		// 呼出し元の文字列だけで欠損rootや正規化前の別名を採用しない。
		if( !root.is_absolute() || root != root.lexically_normal()) {
			return ERROR_INVALID_PARAMETER ;
		}

		CollectorSetupAdmission result ;	// 全検証が完了するまで公開しない所有値。
		result.store = std::make_shared<LocalCollectorStateStore>() ;
		DWORD code	 = result.store->initializeExistingWriter( root) ;	// 新規作成は許さない。
		// Lock競合・ACL・欠損の元codeを維持する。
		if( code != ERROR_SUCCESS) {
			reason =
				code == ERROR_SHARING_VIOLATION ? L"NATIVE_WRITER_BUSY" : L"NATIVE_ORIGIN_INVALID" ;
			return code ;
		}

		std::vector<std::wstring> current ;	// 全current名を検査する。
		std::vector<std::wstring> runs ;	// 全run名を検査する。
		// 部分列挙では共有scopeを除外できない。
		if( (code = result.store->listCurrentNames( current)) != ERROR_SUCCESS ||
		   (code = result.store->listRunNames( runs)) != ERROR_SUCCESS) {
			return code ;
		}

		// 旧inspectorが上位監督へ残すmodeと予約prefixを全て拒否する。
		for( const auto &names : {current, runs}) {
			// 全名を確認し、campaignの待機・日予算を旧v4へ縮小しない。
			for( const auto &name : names) {
				// 共有native予約へ未接続のscopeは専用理由で保留する。
				if( name.starts_with( L"campaign-") || name == L"collector-campaign-mode-v1.json") {
					reason = L"NATIVE_SHARED_SCOPE_UNSUPPORTED" ;
					return ERROR_INVALID_DATA ;
				}
			}
		}

		code = inspectLocalCollectorLegacy( *result.store, utcMillis, result.snapshot, reason) ;
		// 未回収・未来時計・不完全requestの元validatorを迂回しない。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		// 履歴なしstoreから全旧requestの存在を推定しない。
		if( result.snapshot.requests.empty()) {
			reason = L"NATIVE_REQUEST_SCOPE_MISSING" ;
			return ERROR_INVALID_DATA ;
		}

		// 現在のrunにtargetがなくても残るsource待機の作用hostを欠落させない。
		for( const auto &wait : result.snapshot.waits) {
			// 待機groupのactual hostを元builderが復元したかを確認する。
			const bool represented =
				std::any_of( result.snapshot.requests.begin(), result.snapshot.requests.end(),
							[&wait]( const auto &request) { return request.group == wait.group ; }) ;
			// Builderでactual hostを再構築できない待機groupは非共有と証明しない。
			if( !represented) {
				reason = L"NATIVE_REQUEST_SCOPE_UNVERIFIED" ;
				return ERROR_INVALID_DATA ;
			}
		}

		std::set<std::wstring> requests ;	// methodとactual URLの一意集合。
		std::set<std::wstring> hosts ;		// 全groupのactual host footprint。
		// 公式builderが検証した全requestを、monitorと共通の比較式へ投影する。
		for( const auto &request : result.snapshot.requests) {
			const auto	 end = request.url.find( L'/', 8U) ;	// HTTPS authorityの終端。
			std::wstring host =
				// 照合用だけASCII大小文字を統一するhost。
				request.url.substr( 8U, end - 8U) ;
			// 不明なgroup・authority・schemeは非共有に数えない。
			if( !request.url.starts_with( L"https://") || host.empty() ||
			   host.find_first_of( L":@?#\\") != std::wstring::npos ||
			   (request.group != L"asus" && request.group != L"intel")) {
				reason = L"NATIVE_REQUEST_SCOPE_UNVERIFIED" ;
				return ERROR_INVALID_DATA ;
			}

			// DNS hostは大小文字を区別しないため、Python hostnameと同じ小文字へ固定する。
			std::transform( host.begin(), host.end(), host.begin(), []( const wchar_t letter) {
				return letter >= L'A' && letter <= L'Z'
						   ? static_cast<wchar_t>( letter + (L'a' - L'A'))
						   : letter ;
			}) ;
			std::wstring requestHash ;	// GETとURLを明示した共通比較hash。
			std::wstring hostHash ;		// 大小文字を公式builderが固定したactual hostのhash。
			// Hash失敗を空集合へ置き換えて許可しない。
			if( computeBytesSha256( "GET\n" + winrt::to_string( request.url), requestHash) != 0 ||
			   computeBytesSha256( winrt::to_string( host), hostHash) != 0) {
				return ERROR_INVALID_DATA ;
			}

			requests.insert( std::move( requestHash)) ;
			hosts.insert( std::move( hostHash)) ;
		}

		result.requestHashes.assign( requests.begin(), requests.end()) ;
		result.hostHashes.assign( hosts.begin(), hosts.end()) ;
		admission = std::move( result) ;
		reason.clear() ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		reason.clear() ;
		return ERROR_INVALID_DATA ;
	}
}

} // namespace drivercrate
