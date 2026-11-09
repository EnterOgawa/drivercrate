//------------------------------------------------------------------------------
/**
 * @file nvidia_collector_metadata.cpp
 * @brief NVIDIA公開queryと原応答を同collector releaseへ結びます。
 * @version 01.01.00
 * @date 2026/11/05
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/05  原件数・echo・channelと新版の一意性検査を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/11/05  原flagを検証して既知の非対象行だけを選択から除外。
 * </pre>
 * @note 表示版は同公開query内の選択専用です。内容・適用性・同意のproofを発行しません。
 * @see docs/adr/0447-nvidia-collector-json-metadata.md
 */
//------------------------------------------------------------------------------
#include "platform/nvidia_collector_metadata.h"
#include <array>
#include <exception>
#include <regex>
#include <set>
#include <utility>
#include <vector>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>

namespace drivercrate {
/** @see nvidia_collector_metadata.h 宣言側の契約を正本とします。 */
bool parseNvidiaCollectorLookupUrl( const std::wstring_view url, NvidiaCollectorLookup &lookup)
{
	lookup = {} ;
	// 登録公開IDを含む固定API以外をmetadata用途へ昇格しません。
	if( url.size() > 512U) {
		return false ;
	}

	const std::wregex pattern(
		// 原queryの引数順も固定します。
		LR"(https://gfwsl\.geforce\.com/services_toolkit/services/com/nvidia/services/AjaxDriverService\.php\?func=DriverManualLookup&psid=([1-9][0-9]{0,9})&pfid=([1-9][0-9]{0,9})&osID=(57|135)&languageCode=1033&beta=0&isWHQL=1&dltype=-1&dch=1&upCRD=(0|1)&qnf=0&sort1=0&numberOfResults=3)") ;
	// 元URLを呼出し中だけ借用します。
	std::match_results<std::wstring_view::const_iterator> match ;
	// 重複query・余分な引数・encodeした端末IDを許可しません。
	if( !std::regex_match( url.begin(), url.end(), match, pattern)) {
		return false ;
	}

	lookup = {match[1].str(), match[2].str(), match[3].str(), match[4].str() == L"1"} ;
	return true ;
}
/** @see nvidia_collector_metadata.h 宣言側の契約を正本とします。 */
NvidiaCollectorMetadataStatus selectNvidiaCollectorRelease( const std::wstring_view json,
														   const std::wstring_view lookupUrl,
														   NvidiaDriverEntry	  &selected)
{
	selected = {} ;
	try {
		NvidiaCollectorLookup lookup ;	// 定義内の公開queryだけです。
		// 過大本文とcanonical外のAPI条件を解析前に拒否します。
		if( json.empty() || json.size() > 2U * 1024U * 1024U ||
		   json.find( L'\0') != std::wstring_view::npos ||
		   !parseNvidiaCollectorLookupUrl( lookupUrl, lookup)) {
			return NvidiaCollectorMetadataStatus::INVALID ;
		}

		const auto root = winrt::Windows::Data::Json::JsonObject::Parse(
			// 原Requestはapp用parserの外側で照合します。
			winrt::hstring( json)) ;
		const auto requests = root.GetNamedArray( L"Request") ;	// APIが反映した公開queryです。
		// 別queryや曖昧な複数Requestからreleaseを選びません。
		if( requests.Size() != 1U) {
			return NvidiaCollectorMetadataStatus::INVALID ;
		}

		const auto request = requests.GetAt( 0U).GetObject() ;	// 同lookupのechoです。
		// 同product/OS/channelと非beta/WHQL/DCH/言語/有限結果条件を全て要求します。
		if( request.GetNamedString( L"psid") != lookup.seriesId ||
		   request.GetNamedString( L"pfid") != lookup.productId ||
		   request.GetNamedString( L"osID") != lookup.osId ||
		   request.GetNamedString( L"languageCode") != L"1033" ||
		   request.GetNamedString( L"beta") != L"0" || request.GetNamedString( L"isWHQL") != L"1" ||
		   request.GetNamedString( L"dltype") != L"-1" ||
		   request.GetNamedString( L"theSystemIsDc") != L"1" ||
		   request.GetNamedString( L"theUserRequestedCRD") != (lookup.studio ? L"1" : L"0") ||
		   request.GetNamedString( L"numberOfResults") != L"3" ||
		   request.GetNamedString( L"sort1") != L"0") {
			return NvidiaCollectorMetadataStatus::INVALID ;
		}

		std::vector<NvidiaDriverEntry> entries ;	// 既存公式host/ID検査を通った全releaseです。
		// 一部の不正releaseを除外して成功件数を作りません。
		if( !parseNvidiaDriverJson( json, entries)) {
			return NvidiaCollectorMetadataStatus::INVALID ;
		}

		const auto ids = root.GetNamedArray( L"IDS") ;	// 空応答のfailure wrapperも保持します。
		// HTTP200の空応答は候補なしでありdriver成功ではありません。
		if( root.GetNamedString( L"Success") == L"0") {
			return entries.empty() && ids.Size() == 1U &&
						   ids.GetAt( 0U)
								   .GetObject()
								   .GetNamedObject( L"downloadInfo")
								   .GetNamedString( L"Success") == L"0"
					   ? NvidiaCollectorMetadataStatus::NO_RESULT
					   : NvidiaCollectorMetadataStatus::INVALID ;
		}

		// 原Successはrelease件数です。原3件をSuccess=1へ読み替えません。
		if( entries.empty() || entries.size() > 3U || ids.Size() != entries.size() ||
		   root.GetNamedString( L"Success") != std::to_wstring( entries.size())) {
			return NvidiaCollectorMetadataStatus::INVALID ;
		}

		std::vector<bool> eligible ;	// 原行を削らず、同じ位置の選択適格性だけを保持します。
		eligible.reserve( entries.size()) ;
		// 最大3の全原行でflag字句を検証し、既知の非対象と不正schemaを区別します。
		for( const auto &value : ids) {
			const auto info =
				// 原一entryだけです。
				value.GetObject().GetNamedObject( L"downloadInfo") ;
			const std::array<winrt::hstring, 5U> flags{
				info.GetNamedString( L"IsActive"), info.GetNamedString( L"IsWHQL"),
				info.GetNamedString( L"Is64Bit"), info.GetNamedString( L"IsCRD"),
				// 一時viewでなく五つの原flagを所有します。
				info.GetNamedString( L"IsBeta")} ;
			// 非対象行でも未知flagをfalseや欠落へ補完しません。
			for( const auto &flag : flags) {
				// 0/1以外は選択可否とは別のschema拒否です。
				if( flag != L"0" && flag != L"1") {
					return NvidiaCollectorMetadataStatus::INVALID ;
				}
			}

			eligible.push_back( flags[0] == L"1" && flags[1] == L"1" && flags[2] == L"1" &&
							   flags[3] == (lookup.studio ? L"1" : L"0") && flags[4] == L"0") ;
		}

		const std::wregex version( LR"(([0-9]{1,5})\.([0-9]{2}))") ;	// marketing版の公開構文です。
		std::array<unsigned long, 2U> best{} ;							// 同product/OS/channel内だけの比較値です。
		std::set<std::wstring>		  seen ;							// APIの同download ID重複を拒否します。
		bool						  tied{} ;							// 最大同版の別releaseを勝手に選びません。
		NvidiaDriverEntry			  candidate ;						// 全検査前には外側の選択へcommitしません。
		// 全原releaseのID/版を検査した上で、選択可能な最大3行から一意の最大版を選びます。
		for( std::size_t index = 0U; index < entries.size(); ++index) {
			const auto	&entry = entries[index] ;	// eligibleと同じ原位置の完全なreleaseです。
			std::wsmatch match ;					// 一件のmarketing版だけです。
			// 不正ID重複や版構文は、非対象行でも他の有効候補で救済しません。
			if( !seen.insert( entry.id).second || !std::regex_match( entry.version, match, version)) {
				return NvidiaCollectorMetadataStatus::INVALID ;
			}

			const std::array<unsigned long, 2U> current{	// INF版へ転用しません。
														std::stoul( match[1].str()),
														std::stoul( match[2].str())} ;
			// 数値文法と有界範囲を保ち、過大な版の選択を拒否します。
			if( current[0] > 65535U) {
				return NvidiaCollectorMetadataStatus::INVALID ;
			}

			// 既知の非対象行を選択から外し、他の有効な現行releaseまで拒否しません。
			if( !eligible[index]) {
				continue ;
			}

			// 明示最大版の更新でのみ選択し、APIの配列順には依存しません。
			if( candidate.id.empty() || current > best) {
				best	  = current ;
				candidate = entry ;
				tied	  = false ;
			}
			// 同版の別download IDは不明なvariantとしてHOLDへ残します。
			else if( current == best) {
				tied = true ;
			}
		}

		// 最大同版の曖昧性を配列順やURLで解消しません。
		if( tied) {
			return NvidiaCollectorMetadataStatus::INVALID ;
		}

		// 原応答にreleaseがあっても全行非対象なら有効driverの成功を発行しません。
		if( candidate.id.empty()) {
			return NvidiaCollectorMetadataStatus::NO_RESULT ;
		}

		selected = std::move( candidate) ;
		return NvidiaCollectorMetadataStatus::SELECTED ;
	} catch( const winrt::hresult_error &) {
		selected = {} ;
		return NvidiaCollectorMetadataStatus::INVALID ;
	} catch( const std::exception &) {
		selected = {} ;
		return NvidiaCollectorMetadataStatus::INVALID ;
	}
}
} // namespace drivercrate
