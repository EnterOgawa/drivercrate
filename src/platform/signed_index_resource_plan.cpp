//------------------------------------------------------------------------------
/**
 * @file signed_index_resource_plan.cpp
 * @brief descriptor-v2の閉じた親範囲計画をstrict readerで読む。
 * @version 01.01.01
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  STATIC_URLと三段content計画の読取りを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続。
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 元申告を読むだけで、取得・由来・署名・適合・導入を許可しない。
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_acquisition_descriptor_internal.h"
#include <Windows.h>
#include <array>
#include <utility>

namespace drivercrate::signed_index_acquisition {
namespace {
using signed_index_json::require ;
constexpr auto BAD = IndexRecordsStatus::INVALID_EVIDENCE ;	// この元申告の固定拒否区分。
//------------------------------------------------------------------------------
/**
 * @brief strict UTF-8原textをWindowsの原UTF-16へ変換する。
 * @param[in] text 既存readerの検査済み有限text。
 * @return 正規化しない元値。
 */
//------------------------------------------------------------------------------
std::wstring   resourceWide( const std::string &text)
{
	const auto size = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
										  // 原UTF-16長。
										  static_cast<int>( text.size()), nullptr, 0) ;
	require( size > 0, BAD) ;
	std::wstring value( static_cast<std::size_t>( size), L'\0') ;	// 欠損なく変換する所有値。
	require( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
								static_cast<int>( text.size()), value.data(), size) == size,
			BAD) ;
	return value ;
}
//------------------------------------------------------------------------------
/**
 * @brief 順序によらず型付きresource atomを読む。
 * @param[in,out] reader 元recordのstrict reader。
 * @return 数値と文字列を区別した元atom。
 */
//------------------------------------------------------------------------------
OfficialResourceIdentifier atom( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 2U> fields{"kind", "value"} ;	// 閉じたatom field。
	OfficialResourceIdentifier				   value ;						// 全構造成功まで公開しない値。
	std::string								   kind ;						// 元kind文字列。
	bool									   text{} ;						// 元valueのJSON型。
	std::uint64_t							   id{} ;						// narrowing前の数値。
	reader.object( fields, [&]( const std::size_t index) {
		// kindの順序でvalueのJSON型を推測しない。
		if( index == 0U) {
			kind = reader.text( 16U) ;
		}
		// JSON textだけを原UTF-16名へ変換する。
		else if( (text = reader.textAhead())) {
			value.text = resourceWide( reader.text( 256U)) ;
		} else {
			id = reader.number() ;
		}
	}) ;
	require( (kind == "STRING" && text) || (kind == "ID" && !text && id <= 65535U), BAD) ;
	value.named = text ;
	value.id	= static_cast<std::uint32_t>( id) ;
	return value ;
}
//------------------------------------------------------------------------------
/**
 * @brief PEの三段tupleを読む。
 * @param[in,out] reader 元strict reader。
 * @return 明示languageを含む元tuple。
 */
//------------------------------------------------------------------------------
OfficialResourceTuple tuple( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 3U> fields{"type", "name",
													  "language"} ;	// 段を明示するfield。
	OfficialResourceTuple					   value ;				// 原tuple。
	reader.object( fields, [&]( const std::size_t index) {
		const auto item = atom( reader) ;	// 現段の元atom。
		// 三段の役割はfield名だけで定める。
		if( index == 0U) {
			value.type = item ;
		}
		// 第二段nameを原tupleへ保持する。
		else if( index == 1U) {
			value.name = item ;
		} else {
			require( !item.named, BAD) ;
			value.language = item.id ;
		}
	}) ;
	return value ;
}
//------------------------------------------------------------------------------
/**
 * @brief 親範囲へ後で結ぶ原sliceを読む。
 * @param[in,out] reader 元strict reader。
 * @return 全必須fieldを読んだslice。
 */
//------------------------------------------------------------------------------
OfficialResourceSlice slice( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 4U> fields{"resource", "offset", "length",
													  "sha256"} ;	// 全必須field。
	OfficialResourceSlice					   value ;				// 元範囲。
	reader.object( fields, [&]( const std::size_t index) {
		// 元JSON型をfieldごとに固定する。
		if( index == 0U) {
			value.resource = tuple( reader) ;
		}
		// raw offsetは非負の原整数として読む。
		else if( index == 1U) {
			value.offset = reader.number() ;
		}
		// 原slice長は元整数で保持する。
		else if( index == 2U) {
			value.length = reader.number() ;
		} else {
			value.sha256 = resourceWide( reader.text( 64U)) ;
		}
	}) ;
	return value ;
}
//------------------------------------------------------------------------------
/**
 * @brief 一roleの元名と原範囲を読む。
 * @param[in,out] reader 元strict reader。
 * @return 全必須fieldを読んだfile。
 */
//------------------------------------------------------------------------------
OfficialResourceRoleFile file( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 6U> fields{"role",	"basename", "resource", "offset",
													  "length", "sha256"} ;	// flat roleの全field。
	OfficialResourceRoleFile				   value ;						// 原role file。
	reader.object( fields, [&]( const std::size_t index) {
		// 役割を拡張子から補完しない。
		if( index == 0U) {
			const auto role = reader.text( 32U) ;	// 元enum文字列。
			require( role == "INF" || role == "CATALOG" || role == "DRIVER_FILE", BAD) ;
			value.role = role == "INF"		 ? OfficialResourceRole::INF
						 : role == "CATALOG" ? OfficialResourceRole::CATALOG
											 : OfficialResourceRole::DRIVER_FILE ;
		}
		// 出力logical basenameの原textを読む。
		else if( index == 1U) {
			value.basename = resourceWide( reader.text( 260U)) ;
		}
		// collectorの原tupleを別段の位置へ変換しない。
		else if( index == 2U) {
			value.slice.resource = tuple( reader) ;
		}
		// inner親へのraw offsetを読む。
		else if( index == 3U) {
			value.slice.offset = reader.number() ;
		}
		// roleの原byte数を読む。
		else if( index == 4U) {
			value.slice.length = reader.number() ;
		} else {
			value.slice.sha256 = resourceWide( reader.text( 64U)) ;
		}
	}) ;
	return value ;
}
//------------------------------------------------------------------------------
/**
 * @brief 再帰を持たない三段contentだけを読む。
 * @param[in,out] reader 元strict reader。
 * @return 原親と全roleに静的結合した計画。
 */
//------------------------------------------------------------------------------
OfficialResourceContentPlan content( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 6U> fields{"kind",  "root",		 "archive", "member",
													  "files", "selectedInf"} ;	// 固定三段のfield。
	OfficialResourceContentPlan				   value ;							// 原計画。
	reader.object( fields, [&]( const std::size_t index) {
		// kindごとの再帰解釈は行わない。
		if( index == 0U) {
			require( reader.text( 64U) == "PE_RESOURCE_RANGES_V1", BAD) ;
		}
		// root identityの必須size/hashを読む。
		else if( index == 1U) {
			constexpr std::array<std::string_view, 2U> rootFields{"bytes",
																  "sha256"} ;	// 原outer identity。
			reader.object( rootFields, [&]( const std::size_t field) {
				// 原親の全byte/hashを要求する。
				if( field == 0U) {
					value.rootBytes = reader.number() ;
				} else {
					value.rootSha256 = resourceWide( reader.text( 64U)) ;
				}
			}) ;
		}
		// 原outer内の7z sliceだけを読む。
		else if( index == 2U) {
			value.archive = slice( reader) ;
		}
		// 中間一memberの原名/size/hashを読む。
		else if( index == 3U) {
			constexpr std::array<std::string_view, 3U> memberFields{
				"path", "bytes", "sha256"} ;	// 一member identity。
			reader.object( memberFields, [&]( const std::size_t field) {
				// 中間fileは原名/size/hashを全て読む。
				if( field == 0U) {
					value.memberPath = resourceWide( reader.text( 260U)) ;
				}
				// 中間memberの正確なbyte宣言を読む。
				else if( field == 1U) {
					value.memberBytes = reader.number() ;
				} else {
					value.memberSha256 = resourceWide( reader.text( 64U)) ;
				}
			}) ;
		}
		// 有限role inventoryを原順に読む。
		else if( index == 4U) {
			reader.array(
				32U, [&] { value.files.push_back( file( reader)) ; }, IndexRecordsStatus::COUNT_LIMIT) ;
		} else {
			value.selectedInf = resourceWide( reader.text( 260U)) ;
		}
	}) ;
	require( validOfficialResourceContentPlan( value), BAD) ;
	return value ;
}
} // namespace
//------------------------------------------------------------------------------
/**
 * @brief v2の閉じた取得方法と三段resource計画をstrict readerで読む。
 * @param[in,out] reader 元recordを借用するstrict reader。
 * @param[out] anonymousCdn 明示された匿名解決の公開値。STATIC_URL時は空。
 * @return 全静的結合を成功した計画。取得/導入能力はない。
 */
//------------------------------------------------------------------------------
OfficialResourceContentPlan readResourcePayloadPlan(
	DescriptorReader &reader, std::optional<OfficialAnonymousCdnPlan> &anonymousCdn)
{
	constexpr std::array<std::string_view, 2U> fields{"retrieval",
													  "content"} ;	// 独立した二つの境界。
	OfficialResourceContentPlan				   value ;				// 全成功後だけ返す原選択。
	reader.object( fields, [&]( const std::size_t index) {
		// 明示された閉じた取得種別だけを元public文脈へ結ぶ。
		if( index == 0U) {
			constexpr std::array<std::string_view, 4U> retrievalFields{
				"kind", "model", "path", "systemCode"} ;	// 旧一fieldまたは新全四field。
			std::string				 kind ;					// 元の閉じた取得種別。
			OfficialAnonymousCdnPlan plan ;					// public値だけの元文脈。
			const auto				 present =
				reader.objectWithPresence( retrievalFields, [&]( const std::size_t field) {
					// Field順序からJSON型を推測しない。
					if( field == 0U) {
						kind = reader.text( 64U) ;
					}
					// 元modelだけを有限ASCII値として保持する。
					else if( field == 1U) {
						plan.model = resourceWide( reader.text( 64U)) ;
					}
					// 原pathを正規化せず保持する。
					else if( field == 2U) {
						plan.path = resourceWide( reader.text( 512U)) ;
					} else {
						plan.systemCode = resourceWide( reader.text( 16U)) ;
					}
				}) ;
			require( (kind == "STATIC_URL" && present == 1U) ||
						(kind == "ANONYMOUS_CDN_TOKEN_V1" && present == 15U &&
						 validAsusAnonymousCdnPlan( plan)),
					BAD) ;
			// STATICへ未知resolverを黙って落とさない。
			if( kind == "ANONYMOUS_CDN_TOKEN_V1") {
				anonymousCdn = std::move( plan) ;
			}
		} else {
			value = content( reader) ;
		}
	}) ;
	return value ;
}
} // namespace drivercrate::signed_index_acquisition
