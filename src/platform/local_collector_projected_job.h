//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_job.h
 * @brief 共有metadata jobの全公開対象と公式GET契約を所有します。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  全対象scopeと公式requestの固定結合を追加。
 * </pre>
 *
 * @note 本型は非通信・非保存です。公式recordや取得許可を発行しません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/local_collector_campaign.h"
#include "platform/local_driver_collector.h"

#include <cstddef>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief 一つの共有jobで照合する元公開targetと明示OS条件です。 */
struct CollectorProjectedTargetScope {
	/// Manifest内で固定されたindex。
	std::size_t				index{} ;
	/// 元manifestにある公開fieldを改変せず所有します。
	CollectorCampaignTarget target ;
	/// 初期profileの明示OS。公開titleから推測しません。
	std::wstring			operatingSystem ;
	/// 初期profileの明示architecture。
	std::wstring			architecture ;
	/// 初期profileでは空の明示chip条件。
	std::wstring			chip ;
} ;

/** @brief 一つの公式metadata本文を評価する有限sliceです。 */
struct CollectorProjectedSliceScope {
	/// ASUS公式分類LAN、またはIntel Ethernet。
	std::wstring category ;
	/// 初期profileに固定した目的。
	std::wstring purpose ;
	/// Source parserへ渡す明示OS。
	std::wstring operatingSystem ;
	/// 明示architecture。
	std::wstring architecture ;
	/// Canonical slice identity。
	std::wstring key ;
} ;

/** @brief 元manifestから固定した一GETと全対象の所有入力です。 */
struct CollectorProjectedJobInput {
	/// 元manifestの実byte SHA-256。
	std::wstring							   manifestSha256 ;
	/// 元job index。
	std::size_t								   jobIndex{} ;
	/// 元job key。旧算法を維持します。
	std::wstring							   jobKey ;
	/// 旧公式GETを再構築できる公開target。
	LocalCollectorTarget					   requestTarget ;
	/// 元requestの恒久key。旧算法を維持します。
	std::wstring							   requestKey ;
	/// 組み込みsourceの有限契約。
	CollectorCampaignSource					   source ;
	/// 公式Provider ID。
	std::wstring							   providerId ;
	/// Sourceラベルとは別の組み込みpolicy ID。
	std::wstring							   policyId ;
	/// Record parserの固定版。
	std::wstring							   recordParser ;
	/// 製品一覧parserの固定版。
	std::wstring							   identityParser ;
	/// 三状態照合規則の固定版。
	std::wstring							   matchingRule ;
	/// 要求した公開locator。URLは含みません。
	std::wstring							   publicLocator ;
	/// 元要求のlocale。
	std::wstring							   locale ;
	/// 元要求のpage。
	std::uint32_t							   page{} ;
	/// 元index順に並ぶ全公開対象。先頭だけを解析へ渡しません。
	std::vector<CollectorProjectedTargetScope> targets ;
	/// 初期profileでは一slice。拡張時も最大16です。
	std::vector<CollectorProjectedSliceScope>  slices ;
	/// 全対象・slice・sourceを含む固定SHA-256。
	std::wstring							   scopeSha256 ;
	/// Scope、policy、artifact、全parser版の専用cache binding。
	std::wstring							   cacheBinding ;
} ;

/** @brief 検証済みmanifestの一共有jobを全targetごと再照合して所有します。
 * @param[in] manifest 元実byteを検証済みのmanifest。
 * @param[in] jobIndex 対象jobのindex。
 * @param[in] artifactSha256 実binary等から別途固定された小文字SHA-256。
 * @param[out] input 成功時だけ所有scopeを返します。失敗時は空。
 * @return 旧公式request、source policy、全対象とcache bindingが成立した場合true。
 * @note 旧requestKey／jobKey算法は変更せず、通信や保存は行いません。
 */
[[nodiscard]] bool makeCollectorProjectedJobInput( const CollectorCampaignManifest &manifest,
												  std::size_t					   jobIndex,
												  std::wstring_view				   artifactSha256,
												  CollectorProjectedJobInput	  &input) ;

} // namespace drivercrate
