//------------------------------------------------------------------------------
/**
 * @file amd_catalog_parser.h
 * @brief AMD公式support page parser定義。
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
 * @note AMD公式support pageに埋め込まれた製品一覧とWindows x64配布情報を有限に解析します。HTMLまたは表示名からPnP適用性を推測しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// AMD公式page値型定義。
//------------------------------------------------------------------------------

/**
 * @brief AMD公式製品選択一覧に含まれる一つの末端製品である。
 */
struct AmdProductPage {
	/// AMDが表示する末端製品名。
	std::wstring title ;
	/// `www.amd.com`上の製品別support page URL。
	std::wstring url ;
} ;

/**
 * @brief AMD製品別support pageに含まれる一つのWindows x64配布情報である。
 *
 * @note `downloadUrl`は表示専用metadataであり、G11取得・内容・system監査の合格を
 * 意味しない。
 */
struct AmdDriverPageEntry {
	/// Adrenalin EditionまたはPRO Editionの公式名称。
	std::wstring  title ;
	/// AMDが表示するrelease番号とWHQL区分。
	std::wstring  revision ;
	/// `YYYY-MM-DD`形式の公式公開日。
	std::wstring  releaseDate ;
	/// `drivers.amd.com`上のEULA同意対象URL。
	std::wstring  downloadUrl ;
	/// 表示sizeから切り上げた上限byte数。
	std::uint64_t maximumDownloadBytes{} ;
	/// RevisionがWHQL Recommendedと明示する場合true。
	bool		  whqlRecommended{} ;
	/// RevisionがWHQL Optionalと明示する場合true。
	bool		  whqlOptional{} ;
} ;

//------------------------------------------------------------------------------
// AMD公式page parser定義。
//------------------------------------------------------------------------------

/**
 * @brief AMD driver選択pageの埋込み製品JSONから末端製品一覧を取得する。
 * Scriptを実行せず、componentのdata-json属性だけを解析する。
 * @param[in] html AMD公式起点から取得したUTF-16 HTML。 AMD公式起点pageのUTF-16 HTML。
 * @param[out] products 成功時の製品名と公式page URL。失敗時は空にする。 全検証成功時の末端製品一覧。
 * @return Schema、文字列、件数、深さおよびURL境界を満たす場合は`true`。 埋込みJSON全体を有限に検証できた場合は`true`。
 * @pre 呼出しthreadでCOM apartmentが初期化されていること。
 */
[[nodiscard]] bool parseAmdProductIndexHtml( std::wstring_view			 html,
											std::vector<AmdProductPage> &products) ;

/**
 * @brief Local表示名へ完全一致するAMD末端製品pageを一意に選択する。
 * 商標表記以外の語を維持し、同名重複は曖昧として拒否する。
 * @param[in] products 検証済みAMD末端製品一覧。 検証済み末端製品一覧。
 * @param[in] deviceModel SetupAPI由来の非機密device表示名。 SetupAPI由来のdevice表示名。
 * @param[out] product 成功時の一意な製品page。失敗時は空にする。 一意一致時の公式製品page。
 * @return 商標表記と空白だけを正規化した名前が一意に完全一致する場合は`true`。 一件だけ完全一致した場合は`true`。
 */
[[nodiscard]] bool findAmdProductPage( std::span<const AmdProductPage> products,
									  std::wstring_view deviceModel, AmdProductPage &product) ;

/**
 * @brief AMD製品別pageから指定Windows x64区分のdriver表示情報を取得する。
 * Display driver以外を除外し、EXEをinstall可能とは扱わない。
 * @param[in] html AMD公式製品pageから取得したUTF-16 HTML。 AMD製品別pageのUTF-16 HTML。
 * @param[in] windowsSection `Windows 10`または`Windows 11`のx64区分名。 対象Windows x64 accordion名。
 * @param[out] entries 成功時のdriver表示情報。該当なしの場合は空にする。 全採用articleの表示metadata。
 * @return HTML境界と全採用entryの必須metadataが有効な場合は`true`。 対象区分と採用articleを全て検証できた場合は`true`。
 */
[[nodiscard]] bool parseAmdDriverPageHtml( std::wstring_view html, std::wstring_view windowsSection,
										  std::vector<AmdDriverPageEntry> &entries) ;

} // namespace drivercrate
