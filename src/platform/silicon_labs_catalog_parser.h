//------------------------------------------------------------------------------
/**
 * @file silicon_labs_catalog_parser.h
 * @brief CP210x公式配布metadataの検証契約。
 * @version 01.00.01
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式JSONからCP210x配布を限定。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * </pre>
 *
 * @note ADR 0093の公開配布だけを抽出する。通信と内容検証は呼出し側が行う。
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <string_view>

namespace drivercrate {
struct OfficialReleaseRecord ;

/**
 * @brief 既存の公開ZIP検証に加え、JSONが明示した配布版を保持する。
 * @param[in] html 上限付き公式landing本文。
 * @param[in] json 上限付き公式一覧本文。
 * @param[out] record 成功時のworker専用record。拒否時は初期値。
 * @return 公開区画と一意な配布recordの全条件が成立した場合true。
 * @note 版はINF版ではない。公開日、容量、hash、許諾を推測しない。
 */
[[nodiscard]] bool parseSiliconLabsOfficialRelease( std::wstring_view html, std::wstring_view json,
												   OfficialReleaseRecord &record) ;

/**
 * @brief 公式download区画とJSON内の一意なCP210x公開ZIPを検証する。
 * Windows JSON parserの型例外をmetadata拒否へ変換する。外部URL、login配布、別OS、別archiveを推測で補完しない。
 * @param[in] html 公式landingのUTF-16本文。2 Mi文字以内。 公式landing本文。
 * @param[in] json 同じ公式配布一覧のUTF-16 JSON。2 Mi文字以内。 公式一覧本文。
 * @param[out] url 成功時の内部URL。拒否時は空。 成功時の内部URL。失敗時は空。
 * @return 審査済み区画、型、配布種別、相対pathが一致した場合true。 全schema条件と一意性を確認できた場合true。
 * @note JSON表示版をINF版や適用性として使用しない。通信、署名検証は行わない。
 */
[[nodiscard]] bool parseSiliconLabsOfficialZipUrl( std::wstring_view html, std::wstring_view json,
												  std::wstring &url) ;
} // namespace drivercrate
