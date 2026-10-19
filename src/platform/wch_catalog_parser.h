//------------------------------------------------------------------------------
/**
 * @file wch_catalog_parser.h
 * @brief WCH公式serial配布metadata検証契約。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公開JSONの限定解析を追加。
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
 * @note 公式取得先は検証済み整数IDだけから構成する。署名検証は別途行う。
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <string_view>

namespace drivercrate {
struct OfficialReleaseRecord ;
/** @brief WCH公式metadataで許可した二つのZIP配布種別。 */
enum class WchOfficialPackageKind {
	/// CH340／CH341用CH341SER.ZIP。
	CH341,
	/// CH342／CH343系用CH343SER.ZIP。
	CH343,
} ;

/**
 * @brief WCHの主recordを検証して明示配布版と公開整数IDを保持する。
 * @param[in] kind 固定した審査済み配布系列。
 * @param[in] html 上限付き公式landing本文。
 * @param[in] json 上限付き公式lookup本文。
 * @param[out] record 成功時のworker専用record。拒否時は初期値。
 * @return 既存公開ZIPの全検証条件が成立した場合true。
 * @note 版をINF版として扱わず、未知の日付、容量、hash、許諾を補完しない。
 */
[[nodiscard]] bool parseWchOfficialRelease( WchOfficialPackageKind kind, std::wstring_view html,
										   std::wstring_view json, OfficialReleaseRecord &record) ;

/**
 * @brief 公式landingとJSONを検証して一つの主recordのZIP URLを得る。
 * 任意URLや関連配布物ではなく検証済み整数IDだけを使用する。Windows JSONの型／構文例外はmetadata拒否に変換する。
 * @param[in] kind 検索対象に固定する配布種別。未知enumは拒否する。 審査済み配布種別。
 * @param[in] html 対応する公式landingのUTF-16本文。2 Mi文字以内。 公式landing本文。
 * @param[in] json 固定lookupで得たUTF-16 JSON。2 Mi文字以内。 公式lookup本文。
 * @param[out] url 成功時のworker内URL。拒否時は空。 成功時だけの取得URL。
 * @return Schema、公開状態、family、ID範囲が有効な場合true。 主recordの全条件が有効な場合true。拒否時は出力を空にする。
 * @note 通信と署名検証は行わない。JSON表示版をINF版や適用性へ流用しない。
 */
[[nodiscard]] bool parseWchOfficialZipUrl( WchOfficialPackageKind kind, std::wstring_view html,
										  std::wstring_view json, std::wstring &url) ;
} // namespace drivercrate
