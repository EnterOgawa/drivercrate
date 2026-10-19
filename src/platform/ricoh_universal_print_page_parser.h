//------------------------------------------------------------------------------
/**
 * @file ricoh_universal_print_page_parser.h
 * @brief Ricoh Universal Print公式download page parser定義。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Windows x64向け従来型PCL6 Universal Print Driverの表示情報だけを解析します。本結果はPnP適用性、内容監査、取得または導入の許可を表しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <string_view>

namespace drivercrate {

/** @brief Ricoh公式pageの六つのx64 OS欄で一致した表示専用metadata。 */
struct RicohUniversalPrintPageMetadata {
	/// 公式download URLが明示したEXE basename。
	std::wstring fileName ;
	/// 公式pageが明示したdotted numeric配布版。
	std::wstring version ;
	/// 公式pageが明示したMM/DD/YYYY形式の公開日。
	std::wstring releaseDate ;
	/// 公式pageが明示したKB単位の概算size。
	std::wstring displaySize ;
	/// Ricoh公式host上の直接HTTPS URL。取得許可ではない。
	std::wstring downloadUrl ;

	/**
     * @brief 六つのOS欄が同一配布物を示すことを全fieldで比較する。
     * @param[in] other 別のOS欄から解析した表示専用metadata。
     * @return 全fieldが一致する場合true。
     */
	bool		 operator==( const RicohUniversalPrintPageMetadata &other) const = default ;
} ;

/**
 * @brief Ricoh Universal Print Driver pageを有限規則で解析する。
 * OS別の明示値が分岐した場合は一つの候補へ推測統合せず拒否する。
 * @param[in] html Ricoh公式hostから取得したUTF-16 HTML。
 * @param[out] metadata 成功時の表示専用metadata。失敗時は初期値。 成功時の六OS共通metadata。失敗時は初期値。
 * @return 六つのWindows x64欄が同一の従来型PCL6配布情報を示す場合true。 六つの対象x64 OS欄が同一の従来型PCL6配布情報を示す場合true。
 * @note V4、PostScript、utility、32-bit、別hostおよびOS別に分岐した配布物は拒否する。
 */
[[nodiscard]] bool parseRicohUniversalPrintPage( std::wstring_view				 html,
												RicohUniversalPrintPageMetadata &metadata) ;

} // namespace drivercrate
