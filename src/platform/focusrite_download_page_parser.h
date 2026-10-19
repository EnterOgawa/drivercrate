//------------------------------------------------------------------------------
/**
 * @file focusrite_download_page_parser.h
 * @brief Focusrite製品別Windows driver page parser定義。
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
 * @note 固定Scarlett 2i2 2nd Gen pageの現行Windows driver表示だけを解析します。本結果はEXEの内容、PnP適用性、取得または導入の許可を表しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <string_view>

namespace drivercrate {

/** @brief Focusrite製品別pageから取得したWindows向け表示専用metadata。 */
struct FocusriteDownloadPageMetadata {
	/// 公式payload URLが明示したEXE basename。
	std::wstring fileName ;
	/// 製品pageの名称とfile名で一致した配布版。
	std::wstring version ;
	/// 製品pageが明示したMB単位の概算size。
	std::wstring displaySize ;
	/// Focusrite公式配布hostのHTTPS URL。取得許可ではない。
	std::wstring downloadUrl ;

	/**
     * @brief 同じ公式pageから得た表示専用metadataを全fieldで比較する。
     * @param[in] other 比較対象のmetadata。
     * @return 全fieldが一致する場合true。
     */
	bool		 operator==( const FocusriteDownloadPageMetadata &other) const = default ;
} ;

/**
 * @brief Scarlett 2i2 2nd Gen Downloads pageの現行Windows欄を有限規則で解析する。
 * 製品、OS、版、公式URL、file名、build、sizeを相互照合する。旧USB driver、Mac欄、EXE取得、実行、内容監査またはPnP適用性判定は扱わない。
 * @param[in] html Focusrite公式hostから取得したUTF-16 HTML。
 * @param[out] metadata 成功時の表示専用metadata。失敗時は初期値。
 * @return 製品、OS、版、URL、file名、sizeが一意に整合する場合true。 固定製品の現行Windows配布欄が一意に整合する場合true。
 * @note 旧版、Mac、Control software、別製品または別hostを候補へ混入させない。
 */
[[nodiscard]] bool parseFocusriteScarlett2i2SecondGenPage( std::wstring_view				 html,
														  FocusriteDownloadPageMetadata &metadata) ;

} // namespace drivercrate
