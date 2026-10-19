//------------------------------------------------------------------------------
/**
 * @file wacom_driver_page_parser.h
 * @brief Wacom Windows driver公式page parser定義。
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
 * @note Wacom公式pageが明示するWindows x64対応の統合driver情報だけを解析します。本結果はRetail／OEM適用性、内容監査、取得または導入の許可を表しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <string_view>

namespace drivercrate {

/** @brief Wacom公式pageから取得したWindows向け表示専用metadata。 */
struct WacomDriverPageMetadata {
	/// 公式CDN URLが明示したEXE basename。
	std::wstring fileName ;
	/// Page属性、title、file名で一致した配布版。
	std::wstring version ;
	/// Page属性が明示したM/D/YYYY形式の公開日。
	std::wstring releaseDate ;
	/// Page属性が明示したMB単位の概算size。
	std::wstring displaySize ;
	/// Wacom公式CDN上の直接HTTPS URL。取得許可ではない。
	std::wstring downloadUrl ;

	/**
     * @brief 同じ公式pageから得た表示専用metadataを全fieldで比較する。
     * @param[in] other 比較対象のmetadata。
     * @return 全fieldが一致する場合true。
     */
	bool		 operator==( const WacomDriverPageMetadata &other) const = default ;
} ;

/**
 * @brief Wacom Product Resources pageのWindows driver欄を有限規則で解析する。
 * 既知Mustache templateを読み飛ばし、URL、file名、版、OS、size、日付を相互照合する。統合EXEの取得、実行、展開、EULA同意、PnP適用性判定は行わない。
 * @param[in] html Wacom公式hostから取得したUTF-16 HTML。
 * @param[out] metadata 成功時の表示専用metadata。失敗時は初期値。
 * @return Windows x64を含む一意な配布情報が全属性で整合する場合true。 既知template以外のWindows x64配布欄が一件だけ整合する場合true。
 * @note macOS、ARM64単独、旧版、別host、utility、firmwareは候補へ混入させない。
 */
[[nodiscard]] bool parseWacomWindowsDriverPage( std::wstring_view		html,
											   WacomDriverPageMetadata &metadata) ;

} // namespace drivercrate
