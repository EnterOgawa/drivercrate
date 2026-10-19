//------------------------------------------------------------------------------
/**
 * @file intel_wireless_page_parser.h
 * @brief Intel Wireless公式download page parser定義。
 * @version 01.01.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  本文非保持の任意拒否段階診断を追加。
 * </pre>
 *
 * @note Intel公式download pageの区分B metadataだけを有限規則で取得します。HTML変更、重複、欠落時は候補を推測せず拒否します。
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <cstdint>
#include <string_view>

namespace drivercrate {

/**
 * @brief Intel Wireless公式pageから検証済みとして取得した探索metadataを表す。
 */
struct IntelWirelessPageMetadata {
	/// ZIP file名と紹介文が一致したpackage version。
	std::wstring version ;
	/// Driver-only x64 ZIPのbasename。
	std::wstring fileName ;
	/// Allowlist済みIntel download mirror HTTPS URL。
	std::wstring downloadUrl ;
	/// Pageに表示された概算size。完全性検証には使わない。
	std::wstring displaySize ;
	/// Pageに表示された64桁uppercase SHA-256。
	std::wstring sha256 ;
	/// trueの場合はdownload前に利用者の明示同意が必要。
	bool		 requiresEula{} ;
} ;

/**
 * @brief Intel Wireless IT管理者向けdownload pageを有限schemaとして解析する。
 * Intel Wireless公式download pageを解析する。
 * Page探索結果だけを返し、INF／CAT、PnP適用性、EULA同意を完了済みとして扱わない。
 * @param[in] html Intel公式hostから取得したUTF-16 HTML。
 * @param[out] metadata 成功時の探索metadata。失敗時は空にする。
 * @param[out] failureStage 任意診断。0=成功、1=表示変換、2=見出し、3=範囲、4=配布URL、5=目的、6=hash/size、7=資源。
 * @return 必須section、driver-only x64 ZIP、URL、version、size、SHA-256、EULA表示が一意かつ整合する場合は`true`。 必須
 *         metadataが一意で相互に一致する場合は`true`。
 * @note 本結果は探索区分Bであり、INF／CATと現在deviceの検証を代替しない。
 */
[[nodiscard]] bool parseIntelWirelessDownloadPage( std::wstring_view			 html,
												  IntelWirelessPageMetadata &metadata,
												  std::uint32_t *failureStage = nullptr) ;

} // namespace drivercrate
