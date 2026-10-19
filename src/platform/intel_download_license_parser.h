//------------------------------------------------------------------------------
/**
 * @file intel_download_license_parser.h
 * @brief Intel配布pageの非実行許諾snapshot定義。
 * @version 01.02.00
 * @date 2026/09/23
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  制御付き内部coreの必須参照入口を追加。
 * </pre>
 *
 * @note ADR 0129の単一buttonと埋込み許諾本文を結合します。HTMLを実行せず、本文の保持から取得同意や導入許可を発行しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/collector_parser_control.h"

#include <string>
#include <string_view>

namespace drivercrate {
/**
 * @brief Intel公式pageの単一配布buttonと許諾snapshotを結合する。
 * 部分変換を公開せず、同意の状態は一切変更しません。
 * @param[in] html 同じ公式起点から取得した最大2 Mi UTF-16単位のpage。 有限な公式page。
 * @param[in] downloadUrl 系列parserで別途検証済みの対象ZIP URL。 検証済み対象URL。
 * @param[out] revision 成功時の明示許諾名と版。失敗時は空。
 * @param[out] text 成功時のtitle付き完全plain text。失敗時は空。 Titleを含む全文。
 * @return 既知構造を省略なく非実行変換できた場合true。 単一button・modal・許諾の結合成立時true。失敗時は両出力が空。
 * @note 取得元検証、法的条件の確認、同意は呼出側の別工程で行う。
 */
[[nodiscard]] bool parseIntelDownloadLicense( std::wstring_view html, std::wstring_view downloadUrl,
											 std::wstring &revision, std::wstring &text) ;
/**
 * @brief 公開button・空raw欄・既知module参照の実HTML要素を結合します。
 * @param[in] html 有限公式HTML。
 * @param[in] downloadUrl 検証済みの対象配布URL。
 * @param[in] modulePath 固定の公式script相対path。
 * @return 一意な実要素だけで空欄の公開配布構造を確認できた場合true。
 * @note Scriptのhash／HTTP根拠は別途必要です。単独では取得を許可しません。
 */
[[nodiscard]] bool matchesIntelPublicEmptyDownloadLicense( std::wstring_view html,
														  std::wstring_view downloadUrl,
														  std::wstring_view modulePath) ;

/**
 * @brief 同じ許諾coreを使用し、停止・OOMは上位の型付き境界へ伝播します。
 * @param[in] html 同じ公式本文。
 * @param[in] downloadUrl 同じ配布URL。
 * @param[out] revision 許諾識別子。
 * @param[out] text 許諾本文。
 * @param[in,out] context 必須の元制御。
 * @return 許諾非採用はfalse。障害・停止は内部例外です。
 */
[[nodiscard]] bool parseIntelDownloadLicenseForCollector( std::wstring_view html,
														 std::wstring_view downloadUrl,
														 std::wstring &revision, std::wstring &text,
														 CollectorParserContext &context) ;
} // namespace drivercrate
