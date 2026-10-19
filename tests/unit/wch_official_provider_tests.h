//------------------------------------------------------------------------------
/**
 * @file wch_official_provider_tests.h
 * @brief WCH公式取得とserial共通境界の試験契約。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公開取得の拒否試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 合成metadataとfakeを使い、通信や実driver導入は行わない。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {
class TestContext ;
/**
 * @brief WCH公開metadataと4 familyの同意、local監査、取得上限を検証する。
 * 公開解析、同意、予算、許可ID監査を通信と実導入なしで試験する。
 * @param[in,out] context Assertionの集計先。 全試験のassertion集計先。
 */
void runWchOfficialProviderTests( TestContext &context) ;
} // namespace drivercrate::test
