//------------------------------------------------------------------------------
/**
 * @file windows_restore_point_service.h
 * @brief Windows復元ポイントサービス生成定義。
 * @version 01.00.00
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note SrClient.dllを動的に使用する復元ポイントサービスを生成します。Windows Server等でAPIを利用できない場合はinstallをfail-closedにします。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/restore_point_service.h"

#include <memory>

namespace drivercrate {

//------------------------------------------------------------------------------
// Windows復元ポイントサービス生成関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 現在のworker COM apartmentでWindows復元ポイントサービスを生成する。
 * Provider COM object生成前に生成し、process-wide COM securityとSystem Restore APIを初期化する。
 * @return 呼出し側が単独所有するサービス。初期化失敗は`begin`の結果として返す。
 * @note Provider COM objectの生成前に呼び出し、process-wide COM securityを設定する。
 */
[[nodiscard]] std::unique_ptr<IRestorePointService> makeWindowsRestorePointService() ;

} // namespace drivercrate
