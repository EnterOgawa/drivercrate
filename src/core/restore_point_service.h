//------------------------------------------------------------------------------
/**
 * @file restore_point_service.h
 * @brief 復元ポイントサービス契約定義。
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
 * @note Driver変更を保護するWindows復元ポイント操作を抽象化します。unit testは本契約のfakeを使用し、実端末の復元ポイントを変更しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// 復元ポイントサービス型定義。
//------------------------------------------------------------------------------

/**
 * @brief 一連のdriver変更を囲むWindows復元ポイント操作を提供する。
 *
 * @note 実装はProviderと同じ専用worker threadから直列に呼び出される。
 */
class IRestorePointService {
public:
	/**
     * @brief 実装が所有するWindows resourceを解放する。
     */
	virtual ~IRestorePointService() = default ;

	/**
     * @brief system変更直前に復元ポイントを開始する。
     * @param[in] description Windowsの復元UIへ表示する説明。呼出し中だけ有効である。
     * @return 開始結果と、成功時は後続の`complete`へ渡すsequence number。
     */
	[[nodiscard]] virtual RestorePointOperationResult begin(
		std::wstring_view description) noexcept = 0 ;

	/**
     * @brief 開始済みの復元ポイントへsystem変更完了を通知する。
     * @param[in] sequenceNumber `begin`が成功時に返した識別番号。
     * @return 終了結果。失敗時も既に行われたdriver変更は取り消さない。
     */
	[[nodiscard]] virtual RestorePointOperationResult complete(
		std::int64_t sequenceNumber) noexcept = 0 ;
} ;

} // namespace drivercrate
