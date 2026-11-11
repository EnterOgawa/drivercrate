//------------------------------------------------------------------------------
/**
 * @file restore_point_service.h
 * @brief 復元ポイントサービス契約定義。
 * @version 01.01.01
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
 * Ver.01.01.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続。
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
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
     * @brief system変更直前に実在保護を準備し、同日のpoint再利用を区別する。
     * @param[in] description Windowsの復元UIへ表示する説明。呼出し中だけ有効である。
     * @return 実native開始結果、または再利用時のNOT_STARTED。保護成立はprotectionで確認する。
     * @note 返されたsequenceをcompleteへ渡しscopeを閉じる。再利用ではnative BEGINを呼ばない。
     */
	[[nodiscard]] virtual RestorePointOperationResult begin(
		std::wstring_view description) noexcept = 0 ;

	/**
     * @brief 保護scopeの実在を再確認し、native BEGIN所有時だけENDを通知する。
     * @param[in] sequenceNumber `begin`が保護scopeへ結合した識別番号。
     * @return 終了結果。失敗時も既に行われたdriver変更は取り消さない。
     */
	[[nodiscard]] virtual RestorePointOperationResult complete(
		std::int64_t sequenceNumber) noexcept = 0 ;
	/**
	 * @brief 最後の同service保護scopeの読取事実を返します。
	 * @return 実在/再利用/保存診断。既存実装の欠測は保護未成立として返します。
	 * @note Windows実装は必ず実在確認を返し、不完全fixtureをproductionへfallbackしません。
	 */
	[[nodiscard]] virtual RestorePointProtectionResult protection() const noexcept
	{
		return {.disposition  = RestorePointDisposition::UNAVAILABLE,
				.verification = OutcomeCode::FAILURE,
				.error		  = static_cast<NativeError>( 0x80004001U)} ;
	}
} ;

} // namespace drivercrate
