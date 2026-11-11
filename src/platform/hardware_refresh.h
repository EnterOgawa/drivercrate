//------------------------------------------------------------------------------
/**
 * @file hardware_refresh.h
 * @brief 通常検索前のWindowsハードウェア再検出と非機密結果を定義します。
 * @version 01.00.01
 * @date 2026/10/28
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/28  検索前再検出の結果と一時権限境界を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note 再検出成功は全deviceの開始やdriver導入完了の保証ではありません。
 * @see docs/adr/0419-hardware-refresh-before-update-search.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"

namespace drivercrate {
/** @brief 再検出で元の診断値が発行されたAPI領域です。 */
enum class HardwareRefreshErrorDomain {
	/// 成功でerrorを持たない状態です。
	NONE,
	/// Token/権限APIのGetLastError値です。
	WINDOWS_ERROR,
	/// CfgMgr32の元CONFIGRET値です。
	CONFIGURATION_MANAGER,
	/// Callback例外や不完全な内部依存のHRESULTです。
	HRESULT_VALUE,
} ;
/** @brief 再検出が到達した最後の段階です。 */
enum class HardwareRefreshStage {
	/// Process tokenを開く段階です。
	OPEN_TOKEN,
	/// 既存SeLoadDriverPrivilegeを一時有効化する段階です。
	ENABLE_PRIVILEGE,
	/// 現在のlocal rootを照会する段階です。
	LOCATE_ROOT,
	/// Root以下へ同期再検出を一回要求する段階です。
	REENUMERATE,
	/// 保存した権限属性へ復帰する段階です。
	RESTORE_PRIVILEGE,
} ;
/** @brief 操作に結合する非機密の再検出結果です。生IDやHANDLEは含みません。 */
struct HardwareRefreshResult {
	/// 一回の同期再検出と必要な権限復帰がともに成功した場合だけtrueです。
	bool					   succeeded{} ;
	/// 主結果が発生した段階です。
	HardwareRefreshStage	   stage{HardwareRefreshStage::OPEN_TOKEN} ;
	/// Errorの元領域です。
	HardwareRefreshErrorDomain domain{HardwareRefreshErrorDomain::NONE} ;
	/// 元CONFIGRET/Win32/HRESULT。成功では0です。
	NativeError				   error{} ;
	/// 主失敗と独立した権限復帰のWin32 error。成功では0です。
	NativeError				   restoreError{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 既存token権限を一時使用し、local rootの同期再検出を一回実行します。
 * @return 元error領域・値と権限復帰結果。失敗時の自動retryはありません。
 * @note Blocking処理です。Productionの通常検索workerからだけ呼び、UIから呼びません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HardwareRefreshResult refreshHardware() noexcept ;
} // namespace drivercrate
