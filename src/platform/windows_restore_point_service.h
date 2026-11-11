//------------------------------------------------------------------------------
/**
 * @file windows_restore_point_service.h
 * @brief Windows復元ポイントサービス生成定義。
 * @version 01.01.00
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
 * </pre>
 *
 * @note SrClient.dllを動的に使用する復元ポイントサービスを生成します。Windows Server等でAPIを利用できない場合はinstallをfail-closedにします。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/restore_point_service.h"

#include <memory>
#include <functional>
#include <vector>

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

namespace restore_point_detail {
/** @brief Windows一覧の一pointだけの非秘密な読取値です。 */
struct Point {
	/// Windowsが返した番号です。
	std::int64_t sequenceNumber{} ;
	/// 元作成UTC秒です。
	std::int64_t createdUtc{} ;
} ;
/** @brief 同じ読取時点のUTCとWindows local暦日です。 */
struct Clock {
	/// UTC秒です。
	std::int64_t  utc{} ;
	/// YYYYMMDDです。
	std::uint32_t localDay{} ;
} ;
/** @brief 復元サービス内だけの完全依存表。未指定callbackへproduction fallbackしません。 */
struct Calls {
	/// 時刻とlocal日付を読み取ります。
	std::function<Clock()>										  clock ;
	/// Windows一覧を有限読取します。
	std::function<NativeError( std::vector<Point> &)>			  points ;
	/// 実native BEGIN、または完全fakeです。
	std::function<RestorePointOperationResult( std::wstring_view)> begin ;
	/// 実native END、または完全fakeです。
	std::function<RestorePointOperationResult( std::int64_t)>	  end ;
	/// 既保護領域の実排他を所有します。
	std::function<NativeError( std::shared_ptr<void> &)>			  lock ;
	/// 固定一件の非authority memoを読みます。
	std::function<NativeError( RestorePointDayMemo &)>			  loadMemo ;
	/// 正常END後だけ固定memoを保存します。
	std::function<NativeError( const RestorePointDayMemo &)>		  saveMemo ;
} ;
/** @brief 全callbackが明示された内部fixtureだけを生成します。
 * @param[in] calls 完全fake。未指定時は一切実APIを呼ばず拒否します。
 * @return 完全表ならservice、不完全ならnullptrです。
 */
[[nodiscard]] std::unique_ptr<IRestorePointService> createFixture( Calls calls) ;
}

} // namespace drivercrate
