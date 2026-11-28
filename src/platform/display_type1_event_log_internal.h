//------------------------------------------------------------------------------
/**
 * @file display_type1_event_log_internal.h
 * @brief DisplayのType 1実行記録を同じWindowsチャネルの前後で読み取る
 * @version 01.01.00
 * @date 2026/11/27
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/27  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/27  変更前の元境界で取得した結果を事後照合へ接続
 * </pre>
 *
 * @note 境界と記録は同じ導入のworker内で使い、機器IDや元コマンドを保存・表示しない
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_types.h"
#include "platform/display_inf_scope_internal.h"
#include <cstdint>
#include <string>
#include <vector>

namespace drivercrate {
/** @brief 固定チャネルに存在した境界記録と、同じ記録へのWindowsブックマーク */
struct DisplayType1EventBoundary {
	/// 同じチャネル内のEventRecordID。0は境界未取得
	std::uint64_t record{} ;
	/// 記録の生成UTCを100ns単位のWindows FILETIMEで保持
	std::uint64_t created{} ;
	/// 同じチャネルの作成UTCを100ns単位のWindows FILETIMEで保持
	std::uint64_t logCreated{} ;
	/// その記録を発行したWindowsプロセス番号。元欄欠損時は0
	std::uint32_t process{} ;
	/// その記録を発行したWindowsスレッド番号。元欄欠損時は0
	std::uint32_t thread{} ;
	/// 同じチャネル内のイベント定義番号
	std::uint16_t eventId{} ;
	/// 同じイベントのスキーマ版
	std::uint8_t  version{} ;
	/// Windowsが実記録から生成したXML。導入worker内だけに保持
	std::wstring  bookmarkXml ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 変更前の固定チャネルの最後の記録を、一つの実在する境界として採取する
 * @param[out] boundary 成功時に境界の値を所有する。欠損・拒否時は空
 * @return 境界採取成功時0、イベントログAPIまたは形式の失敗はHRESULT
 * @note ローカル読取りを同じworkerで完結し、チャネルやドライバーを変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError captureDisplayType1EventBoundary(
	DisplayType1EventBoundary &boundary) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 変更前の記録より後で、読取り開始時の上限までの固定イベントを読む
 * @param[in] before 同じ操作の変更前に採取した実在する境界を同期中だけ借用する
 * @param[out] events 成功時に対象記録を昇順で所有する。欠損・拒否時は空
 * @return 同じチャネルの前後境界と全区間を検証した場合0、APIまたは形式の失敗はHRESULT
 * @note 対象記録の空は検証済みの区間でのみ成功。導入結果の照合は呼出し元の責務
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDisplayType1InstallEvents(
	const DisplayType1EventBoundary		  &before,
	std::vector<DisplayType1InstallEvent> &events) noexcept ;

/** @brief 同じ導入の元境界を検証してイベントを所有値として返す同期読取り */
using DisplayType1EventRead = NativeError ( *)( const DisplayType1EventBoundary &,
											  std::vector<DisplayType1InstallEvent> &) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ導入の元境界と確認済みの子から実行・反映を一度だけ観測する
 * @param[in] before 変更前に採取した同じ操作の元境界
 * @param[in] observation 確認した元宣言、登録済み実行物と子の事後状態
 * @param[in] readEvents 元境界以降を読む同期関数。通常は固定Windowsチャネルを使う
 * @return 照合した事後状態。取得不能時は未確認と元診断
 * @note 境界と取得の完全性は読取りの結果から定め、実行や再試行は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] DisplayType1InstallResult observeDisplayType1InstallEvents(
	const DisplayType1EventBoundary &before, DisplayType1InstallObservation observation,
	DisplayType1EventRead readEvents = &readDisplayType1InstallEvents) noexcept ;
} // namespace drivercrate
