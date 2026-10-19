//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_update.h
 * @brief 元未精算予約の固定操作と疎な前後値を定義します。
 * @version 01.00.00
 * @date 2026/10/02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  元予約精算・二制御行の非通信再導出を追加。
 * </pre>
 *
 * @note Caller所有の開発用操作です。公式応答・通信許可・予約・CACHE更新ではありません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_shared_ledger.h"
#include <Windows.h>
#include <cstdint>
#include <string>
#include <string_view>

namespace drivercrate {
/** @brief 元予約を受領または明示中断で一回だけ閉じる固定入力です。 */
struct CollectorSharedSettlement {
	/// 元group／request／generation／jobの完全identity。
	CollectorWaitRequest	 request ;
	/// 元予約開始UTC millisecond。予約秒へ完全一致します。
	std::uint64_t			 started{} ;
	/// 元応答または中断の完了UTC millisecond。
	std::uint64_t			 finished{} ;
	/// 元の親受領UTC millisecond。回復時刻へ置換しません。
	std::uint64_t			 accepted{} ;
	/// Callerが固定した待機観測。公式応答の検査済み証明ではありません。
	CollectorWaitObservation observation ;
	/// 実受信量が観測済みの場合true。
	bool					 bytesKnown{} ;
	/// 既知の元受信量。未知時は0の表現ですがmaximumを課金します。
	std::uint64_t			 receivedBytes{} ;
	/// 応答なしの明示中断ならtrue。既知byte・HTTP観測を持ちません。
	bool					 interrupted{} ;
} ;
/** @brief 元操作からだけ再計算した一予約と二制御行の前後本文です。 */
struct CollectorSharedSettlementDelta {
	/// 固定schemaの元操作本文。
	std::string operation ;
	/// 元一予約だけを持つcanonical予算本文。
	std::string budgetBefore ;
	/// 同じ一予約を精算したcanonical予算本文。
	std::string budgetAfter ;
	/// 元group／request二行だけのcanonical制御本文。
	std::string waitBefore ;
	/// 元観測から精算した同じ二行のcanonical制御本文。
	std::string waitAfter ;
} ;
/** @brief 有限固定操作の型・時刻・観測を検査して符号化します。
 * @param[in] operation Caller所有の元操作。
 * @param[out] bytes 成功時の4096 byte以下の本文。拒否時は空です。
 * @return 成功0、形式13、容量68、確保失敗8。
 * @note 元予約との関係はderiveで別に検査します。
 */
[[nodiscard]] DWORD encodeCollectorSharedSettlement( const CollectorSharedSettlement &operation,
													std::string &bytes) noexcept ;
/** @brief 固定field順の全byteを消費し元操作を復号します。
 * @param[in] bytes 最大4096 byteの元本文。
 * @param[out] operation 成功時だけの値。失敗時は空です。
 * @return 成功0、形式13、容量68、確保失敗8。
 */
[[nodiscard]] DWORD decodeCollectorSharedSettlement( std::string_view		   bytes,
													CollectorSharedSettlement &operation) noexcept ;
/** @brief 元予約phase0と開始intentから精算後台帳と疎な差分を再導出します。
 * @param[in] before 元台帳。入力と出力のaliasを禁止します。
 * @param[in] operation 元受領または明示中断の固定操作。
 * @param[out] after 成功時だけの台帳。拒否時は空です。
 * @param[out] delta 成功時だけの一予約／二制御行の前後像。拒否時は空です。
 * @return 成功0、関係13、容量68、確保失敗8。
 * @note 他行・CACHE・元日を保持します。保存・通信・公式性の検査は行いません。
 */
[[nodiscard]] DWORD deriveCollectorSharedSettlement( const CollectorSharedLedgerSnapshot &before,
													const CollectorSharedSettlement		&operation,
													CollectorSharedLedgerSnapshot		&after,
													CollectorSharedSettlementDelta &delta) noexcept ;
} // namespace drivercrate
