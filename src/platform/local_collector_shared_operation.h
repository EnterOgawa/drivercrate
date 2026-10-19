//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_operation.h
 * @brief 共有台帳の追加三操作と精算の有限共通契約を定義します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  予約・日次・CACHE参照の共通操作を追加。
 * </pre>
 *
 * @note Caller所有の開発入力です。実時計・公式CACHE・送信許可を検査しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_shared_update.h"
#include <Windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace drivercrate {
/** @brief 予算と開始intentを同じcommitで登録する元予約です。 */
struct CollectorSharedReservation {
	/// 元group／request／generation／jobの完全identity。
	CollectorWaitRequest request ;
	/// 秒境界の元開始UTC millisecond。元JST日と一致させます。
	std::uint64_t		 started{} ;
	/// 一応答の先払い1～8 MiB。実source上限との照合は監督側です。
	std::uint64_t		 maximum{} ;
	/// 同processの新baseline以後の観測経過。旧絶対steadyではありません。
	std::uint64_t		 steadyElapsedMillis{} ;
} ;
/** @brief 全未精算閉鎖後だけ新JST日へ進む固定操作です。 */
struct CollectorSharedDayRoll {
	/// 元accepted UTC millisecond。回復時計で置換しません。
	std::uint64_t accepted{} ;
} ;
/** @brief 元制御・成功時刻を変えない未検証の直接参照置換です。 */
struct CollectorSharedCacheUpdate {
	/// 所属が固定された元group。
	std::wstring								 group ;
	/// 恒久requestの完全hash。
	std::wstring								 requestKey ;
	/// 元accepted UTC millisecond。
	std::uint64_t								 accepted{} ;
	/// 期待する旧参照。根拠なしはnulloptです。
	std::optional<CollectorSharedCacheReference> expected ;
	/// 置換する同現区間の三hash。公式検査済み証明ではありません。
	CollectorSharedCacheReference				 next ;
} ;
/** @brief 固定四型だけの操作です。精算の元schemaを維持します。 */
using CollectorSharedOperation = std::variant<CollectorSharedSettlement, CollectorSharedReservation,
											  CollectorSharedDayRoll, CollectorSharedCacheUpdate> ;
/** @brief 操作から再導出する疎な予算・制御・参照の差分です。 */
struct CollectorSharedOperationDelta {
	/// 元型だけのcanonical操作本文。
	std::string operation ;
	/// 元一予約または日次の有限header。変更なしは空です。
	std::string budgetBefore ;
	/// 新一予約または日次の有限header。変更なしは空です。
	std::string budgetAfter ;
	/// 元最大二制御行。変更なしは空です。
	std::string waitBefore ;
	/// 更新後最大二制御行。変更なしは空です。
	std::string waitAfter ;
	/// 期待した元参照本文。参照以外の操作では空です。
	std::string cacheBefore ;
	/// 置換先参照本文。参照以外の操作では空です。
	std::string cacheAfter ;
} ;
/** @brief 四型の固定schemaを最大4096 byteへ符号化します。
 * @param[in] operation Callerが固定した元操作。
 * @param[out] bytes 成功時だけの元本文。拒否時は空です。
 * @return 成功0、形式13、容量68、確保8。
 */
[[nodiscard]] DWORD encodeCollectorSharedOperation( const CollectorSharedOperation &operation,
												   std::string					  &bytes) noexcept ;
/** @brief 既知schemaだけを全byte一致で復号します。
 * @param[in] bytes 最大4096 byteの元本文。
 * @param[out] operation 全成立時だけの元操作。拒否時は空精算です。
 * @return 成功0、形式13、容量68、確保8。
 */
[[nodiscard]] DWORD decodeCollectorSharedOperation( std::string_view			 bytes,
												   CollectorSharedOperation &operation) noexcept ;
/** @brief 全台帳を検査し元操作から更新後と疎な差分を導出します。
 * @param[in] before 元台帳。入力と出力のaliasは禁止です。
 * @param[in] operation 元予約・日次・参照または精算。
 * @param[out] after 成功時だけの値。失敗時は空です。
 * @param[out] delta 成功時だけの差分。失敗時は空です。
 * @return 成功0、形式13、待機1237、容量68、確保8。
 * @note 保存・実時計・batch／worker監督・公式検査・HTTP許可は行いません。
 */
[[nodiscard]] DWORD deriveCollectorSharedOperation( const CollectorSharedLedgerSnapshot &before,
												   const CollectorSharedOperation	   &operation,
												   CollectorSharedLedgerSnapshot	   &after,
												   CollectorSharedOperationDelta &delta) noexcept ;
} // namespace drivercrate
