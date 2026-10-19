//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_storage_rules.h
 * @brief 収集応答の三保存名と世代別状態の非保存判定を定義します。
 * @version 01.00.00
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  旧応答との排他と新終端の形状検査を追加。
 * </pre>
 *
 * @note 非保存部品です。稼働inventory・root移行・acceptProjectedを有効化しません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace drivercrate {
/** @brief Oに対する全三保存名の存在結果です。 */
enum class CollectorStoredResponseVersion {
	/// 全保存名が存在しません。
	ABSENT,
	/// 応答v2だけが存在します。
	V2,
	/// 応答v3だけが存在します。
	V3,
	/// 応答v4だけが存在します。
	V4,
	/// 二保存名以上が併存します。どれも優先採用しません。
	CONFLICT
} ;

/** @brief 三つ全ての読取り結果から版の排他だけを判定します。
 * @param[in] v2 v2名の存在。
 * @param[in] v3 v3名の存在。
 * @param[in] v4 v4名の存在。
 * @return 単独版、全欠測、または全拒否。Fileを読みません。
 */
[[nodiscard]] CollectorStoredResponseVersion collectorStoredResponseVersion( bool v2, bool v3,
																			bool v4) noexcept ;

/** @brief 検査済みOから有限な相対保存名だけを作ります。
 * @param[in] version V2／V3／V4のいずれか。
 * @param[in] operation 元Oの小文字64桁SHA-256。
 * @return 正しい版とOの場合だけ固定runs配下の名前。それ以外はnullです。
 */
[[nodiscard]] std::optional<std::wstring>	 collectorResponseFileName(
	   CollectorStoredResponseVersion version, std::wstring_view operation) ;

/** @brief 登録世代・応答schema・状態・I/O有無の許可表を検査します。
 * @param[in] storageVersion 元登録の2または3。
 * @param[in] version 保存名とschemaを別途照合した応答版。
 * @param[in] state 元応答の状態名。
 * @param[in] hasObservation I/O objectの存在。内容検査の代用にはしません。
 * @return 許可表に一致する場合true。実保存の許可は発行しません。
 */
[[nodiscard]] bool collectorResponseVersionAllowed( std::uint32_t				  storageVersion,
												   CollectorStoredResponseVersion version,
												   std::wstring_view			  state,
												   bool hasObservation) noexcept ;

/** @brief 新state v3のintentと終端応答の必要形状を検査します。
 * @param[in] state 新世代の状態名。OBSERVEDは拒否します。
 * @param[in] hasIntent 元v3 intentの存在。内容は別途照合します。
 * @param[in] version 応答名の排他結果。非終端はABSENTだけです。
 * @param[in] responseSha256 終端の実応答hash。非終端は空です。
 * @param[in] operation 終端の元O。元G／jobとの同一性は別途検査します。
 * @return 形状が一致する場合true。時刻・理由・intent本文の検査は省略できません。
 */
[[nodiscard]] bool collectorProjectedStateShapeAllowed( std::wstring_view state, bool hasIntent,
													   CollectorStoredResponseVersion version,
													   std::wstring_view responseSha256,
													   std::wstring_view operation) noexcept ;
} // namespace drivercrate
