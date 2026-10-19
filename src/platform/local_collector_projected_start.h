//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_start.h
 * @brief 新収集世代へ結合する開始intentの非保存codecを定義します。
 * @version 01.00.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  input／scope／response version結合を追加。
 * </pre>
 *
 * @note 復号は予約・送信許可を発行しません。元processの単調時刻を保持します。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include <string>
#include <string_view>

namespace drivercrate {
struct CollectorProjectedCampaignIdentity ;
struct CollectorRecoveryDispatch ;

/** @brief 全inputを再構築して射影専用の開始intentを符号化します。
 * @param[in] identity 登録予定inputの実byteと世代hash。
 * @param[in] dispatch 元予約の所有値。PROJECTEDだけを認めます。
 * @param[out] body 成功時だけのcanonical UTF-8。失敗時は空です。
 * @return 元job・scope・二時計と120秒上限の一致時true。
 * @note 日次／batchの最小期限と永続予約は呼出し側で別途検証します。
 */
[[nodiscard]] bool encodeCollectorProjectedStart( const CollectorProjectedCampaignIdentity &identity,
												 const CollectorRecoveryDispatch		  &dispatch,
												 std::string							  &body) ;

/** @brief 保存intentから元入力へ結合したdispatchを復号します。
 * @param[in] identity 検査対象のinput実byteと世代hash。
 * @param[in] body 最大4 KiBのcanonical本文。
 * @param[out] dispatch 全照合後だけ返す値。失敗時は空です。
 * @return 全再符号化とbyte一致が成立する場合true。
 * @note 保存された単調時計を新processの期限や再送許可として使用しません。
 */
[[nodiscard]] bool parseCollectorProjectedStart( const CollectorProjectedCampaignIdentity &identity,
												std::string_view						  body,
												CollectorRecoveryDispatch				 &dispatch) ;
} // namespace drivercrate
