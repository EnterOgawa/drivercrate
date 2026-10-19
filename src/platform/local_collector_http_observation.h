//------------------------------------------------------------------------------
/**
 * @file local_collector_http_observation.h
 * @brief 固定I/O観測の厳密codecを定義します。
 * @version 01.00.00
 * @date 2026/09/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  応答v3・所有worker回収を追加。
 * </pre>
 *
 * @note 開発用の有限収集に限定し、製品の取得・導入を許可しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "official_collector_http_control.h"
#include <string>
#include <string_view>

namespace drivercrate {
/** @brief 固定I/O objectを4 KiB以内でcanonical保存します。
 * @param[in] observation 元workerの観測。Finished／基本結果は外側応答で検証します。
 * @param[in] permit 元G／jobから導出した小文字SHA-256。
 * @param[out] bytes 成功時だけcanonical UTF-8。失敗時は空です。
 * @return 型・有限値・既知enumを検証した場合true。
 */
[[nodiscard]] bool encodeCollectorHttpObservation( const CollectorIoSnapshot &observation,
												  std::wstring_view permit, std::string &bytes) ;
/** @brief 固定field集合とcanonical byteを照合して観測を復号します。
 * @param[in] bytes 最大4 KiBのcanonical UTF-8。
 * @param[in] permit 呼出し側が導出した元permit key。
 * @param[out] observation 成功時だけ固定I/O観測。外側fieldは呼出し側が再結合します。
 * @return 改変・未知field・型不一致がない場合true。
 */
[[nodiscard]] bool decodeCollectorHttpObservation( std::string_view bytes, std::wstring_view permit,
												  CollectorIoSnapshot &observation) ;
} // namespace drivercrate
