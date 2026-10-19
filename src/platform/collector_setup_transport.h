//------------------------------------------------------------------------------
/**
 * @file collector_setup_transport.h
 * @brief 収集setupだけへ信頼済みOS取得processの実handleを結合します。
 * @version 01.00.01
 * @date 2026/10/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/17 OS固定curlと共通cached-only検証を結合。
 * Ver.01.00.01 Shunji Ogawa  2026/10/17 固定OS curl専用の署名段階を内部試験と共有。
 * </pre>
 *
 * @note PATH・環境・任意caller pathへのfallbackや通信を行いません。
 * @see docs/adr/0357-collector-explicit-run-and-system-transport.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace drivercrate {
/** @brief 子の終了まで同じOS curl実byteを保持する検証結果です。 */
struct CollectorSetupTransport {
	/// OS API起点のSystem32/curl.exe絶対path。
	std::filesystem::path executable ;
	/// 実handleが固定するfile全byteのSHA-256。
	std::wstring		  sha256 ;
	/// 書込みと削除共有を拒否する実file handleの所有権。
	std::shared_ptr<void> file ;
} ;

/** @brief OS curlを実handleと共通cached-only署名検証へ固定します。
 * @return 検証済みpath、実byte hash、子の終了まで保持すべきhandle。
 * @throws std::exception 実API／path／通常file／hash／署名の最初の拒否。
 * @note cache不足やcatalog-only署名は元errorで拒否し、online fallbackしません。
 */
[[nodiscard]] CollectorSetupTransport prepareCollectorSetupTransport() ;

namespace collector_setup_transport_detail {
/** @brief 固定OS curl専用のpublisher policyで共通cached-only署名段階だけを検証します。
 * @param[in] path 実prepareでpath・通常file・hashを検証し、実handleで保持した対象path。
 * @return 成功0、空入力または共通署名検証の最初の元error。
 * @pre 製品呼出側はprepareのfile検証を完了していること。完全fake試験は人工pathを使用します。
 * @note 内部共有契約であり、path／file／hash検証全体や収集開始許可を代替しません。
 *       借用pathを呼出し中だけ参照し、通常署名APIや他packageの許可名を変更しません。
 */
[[nodiscard]] NativeError verifyCachedSystemCurlPublisherStage( std::wstring_view path) ;
} // namespace collector_setup_transport_detail
} // namespace drivercrate
