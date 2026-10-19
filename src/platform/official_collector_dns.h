//------------------------------------------------------------------------------
/**
 * @file official_collector_dns.h
 * @brief 収集専用の有限同期DNSと完全なAPI依存表です。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  有限DNS・共通HTTP制御接続を追加。
 * </pre>
 *
 * @note 台帳・公式parser・導入処理は実行しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>

#include "platform/official_collector_http_control.h"
#include "platform/official_public_destination.h"

namespace drivercrate {
/** @brief 全関数を明示して使うDNS依存です。欠損をnativeで補完しません。 */
struct OfficialCollectorDnsApi {
	/// Winsock参照の取得。
	decltype( &WSAStartup)	   startup{} ;
	/// 有限timeout付き同期解決。
	decltype( &GetAddrInfoExW)  resolve{} ;
	/// 結果listを同じ所有者で解放。
	decltype( &FreeAddrInfoExW) freeResult{} ;
	/// Winsock参照の解放。
	decltype( &WSACleanup)	   cleanup{} ;
	/// Cleanup失敗直後のWinsock error。
	decltype( &WSAGetLastError) lastError{} ;
} ;
/** @brief 明示native用の完全な不変依存を作ります。
 * @return 同期Windows API表。通信はまだ行いません。
 */
[[nodiscard]] OfficialCollectorDnsApi nativeCollectorDnsApi() noexcept ;
/** @brief 既存の全public宛先検査を有限DNSへ接続します。
 * @param[in] host 公式URLからのDNS名。保存しません。
 * @param[in,out] control claim済みのworker制御。終了確定は呼出し側。
 * @param[in] api 完全な同期依存表。関数は例外を投げません。
 * @param[out] evidence 成功時だけ全address件数。失敗時は空。
 * @return 成功0、拒否はHRESULT bit pattern。原Winsock値はcontrolに保持します。
 */
[[nodiscard]] NativeError			  resolveCollectorPublicDestination(
				std::wstring_view host, OfficialCollectorHttpControl &control,
				const OfficialCollectorDnsApi &api, OfficialPublicDestinationEvidence &evidence) noexcept ;
/** @brief 固定観測の終端errorを旧API互換HRESULTへ射影します。
 * @param[in] control 観測元。原値自体は変更しません。
 * @return 元HRESULT、またはdomain付きcodeからのHRESULT。未終端はE_ABORT。
 */
[[nodiscard]] NativeError collectorControlError( const OfficialCollectorHttpControl &control) ;
} // namespace drivercrate
