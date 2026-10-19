//------------------------------------------------------------------------------
/**
 * @file official_public_destination.h
 * @brief Record限定HTTP targetのDNS名と全addressをpublic宛先へ限定します。
 * @version 01.00.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  DNSの全IPv4／IPv6宛先をpublic範囲へ限定。
 * </pre>
 *
 * @note HostとIP addressはworker内の検証中だけ所有し、成功結果には件数だけを返します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief Name resolverが返したIP address familyを表します。
 */
enum class OfficialNetworkAddressFamily {
	/// 4 byteのnetwork byte order IPv4 addressです。
	IPV4,
	/// 16 byteのnetwork byte order IPv6 addressです。
	IPV6,
} ;

/**
 * @brief 秘密hostの取得前検証にだけ使う一つのresolved addressです。
 */
struct OfficialResolvedNetworkAddress {
	/// Address byte列の解釈に使うfamily。
	OfficialNetworkAddressFamily family{OfficialNetworkAddressFamily::IPV4} ;
	/// Network byte orderの4または16 byte。未使用領域は0です。
	std::array<std::byte, 16>	 bytes{} ;
} ;

/**
 * @brief 秘密hostを受け取得前の全addressを返すresolverです。
 * @param[in] host ASCII DNS host。保存・表示・記録してはなりません。
 * @param[out] addresses 成功時の全1件以上64件以下のaddress。失敗時は空です。
 * @return 解決成功時は0、失敗時はHRESULT bit pattern。
 */
using OfficialDestinationResolver = std::function<NativeError(
	std::wstring_view host, std::vector<OfficialResolvedNetworkAddress> &addresses)> ;

/**
 * @brief 全address検証のURL非保持結果です。
 */
struct OfficialPublicDestinationEvidence {
	/// 成功時に検証したIPv4／IPv6 addressの合計件数。
	std::uint32_t addressCount{} ;
	/// Local resolverが返した全addressを検証した場合true。
	bool		  locallyResolved{} ;
} ;

/**
 * @brief 一つのresolved addressがpublic global unicast範囲に限定されるか判定します。
 * @param[in] address Network byte orderのIPv4またはIPv6 address。
 * @return Loopback、private、link-local、multicast、unspecified、予約／文書用を除く場合true。
 */
[[nodiscard]] bool isPublicOfficialNetworkAddress(
	const OfficialResolvedNetworkAddress &address) noexcept ;

/**
 * @brief Dynamic targetのASCII DNS hostとresolverが返す全addressを検証します。
 * @param[in] host 一文字以上253文字以下の秘密ASCII DNS host。
 * @param[in] resolver 通信前に呼ぶ完全なname resolver。
 * @param[out] evidence 成功時にだけ件数とlocal検証済みを返す非機密結果。
 * @return Host構文と全addressがpublicなら0、それ以外はHRESULT bit pattern。
 * @note IP literal、単一label、`localhost`、`.local`、`.internal`をresolver呼出し前に拒否します。
 */
[[nodiscard]] NativeError validatePublicOfficialDestination(
	std::wstring_view host, const OfficialDestinationResolver &resolver,
	OfficialPublicDestinationEvidence &evidence) noexcept ;

/**
 * @brief Windows Unicode name resolverで全IPv4／IPv6 addressを取得します。
 * @param[in] host 検証済みASCII DNS host。
 * @param[out] addresses 成功時の全address。失敗時は空です。
 * @return 1件以上64件以下の解決成功時は0、Winsock失敗または不正結果はHRESULT bit pattern。
 * @note `WSAStartup`／`WSACleanup`と`FreeAddrInfoW`は本関数内で対称に終了します。
 */
[[nodiscard]] NativeError resolveOfficialDestinationWithWindows(
	std::wstring_view host, std::vector<OfficialResolvedNetworkAddress> &addresses) noexcept ;

} // namespace drivercrate
