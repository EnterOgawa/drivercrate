//------------------------------------------------------------------------------
/**
 * @file official_http_transport.h
 * @brief 共通HTTPのOS呼出しとcache I/Oの決定的試験境界。
 * @version 01.02.00
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  非通信fixture用の借用I/O依存を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Record限定targetの全address resolverを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Record限定hopのUTC時計注入境界を追加。
 * </pre>
 *
 * @note ProviderやUIから任意backendを取得せず、既定はWindows APIを使用する。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/official_catalog_cache.h"
#include "platform/official_public_destination.h"

#include <Windows.h>
#include <winhttp.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string_view>

namespace drivercrate {

/** @brief URL・policy検証を含まない低位I/Oだけを同じABIで差し替える。 */
struct OfficialHttpTransport {
	/// Proxy policyを指定したsessionを生成する。
	decltype( &WinHttpOpen)				 open{WinHttpOpen} ;
	/// 検証済みhostへ接続handleを生成する。
	decltype( &WinHttpConnect)			 connect{WinHttpConnect} ;
	/// HTTPS等の固定optionでrequest handleを生成する。
	decltype( &WinHttpOpenRequest)		 openRequest{WinHttpOpenRequest} ;
	/// 四phaseの有限timeoutを設定する。
	decltype( &WinHttpSetTimeouts)		 setTimeouts{WinHttpSetTimeouts} ;
	/// Redirect禁止・auto logon policyを設定する。
	decltype( &WinHttpSetOption)			 setOption{WinHttpSetOption} ;
	/// 検証済みETagと固定Accept headerを設定する。
	decltype( &WinHttpAddRequestHeaders)	 addHeaders{WinHttpAddRequestHeaders} ;
	/// Cost・予算・取消し検証後の実送信境界。
	decltype( &WinHttpSendRequest)		 sendRequest{WinHttpSendRequest} ;
	/// 応答待機の同期API境界。
	decltype( &WinHttpReceiveResponse)	 receiveResponse{WinHttpReceiveResponse} ;
	/// 有限headerの必要長と内容を照会する。
	decltype( &WinHttpQueryHeaders)		 queryHeaders{WinHttpQueryHeaders} ;
	/// 応答の有限chunk読取り量を照会する。
	decltype( &WinHttpQueryDataAvailable) queryAvailable{WinHttpQueryDataAvailable} ;
	/// 指定した上限以内でbufferへ本文を受信する。
	decltype( &WinHttpReadData)			 readData{WinHttpReadData} ;
	/// 同じbackendが生成した所有handleを解放する。
	decltype( &WinHttpCloseHandle)		 closeHandle{WinHttpCloseHandle} ;
	/// Dynamic targetの全IPv4／IPv6 addressをrequest開始前に解決する。
	OfficialDestinationResolver			 resolveDestination{resolveOfficialDestinationWithWindows} ;
	/// 非通信fixtureがrequest／redirect開始直前UTC秒を返す。製品経路では使用しない。
	std::function<std::uint64_t()>		 utcNow ;
} ;

/** @brief 既存cacheの検証済みentry境界を非永続fixtureへ置換する。 */
struct OfficialHttpCacheAccess {
	/** @brief 検証済みcache entryを返す同期callback型。 */
	using LoadFunction = std::function<NativeError( std::wstring_view, std::uint64_t, std::uint64_t,
												   CatalogCacheEntry &)> ;
	/** @brief 有限metadata本文とETagを保存する同期callback型。 */
	using StoreFunction = std::function<NativeError( std::wstring_view, std::span<const std::byte>,
													std::wstring_view)> ;
	/// URL・size・期限を照合したentryを返す。試験はWindows cacheを変更しない。
	LoadFunction						   load ;
	/// 正常受信した有限metadata本文だけを保存する。
	StoreFunction						   store ;
	/// 指定したcache entryだけを破棄する。
	std::function<void( std::wstring_view)> discard ;
} ;

} // namespace drivercrate
