//------------------------------------------------------------------------------
/**
 * @file official_collector_dns.cpp
 * @brief 有限GetAddrInfoExWと所有者解放を実装します。
 * @version 01.00.01
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
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 台帳・公式parser・導入処理は実行しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#include "platform/official_collector_dns.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>

namespace drivercrate {
namespace {
/** @brief ListとWinsock参照を所有者threadで一度だけ解放します。 */
class ResolverOwner final {
public:
	/** @brief 成功WSAStartupの参照を引き取ります。
	 * @param[in] api 同scopeより長い完全依存。
	 * @param[in,out] control 同scopeより長い制御。
	 */
	ResolverOwner( const OfficialCollectorDnsApi &api, OfficialCollectorHttpControl &control)
		: api_( api), control_( control)
	{
		control_.setNativeReleased( false) ;
	}
	/** @brief Listを先に解放し、cleanupの原診断を残します。 */
	~ResolverOwner()
	{
		// 失敗APIが返したlistも捨てずに同じ解放関数へ渡す。
		if( result != nullptr) {
			api_.freeResult( result) ;
		}

		const int error = api_.cleanup() ;	// 所有WSA参照の解放結果。
		// 原WSA errorを他のAPIより先に観測する。
		if( error != 0) {
			const int native = api_.lastError() ;	// Cleanup直後の原値。
			control_.fail( CollectorIoCause::SETUP,
						  {CollectorIoErrorDomain::WINSOCK_ERROR,
						   static_cast<std::uint32_t>( native), CollectorIoStage::CLEANUP},
						  false) ;
		}

		control_.setNativeReleased( error == 0) ;
	}
	/**
	 * @brief DNS結果listとWinsock参照の解放責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	ResolverOwner( const ResolverOwner &) = delete ;
	/**
	 * @brief DNS結果listとWinsock参照の解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	ResolverOwner &operator=( const ResolverOwner &) = delete ;
	/// 同期APIが返すlist。Destructorが解放します。
	PADDRINFOEXW   result{} ;

private:
	/// Scope中不変のAPI表。
	const OfficialCollectorDnsApi &api_ ;
	/// 結果の借用先。
	OfficialCollectorHttpControl  &control_ ;
} ;
} // namespace

/** @see official_collector_dns.h */
OfficialCollectorDnsApi nativeCollectorDnsApi() noexcept
{
	return {WSAStartup, GetAddrInfoExW, FreeAddrInfoExW, WSACleanup, WSAGetLastError} ;
}
/** @see official_collector_dns.h */
NativeError collectorControlError( const OfficialCollectorHttpControl &control)
{
	const auto error = control.snapshot().error ;	// 原値を壊さない戻り値射影。
	// HRESULTは下位Win32 codeへ取り直さない。
	if( error.domain == CollectorIoErrorDomain::HRESULT_ERROR) {
		return error.code ;
	}

	// HTTP statusをWin32 codeと混同しない。
	if( error.domain == CollectorIoErrorDomain::HTTP) {
		return 0x80190000U | error.code ;
	}

	return error.code != 0U ? static_cast<NativeError>( HRESULT_FROM_WIN32( error.code))
							: static_cast<NativeError>( E_ABORT) ;
}
/** @see official_collector_dns.h */
NativeError resolveCollectorPublicDestination( std::wstring_view					 host,
											  OfficialCollectorHttpControl		&control,
											  const OfficialCollectorDnsApi		&api,
											  OfficialPublicDestinationEvidence &evidence) noexcept
{
	evidence = {} ;
	// Fake依存の欠損をWindows関数へ補完しない。
	if( !api.startup || !api.resolve || !api.freeResult || !api.cleanup || !api.lastError) {
		control.fail(
			CollectorIoCause::SETUP,
			{CollectorIoErrorDomain::PARSER, ERROR_INVALID_PARAMETER, CollectorIoStage::DNS},
			false) ;
		return collectorControlError( control) ;
	}

	try {
		// 共通host構文・全address検証へ同じ有限resolverを渡す。Captureは同期呼出し中だけ借用する。
		const auto resolver =
			[&]( std::wstring_view							 name,
				std::vector<OfficialResolvedNetworkAddress> &addresses) -> NativeError {
			addresses.clear() ;
			// 予約期限または取消し後はWSA参照さえ追加しない。
			if( control.begin( CollectorIoStage::DNS, 15000U) == 0U) {
				return collectorControlError( control) ;
			}

			WSADATA	  data{} ;											// Scope内のWinsock version結果。
			const int startup = api.startup( MAKEWORD( 2, 2), &data) ;	// 原Winsock code。
			// 参照を得なかった場合はcleanupしない。
			if( startup != 0) {
				control.fail( CollectorIoCause::DNS,
							 {CollectorIoErrorDomain::WINSOCK_ERROR,
							  static_cast<std::uint32_t>( startup), CollectorIoStage::DNS},
							 false) ;
				return collectorControlError( control) ;
			}

			ResolverOwner	   owner( api, control) ;	// Listを参照より先に解放する。
			const std::wstring ownedName( name) ;		// 同期API復帰まで保持するNUL終端host。
			ADDRINFOEXW		   hints{} ;				// 全IPv4／IPv6のTCP候補。
			hints.ai_family		 = AF_UNSPEC ;
			hints.ai_socktype	 = SOCK_STREAM ;
			hints.ai_protocol	 = IPPROTO_TCP ;
			const auto remaining = control.begin( CollectorIoStage::DNS, 15000U) ;	// 直前の残ms。
			// 0 timeoutによる無制限解決を禁止する。
			if( remaining == 0U) {
				return collectorControlError( control) ;
			}

			timeval timeout{} ;	// 秒・microsecondの明示変換。
			timeout.tv_sec	= static_cast<long>( remaining / 1000U) ;
			timeout.tv_usec = static_cast<long>( (remaining % 1000U) * 1000U) ;
			const int error =
				api.resolve( ownedName.c_str(), L"443", NS_DNS, nullptr, &hints, &owner.result,
							&timeout, nullptr, nullptr, nullptr) ;	// 同期解決の原code。
			// Native失敗を後続clock観測で置換しない。
			if( error != 0) {
				control.fail( CollectorIoCause::DNS,
							 {CollectorIoErrorDomain::WINSOCK_ERROR,
							  static_cast<std::uint32_t>( error), CollectorIoStage::DNS},
							 false) ;
				return collectorControlError( control) ;
			}

			// 解決中の取消し後に結果をHTTPへ引き渡さない。
			if( control.begin( CollectorIoStage::DNS, 15000U) == 0U) {
				return collectorControlError( control) ;
			}

			// 最大64件ですべて検査し、未知familyや65件目を部分成功にしない。
			for( auto *entry = owner.result; entry != nullptr; entry = entry->ai_next) {
				// 循環listも有限件数で拒否する。
				if( addresses.size() == 64U || entry->ai_addr == nullptr) {
					return static_cast<NativeError>( E_ACCESSDENIED) ;
				}

				OfficialResolvedNetworkAddress address{} ;	// 共通public判定用のowned byte列。
				// Familyと実sockaddr長が整合するIPv4だけコピーする。
				if( entry->ai_family == AF_INET && entry->ai_addrlen >= sizeof( sockaddr_in) &&
				   entry->ai_addr->sa_family == AF_INET) {
					address.family = OfficialNetworkAddressFamily::IPV4 ;
					// Winsock境界の型付きsockaddrをnetwork byte列へコピーする。
					std::memcpy( address.bytes.data(),
								&reinterpret_cast<const sockaddr_in *>( entry->ai_addr)->sin_addr,
								4U) ;
				} else {
					// IPv4でない結果は、完全なIPv6でなければ部分成功にしない。
					if( entry->ai_family != AF_INET6 || entry->ai_addrlen < sizeof( sockaddr_in6) ||
					   entry->ai_addr->sa_family != AF_INET6) {
						return static_cast<NativeError>( E_ACCESSDENIED) ;
					}

					address.family = OfficialNetworkAddressFamily::IPV6 ;
					// Winsock境界以外へsockaddr pointerを持ち出さない。
					std::memcpy( address.bytes.data(),
								&reinterpret_cast<const sockaddr_in6 *>( entry->ai_addr)->sin6_addr,
								16U) ;
				}

				addresses.push_back( address) ;
			}

			return addresses.empty() ? static_cast<NativeError>( E_ACCESSDENIED) : 0U ;
		} ;
		const auto error =
			// 共通判定。
			validatePublicOfficialDestination( host, resolver, evidence) ;
		// 原API値がなければpublic宛先拒否の型付き診断を付ける。
		if( error != 0U && control.snapshot().cause == CollectorIoCause::NONE) {
			control.fail(
				CollectorIoCause::DNS,
				{CollectorIoErrorDomain::PARSER, ERROR_ACCESS_DENIED, CollectorIoStage::DNS},
				false) ;
		}

		// Cleanup失敗・解放中の期限も成功へ読み替えない。
		if( control.begin( CollectorIoStage::DNS, 15000U) == 0U) {
			evidence = {} ;
			return collectorControlError( control) ;
		}

		return 0U ;
	} catch( ...) {
		control.fail( CollectorIoCause::SETUP,
					 {CollectorIoErrorDomain::HRESULT_ERROR, static_cast<std::uint32_t>( E_FAIL),
					  CollectorIoStage::DNS},
					 false) ;
		evidence = {} ;
		return collectorControlError( control) ;
	}
}
} // namespace drivercrate
