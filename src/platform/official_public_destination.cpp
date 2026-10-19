//------------------------------------------------------------------------------
/**
 * @file official_public_destination.cpp
 * @brief Record限定HTTP targetのDNS名と全addressをpublic宛先へ限定します。
 * @version 01.00.01
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
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Native resolverはworker threadで同期実行します。Hostとaddressは宛先検証中だけ保持します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/official_public_destination.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <utility>

namespace drivercrate {
namespace {

constexpr std::size_t MAXIMUM_RESOLVED_ADDRESSES   = 64U ;	// 一hostで検証するDNS結果上限。
constexpr std::size_t MAXIMUM_DNS_HOST_CHARACTERS  = 253U ;	// 末尾dotを含まないDNS名上限。
constexpr std::size_t MAXIMUM_DNS_LABEL_CHARACTERS = 63U ;	// 一つのDNS label上限。

/**
 * @brief 成功した`WSAStartup`をscope終了時に対称解放します。
 */
class WinsockScope	  final {
public:
	   /**
	 * @brief Winsock 2.2の利用を開始します。
	 */
	   WinsockScope() noexcept
	   {
		   WSADATA data{} ;	// WSAStartupが返すversion情報。
		   result_ = WSAStartup( MAKEWORD( 2, 2), &data) ;
	   }

	   /**
	 * @brief 開始成功時だけWinsock参照を解放します。
	 */
	   ~WinsockScope() noexcept
	   {
		   // 取得していないWinsock参照を減らさない。
		   if( result_ == 0) {
			   static_cast<void>( WSACleanup()) ;
		   }
	   }

	   /**
	    * @brief WSAStartupに対応する参照の解放責務の二重管理を防ぐため、コピー構築を禁止する。
	    */
	   WinsockScope( const WinsockScope &) = delete ;
	   /**
	    * @brief WSAStartupに対応する参照の解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	    */
	   WinsockScope &operator=( const WinsockScope &) = delete ;
	   /**
	    * @brief WSAStartupに対応する参照の解放責務を元のWinsock scopeに留めるため、移動構築を禁止する。
	    */
	   WinsockScope( WinsockScope &&) = delete ;
	   /**
	    * @brief 元のWinsock scopeへの結合を保つため、移動代入による管理状態の置換を禁止する。
	    */
	   WinsockScope		&operator=( WinsockScope &&) = delete ;

	   /**
	 * @brief `WSAStartup`の診断値を返します。
	 * @return 成功は0、失敗はWindows Sockets error。
	 */
	   [[nodiscard]] int result() const noexcept
	   {
		   return result_ ;
	   }

private:
	   /// `WSAStartup`が返した0またはWindows Sockets error。
	   int result_{} ;
} ;

/**
 * @brief `GetAddrInfoW`が返したlinked listを所有します。
 */
class AddressInfoScope final {
public:
	/**
	 * @brief Address list所有権を引き取ります。
	 * @param[in] value `GetAddrInfoW`が返したnull可能pointer。
	 */
	explicit AddressInfoScope( PADDRINFOW value) noexcept : value_( value)
	{
	}

	/**
	 * @brief 所有中のaddress listを一回解放します。
	 */
	~AddressInfoScope() noexcept
	{
		// Null listをWinsock解放APIへ渡さない。
		if( value_ != nullptr) {
			FreeAddrInfoW( value_) ;
		}
	}

	/**
	 * @brief address listの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	AddressInfoScope( const AddressInfoScope &) = delete ;
	/**
	 * @brief address listの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	AddressInfoScope &operator=( const AddressInfoScope &) = delete ;
	/**
	 * @brief address listの解放責務を元のaddress list ownerに留めるため、移動構築を禁止する。
	 */
	AddressInfoScope( AddressInfoScope &&) = delete ;
	/**
	 * @brief 元のaddress list ownerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	AddressInfoScope &operator=( AddressInfoScope &&) = delete ;

private:
	/// `FreeAddrInfoW`で解放するlist先頭。
	PADDRINFOW value_{} ;
} ;

/**
 * @brief Win32またはWinsock errorをHRESULT bit patternへ変換します。
 * @param[in] error 0ではないsystem error。
 * @return `NativeError`で保持するHRESULT bit pattern。
 */
[[nodiscard]] NativeError nativeErrorFromSystem( const int error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( static_cast<unsigned long>( error))) ;
}

/**
 * @brief ASCII DNS hostがdynamic targetの必須構文だけで構成されるか確認します。
 * @param[in] host 検証するhost。
 * @return 複数の正常labelを持ち、literal・禁止suffixでなければtrue。
 */
[[nodiscard]] bool hasValidDynamicDnsSyntax( const std::wstring_view host) noexcept
{
	// 空、全長上限超過、先頭／末尾dot、単一labelは解決しない。
	if( host.empty() || host.size() > MAXIMUM_DNS_HOST_CHARACTERS || host.front() == L'.' ||
	   host.back() == L'.' || host.find( L'.') == host.npos) {
		return false ;
	}

	const bool numericV4 = std::all_of( host.begin(), host.end(), []( const wchar_t character) {
		return (character >= L'0' && character <= L'9') || character == L'.' ;
	}) ; // Dotted decimalをDNS名として受理しない判定。
	// IPv4 literalは範囲にかかわらずrecord直結targetに許可しない。
	if( numericV4) {
		return false ;
	}

	std::size_t labelStart{} ;	// 現在labelのhost内開始index。
	// 末尾直後の仮想dotまで確認し、全labelの長さと文字を検証する。
	for( std::size_t index = 0U; index <= host.size(); ++index) {
		const bool atBoundary = index == host.size() || host[index] == L'.' ;	// Label終端ならtrue。
		// Label途中はASCII letter、digit、hyphenだけを許可する。
		if( !atBoundary) {
			const wchar_t character = host[index] ;	// 現在のDNS label文字。
			const bool	  allowed	= (character >= L'A' && character <= L'Z') ||
								 (character >= L'a' && character <= L'z') ||
								 (character >= L'0' && character <= L'9') ||
								 // ASCII許可集合。
								 character == L'-' ;
			// Unicode、colon、separator等をDNS resolverへ渡さない。
			if( !allowed) {
				return false ;
			}

			continue ;
		}

		const std::size_t labelLength = index - labelStart ;	// 今回確定したlabel長。
		// 空または63文字超過labelと両端hyphenを拒否する。
		if( labelLength == 0U || labelLength > MAXIMUM_DNS_LABEL_CHARACTERS ||
		   host[labelStart] == L'-' || host[index - 1U] == L'-') {
			return false ;
		}

		labelStart = index + 1U ;
	}

	std::wstring normalized( host) ;	// 禁止suffix照合用のASCII小文字host。
	// ASCII大文字だけを小文字化する。
	std::transform( normalized.begin(), normalized.end(), normalized.begin(),
				   []( const wchar_t character) {
					   return character >= L'A' && character <= L'Z'
								  ? static_cast<wchar_t>( character - L'A' + L'a')
								  : character ;
				   }) ;
	// Local名と組織内部用suffixをpublic DNS targetとして扱わない。
	if( normalized == L"localhost" || normalized.ends_with( L".localhost") ||
	   normalized.ends_with( L".local") || normalized.ends_with( L".internal")) {
		return false ;
	}

	return true ;
}

/**
 * @brief IPv4 addressがInternet向けglobal unicast候補か確認します。
 * @param[in] bytes Network byte orderの先頭4 byte。
 * @return Private・特殊・予約／文書用でなければtrue。
 */
[[nodiscard]] bool isPublicIpv4( const std::array<std::byte, 16> &bytes) noexcept
{
	const unsigned int first  = std::to_integer<unsigned int>( bytes[0]) ;	// 第1 octet。
	const unsigned int second = std::to_integer<unsigned int>( bytes[1]) ;	// 第2 octet。
	const unsigned int third  = std::to_integer<unsigned int>( bytes[2]) ;	// 第3 octet。
	// RFC 6890系の非global、private、loopback、link-local、multicast、文書用を一律に拒否する。
	if( first == 0U || first == 10U || first == 127U || first >= 224U ||
	   (first == 100U && second >= 64U && second <= 127U) || (first == 169U && second == 254U) ||
	   (first == 172U && second >= 16U && second <= 31U) || (first == 192U && second == 168U) ||
	   (first == 192U && second == 0U && (third == 0U || third == 2U)) ||
	   (first == 192U && second == 88U && third == 99U) ||
	   (first == 198U && (second == 18U || second == 19U)) ||
	   (first == 198U && second == 51U && third == 100U) ||
	   (first == 203U && second == 0U && third == 113U)) {
		return false ;
	}

	return true ;
}

/**
 * @brief IPv6 addressがInternet向けglobal unicast候補か確認します。
 * @param[in] bytes Network byte orderの16 byte。
 * @return `2000::/3`の通常unicastで特殊／文書／transition用でなければtrue。
 */
[[nodiscard]] bool isPublicIpv6( const std::array<std::byte, 16> &bytes) noexcept
{
	const unsigned int first  = std::to_integer<unsigned int>( bytes[0]) ;	// 第1 octet。
	const unsigned int second = std::to_integer<unsigned int>( bytes[1]) ;	// 第2 octet。
	const unsigned int third  = std::to_integer<unsigned int>( bytes[2]) ;	// 第3 octet。
	const unsigned int fourth = std::to_integer<unsigned int>( bytes[3]) ;	// 第4 octet。
	// Global unicast割当候補`2000::/3`外を、予約範囲を含めて拒否する。
	if( (first & 0xe0U) != 0x20U) {
		return false ;
	}

	// 2001::/23特殊用、2001:2::/48 benchmark、2001:db8::/32文書用、2002::/16 6to4を拒否する。
	if( (first == 0x20U && second == 0x01U && third < 0x02U) ||
	   (first == 0x20U && second == 0x01U && third == 0x02U && fourth == 0x00U) ||
	   (first == 0x20U && second == 0x01U && third == 0x0dU && fourth == 0xb8U) ||
	   (first == 0x20U && second == 0x02U) || (first == 0x3fU && (second & 0xf0U) == 0xf0U)) {
		return false ;
	}

	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_public_destination.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool isPublicOfficialNetworkAddress( const OfficialResolvedNetworkAddress &address) noexcept
{
	// Familyごとの固定byte列検証だけを行う。
	switch( address.family) {
		// IPv4の特殊・private範囲を拒否する。
		case OfficialNetworkAddressFamily::IPV4:
			return isPublicIpv4( address.bytes) ;
		// IPv6の特殊・private範囲を拒否する。
		case OfficialNetworkAddressFamily::IPV6:
			return isPublicIpv6( address.bytes) ;
		// 定義外familyをpublicとして扱わない。
		default:
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_public_destination.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError validatePublicOfficialDestination( const std::wstring_view			 host,
											  const OfficialDestinationResolver &resolver,
											  OfficialPublicDestinationEvidence &evidence) noexcept
{
	evidence = {} ;
	// 未登録resolverとdynamic DNS構文外hostをname resolution前に拒否する。
	if( !resolver || !hasValidDynamicDnsSyntax( host)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	try {
		std::vector<OfficialResolvedNetworkAddress> addresses ;			// Resolverが返す有限address列。
		const NativeError resolveError = resolver( host, addresses) ;	// Worker内name resolution結果。
		// Resolver失敗、空結果、上限超過を宛先不明のまま許可しない。
		if( resolveError != 0 || addresses.empty() ||
		   addresses.size() > MAXIMUM_RESOLVED_ADDRESSES) {
			return resolveError != 0 ? resolveError : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 複数A／AAAAの一つでも非publicならDNS rebinding候補としてhost全体を拒否する。
		for( const OfficialResolvedNetworkAddress &address : addresses) {
			// 現在addressがglobal unicast条件を満たさなければ一部だけを採用しない。
			if( !isPublicOfficialNetworkAddress( address)) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}
		}

		// 64件以下なので狭める前提が成立する。
		if( addresses.size() > std::numeric_limits<std::uint32_t>::max()) {
			return static_cast<NativeError>( E_UNEXPECTED) ;
		}

		evidence.addressCount	 = static_cast<std::uint32_t>( addresses.size()) ;
		evidence.locallyResolved = true ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// Resolver callbackの未知例外をworker境界の成功にしない。
		return static_cast<NativeError>( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_public_destination.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError resolveOfficialDestinationWithWindows(
	const std::wstring_view host, std::vector<OfficialResolvedNetworkAddress> &addresses) noexcept
{
	addresses.clear() ;
	try {
		const WinsockScope winsock ;	// 本解決scopeのWinsock参照。
		// Winsockを開始できない場合はresolverを呼ばない。
		if( winsock.result() != 0) {
			return nativeErrorFromSystem( winsock.result()) ;
		}

		const std::wstring ownedHost( host) ;	// `GetAddrInfoW`が必要とするNUL終端host。
		ADDRINFOW		   hints{} ;			// IPv4／IPv6 TCPに限定する解決hint。
		hints.ai_family	  = AF_UNSPEC ;
		hints.ai_socktype = SOCK_STREAM ;
		hints.ai_protocol = IPPROTO_TCP ;
		PADDRINFOW			   rawResult{} ;	// `GetAddrInfoW`が設定するlist先頭。
		const int			   resolution = GetAddrInfoW( ownedHost.c_str(), L"443", &hints,
														 &rawResult) ;	// Unicode name resolution結果。
		const AddressInfoScope resultScope( rawResult) ;				// 全returnでlistを解放する所有者。
		// Resolverの元errorまたは空linked listをそのまま失敗とする。
		if( resolution != 0 || rawResult == nullptr) {
			return resolution != 0 ? nativeErrorFromSystem( resolution)
								   : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		std::vector<OfficialResolvedNetworkAddress> resolved ;	// 全検証前のnative address列。
		resolved.reserve( 8U) ;
		// Linked list全件を上限まで複写し、familyや長さの不整合を拒否する。
		for( const ADDRINFOW *current = rawResult; current != nullptr; current = current->ai_next) {
			// 65件目は一部addressだけを検証することなく上限失敗にする。
			if( resolved.size() >= MAXIMUM_RESOLVED_ADDRESSES) {
				return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
			}

			OfficialResolvedNetworkAddress address ;	// 現在nodeから固定長へ複写するaddress。
			// IPv4 sockaddrは4 byte address部分だけをnetwork byte orderで保持する。
			if( current->ai_family == AF_INET && current->ai_addr != nullptr &&
			   current->ai_addrlen >= static_cast<int>( sizeof( SOCKADDR_IN))) {
				// Winsockがfamilyと長さを保証した境界でsockaddrをIPv4構造へ変換する。
				const auto *ipv4 = reinterpret_cast<const SOCKADDR_IN *>( current->ai_addr) ;
				address.family	 = OfficialNetworkAddressFamily::IPV4 ;
				std::memcpy( address.bytes.data(), &ipv4->sin_addr, 4U) ;
			} else {
				// IPv6 sockaddrは16 byte address部分だけをnetwork byte orderで保持する。
				if( current->ai_family == AF_INET6 && current->ai_addr != nullptr &&
				   current->ai_addrlen >= static_cast<int>( sizeof( SOCKADDR_IN6))) {
					// Winsockがfamilyと長さを保証した境界でsockaddrをIPv6構造へ変換する。
					const auto *ipv6 = reinterpret_cast<const SOCKADDR_IN6 *>( current->ai_addr) ;
					address.family	 = OfficialNetworkAddressFamily::IPV6 ;
					std::memcpy( address.bytes.data(), &ipv6->sin6_addr, 16U) ;
				} else {
					// 未知familyまたは不正sockaddrを無視して残りだけを使わない。
					return static_cast<NativeError>( E_ACCESSDENIED) ;
				}
			}

			resolved.push_back( address) ;
		}

		// 空結果を成功として公開しない。
		if( resolved.empty()) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		addresses = std::move( resolved) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// OS境界の未知例外をworker外へ漏らさない。
		return static_cast<NativeError>( E_FAIL) ;
	}
}

} // namespace drivercrate
