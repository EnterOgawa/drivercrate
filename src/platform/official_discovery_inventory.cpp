//------------------------------------------------------------------------------
/**
 * @file official_discovery_inventory.cpp
 * @brief Present inventoryの有限bus分類と公式自動探索hint変換実装。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Bus分類とrouting hint変換を追加。
 * </pre>
 *
 * @note Raw identityはbus分類中だけ参照し、出力値へ含めません。入力全件の検証後にだけ
 * 所有vectorを返し、部分hintを後続route plannerへ渡しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "platform/official_discovery_inventory.h"

#include <algorithm>
#include <cstddef>
#include <cwctype>
#include <string>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {

// Native identity入力を不正としてUNKNOWNにする最大UTF-16文字数。
constexpr std::size_t MAXIMUM_NATIVE_IDENTITY_CHARACTERS = 4096U ;

/**
 * @brief ASCII大小文字を区別せず二つのenumerator名を完全一致で比較する。
 * @param[in] left 比較元のenumerator。
 * @param[in] right 大文字で固定した既知enumerator。
 * @return 同じ長さとASCII文字を持つ場合true。
 */
[[nodiscard]] bool	  equalsAsciiInsensitive( const std::wstring_view left,
											 const std::wstring_view right) noexcept
{
	// 長さが異なるprefixを部分一致として同じbusへ分類しない。
	if( left.size() != right.size()) {
		return false ;
	}

	// ASCII範囲の大小文字だけを正規化し、Unicode別名を推測しない。
	for( std::size_t index = 0U; index < left.size(); ++index) {
		const wchar_t leftCharacter = left[index] ;	// 現在比較する入力文字。
		// ASCII小文字だけを大文字へ変換した比較値。
		const wchar_t normalized = leftCharacter >= L'a' && leftCharacter <= L'z'
									   ? leftCharacter - L'a' + L'A'
									   : leftCharacter ;
		// 固定enumeratorと一致しない文字があれば異なるbusとして扱う。
		if( normalized != right[index]) {
			return false ;
		}
	}

	return true ;
}

} // namespace

/** @see official_discovery_inventory.h */
OfficialDiscoveryDeviceBus classifyOfficialDiscoveryDeviceBus(
	const std::wstring_view nativeIdentity) noexcept
{
	// 欠損、過大、埋込みNUL、制御文字を別busへ推測しない。
	if( nativeIdentity.empty() || nativeIdentity.size() > MAXIMUM_NATIVE_IDENTITY_CHARACTERS ||
	   nativeIdentity.find( L'\0') != std::wstring_view::npos ||
	   std::any_of( nativeIdentity.begin(), nativeIdentity.end(),
				   []( const wchar_t character) { return character < L' ' ; })) {
		return OfficialDiscoveryDeviceBus::UNKNOWN ;
	}

	const std::size_t		separator  = nativeIdentity.find( L'\\') ;				// Enumeratorの終端位置。
	const std::wstring_view enumerator = nativeIdentity.substr( 0U, separator) ;	// 借用prefix。
	// 空enumeratorや先頭区切りをOTHERへ昇格させない。
	if( enumerator.empty()) {
		return OfficialDiscoveryDeviceBus::UNKNOWN ;
	}

	// 各busはenumerator完全一致だけで分類し、製品名や後続IDを参照しない。
	if( equalsAsciiInsensitive( enumerator, L"PCI")) {
		return OfficialDiscoveryDeviceBus::PCI ;
	}

	// USB enumeratorだけをUSB分類へ対応付ける。
	if( equalsAsciiInsensitive( enumerator, L"USB")) {
		return OfficialDiscoveryDeviceBus::USB ;
	}

	// ACPI enumeratorだけをACPI分類へ対応付ける。
	if( equalsAsciiInsensitive( enumerator, L"ACPI")) {
		return OfficialDiscoveryDeviceBus::ACPI ;
	}

	// HID enumeratorだけをHID分類へ対応付ける。
	if( equalsAsciiInsensitive( enumerator, L"HID")) {
		return OfficialDiscoveryDeviceBus::HID ;
	}

	// Windowsの既知Bluetooth enumeratorを一つの有限分類へまとめる。
	if( equalsAsciiInsensitive( enumerator, L"BTH") ||
	   equalsAsciiInsensitive( enumerator, L"BTHENUM") ||
	   equalsAsciiInsensitive( enumerator, L"BTHLEDEVICE")) {
		return OfficialDiscoveryDeviceBus::BLUETOOTH ;
	}

	// Software deviceの既知enumeratorだけをSOFTWAREへまとめる。
	if( equalsAsciiInsensitive( enumerator, L"SWD") || equalsAsciiInsensitive( enumerator, L"SW")) {
		return OfficialDiscoveryDeviceBus::SOFTWARE ;
	}

	// ROOT enumeratorだけをroot列挙deviceとして分類する。
	if( equalsAsciiInsensitive( enumerator, L"ROOT")) {
		return OfficialDiscoveryDeviceBus::ROOT ;
	}

	return OfficialDiscoveryDeviceBus::OTHER ;
}

/** @see official_discovery_inventory.h */
std::optional<std::vector<OfficialDiscoveryDeviceHint>> makeOfficialDiscoveryDeviceHints(
	const ScanSessionId scanSessionId, const bool inventoryComplete,
	const std::span<const OfficialCatalogDevice> devices)
{
	// 不完全、空、過大なinventoryから一部だけのroute対象を作らない。
	if( scanSessionId == 0U || !inventoryComplete || devices.empty() ||
	   devices.size() > OFFICIAL_DISCOVERY_DEVICE_LIMIT) {
		return std::nullopt ;
	}

	std::vector<OfficialDiscoveryDeviceHint> hints ;	// 全件成功まで公開しない所有結果。
	hints.reserve( devices.size()) ;
	std::unordered_set<std::wstring> deviceIdentities ;	// Opaque identityの一意性検証集合。
	deviceIdentities.reserve( devices.size()) ;
	// 既存の非機密inventoryを同順の自動探索hintへ変換する。
	for( const OfficialCatalogDevice &device : devices) {
		// Opaque identity重複と観測欠損を部分的なroute対象へ変換しない。
		if( !device.deviceObservation || !deviceIdentities.insert( device.deviceIdentity).second) {
			return std::nullopt ;
		}

		OfficialDiscoveryDeviceHint hint ;	// Raw IDを含まない一deviceの変換候補。
		hint.deviceIdentity	 = device.deviceIdentity ;
		hint.bus			 = device.discoveryBus ;
		hint.setupClassGuid	 = device.deviceClassGuid ;
		hint.deviceClass	 = device.driverClass ;
		hint.manufacturer	 = device.manufacturer ;
		hint.model			 = device.model ;
		hint.currentProvider = device.currentProvider ;
		hint.observation	 = *device.deviceObservation ;
		// 一件でもCore契約に違反する場合は所有vector全体を破棄する。
		if( !validateOfficialDiscoveryDeviceHint( hint, scanSessionId)) {
			return std::nullopt ;
		}

		hints.push_back( std::move( hint)) ;
	}

	return hints ;
}

} // namespace drivercrate
