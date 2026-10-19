//------------------------------------------------------------------------------
/**
 * @file device_observation.cpp
 * @brief Device観測の有限検証と登録状態の純粋分類。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Device観測と有限な分類契約を追加。
 * </pre>
 *
 * @note OS・network・導入APIを呼ばず、欠損を成功へ補完しない。
 * @see docs/adr/0150-device-observation-and-candidate-assessment-contract.md
 */
//------------------------------------------------------------------------------

#include "core/device_observation.h"

#include <array>
#include <cstddef>

namespace drivercrate {
namespace {

// Windows cfg.hのDN_HAS_PROBLEM。Core公開APIへWindows headerを持ち込まない。
constexpr std::uint32_t NODE_HAS_PROBLEM				 = 0x00000400U ;
constexpr std::uint32_t DRIVER_NOT_INSTALLED_PROBLEM	 = 28U ;	// WindowsのCM_PROB_FAILED_INSTALL。
constexpr std::size_t	MAXIMUM_OPAQUE_DEVICE_CHARACTERS = 256U ;	// 既存の候補identity上限。

/**
 * @brief 非成功の診断が既知APIの非0codeを持つか確認する。
 * @param[in] diagnostic 元APIまたは検証失敗の診断。
 * @return 成功と矛盾しない非0診断ならtrue。
 */
bool					isFailureDiagnosticValid( const DeviceDiagnostic &diagnostic) noexcept
{
	// 成功codeを失敗として受理せず、観測不能を0へ補完させない。
	if( diagnostic.code == 0U) {
		return false ;
	}

	// APIごとの成功値を区別し、未知領域をfail-closedで拒否する。
	switch( diagnostic.domain) {
		// Win32失敗は非0の元codeを保持する。
		case DeviceDiagnosticDomain::WINDOWS_ERROR:
		// CONFIGRET失敗はCR_SUCCESS以外を保持する。
		case DeviceDiagnosticDomain::CONFIGURATION_MANAGER:
			return true ;
		// HRESULTは失敗bitがある場合だけ失敗診断とする。
		case DeviceDiagnosticDomain::HRESULT_VALUE:
			return (diagnostic.code & 0x80000000U) != 0U ;
		// 領域なしでは失敗を説明できない。
		case DeviceDiagnosticDomain::NONE:
			return false ;
	}

	return false ;
}
} // namespace

/** @see src/core/device_observation.h */
bool isDevicePropertyReadStatusValid( const DevicePropertyReadStatus &status) noexcept
{
	// 読取り区分に対応する診断の有無を固定し、不正enumを拒否する。
	switch( status.state) {
		// 未照会では失敗を仮定しない。
		case DevicePropertyReadState::NOT_READ:
		// 値を得た場合はstaleな失敗codeを持たない。
		case DevicePropertyReadState::VALUE:
		// 正規の空値はAPI失敗ではない。
		case DevicePropertyReadState::EMPTY:
			return status.diagnostic.domain == DeviceDiagnosticDomain::NONE &&
				   status.diagnostic.code == 0U ;
		// 不存在の観測はWin32 ERROR_NOT_FOUNDに限定する。
		case DevicePropertyReadState::NOT_PRESENT:
			return status.diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR &&
				   status.diagnostic.code == 1168U ;
		// 元APIの失敗を保持する。
		case DevicePropertyReadState::FAILED:
		// 型・境界不正も元または合成codeを必要とする。
		case DevicePropertyReadState::INVALID_DATA:
		// 有限上限の拒否を診断なしにしない。
		case DevicePropertyReadState::LIMIT_REACHED:
			return isFailureDiagnosticValid( status.diagnostic) ;
	}

	return false ;
}

/** @see src/core/device_observation.h */
bool isDeviceNodeObservationValid( const DeviceNodeObservation &node) noexcept
{
	// 読取り自体が不正な場合は登録状態の根拠に使わない。
	if( !isDevicePropertyReadStatusValid( node.read)) {
		return false ;
	}

	// 成功時にだけstatusとproblemの組を解釈する。
	if( node.read.state == DevicePropertyReadState::VALUE) {
		return node.statusFlags.has_value() &&
			   (((*node.statusFlags & NODE_HAS_PROBLEM) != 0U) == node.problemCode.has_value()) &&
			   (!node.problemCode || *node.problemCode != 0U) ;
	}

	// Devnode APIは空文字や不存在propertyを返すAPIではない。
	return (node.read.state == DevicePropertyReadState::NOT_READ ||
			node.read.state == DevicePropertyReadState::FAILED ||
			node.read.state == DevicePropertyReadState::INVALID_DATA) &&
		   !node.statusFlags && !node.problemCode ;
}

/** @see src/core/device_observation.h */
DeviceDriverPresence classifyDeviceDriverPresence(
	const DeviceNodeObservation &node, const DevicePropertyReadStatus &driverKey) noexcept
{
	// 不正な観測を未導入や登録済みへ昇格しない。
	if( !isDeviceNodeObservationValid( node) || !isDevicePropertyReadStatusValid( driverKey)) {
		return DeviceDriverPresence::UNKNOWN ;
	}

	// Windowsが明示した未導入を過去のkey残存や版文字列で隠さない。
	if( node.read.state == DevicePropertyReadState::VALUE &&
	   node.problemCode == DRIVER_NOT_INSTALLED_PROBLEM) {
		return DeviceDriverPresence::NOT_INSTALLED ;
	}

	return driverKey.state == DevicePropertyReadState::VALUE ? DeviceDriverPresence::REGISTERED
															 : DeviceDriverPresence::UNKNOWN ;
}

/** @see src/core/device_observation.h */
bool isDeviceObservationValid( const DeviceObservation &observation) noexcept
{
	// 有限なsession/device結合とnode状態がない観測を候補へ渡さない。
	if( observation.scanSessionId == 0U || observation.deviceIdentity.empty() ||
	   observation.deviceIdentity.size() > MAXIMUM_OPAQUE_DEVICE_CHARACTERS ||
	   observation.deviceIdentity.find( L'\0') != std::wstring::npos ||
	   !isDeviceNodeObservationValid( observation.node)) {
		return false ;
	}

	const std::array<const DevicePropertyReadStatus *, 10> properties{
		&observation.friendlyName,	  &observation.deviceDescription, &observation.manufacturer,
		&observation.deviceClass,	  &observation.driverKey,		  &observation.infName,
		&observation.provider,		  &observation.version,			  &observation.date,
		&observation.instanceIdentity} ;	// 固定属性だけを検証する借用一覧。
	// 固定数の全属性を検証し、一件の矛盾も正常な観測へ混在させない。
	for( const auto *property : properties) {
		// 元APIの失敗を隠した不正状態は観測全体の登録を拒否する。
		if( !isDevicePropertyReadStatusValid( *property)) {
			return false ;
		}
	}

	return observation.driverPresence ==
		   classifyDeviceDriverPresence( observation.node, observation.driverKey) ;
}

/** @see src/core/device_observation.h */
bool isDeviceObservationBound( const DeviceObservation &observation,
							  const std::uint64_t	   scanSessionId,
							  const std::wstring_view  deviceIdentity) noexcept
{
	return isDeviceObservationValid( observation) && observation.scanSessionId == scanSessionId &&
		   observation.deviceIdentity == deviceIdentity ;
}

} // namespace drivercrate
