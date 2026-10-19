//------------------------------------------------------------------------------
/**
 * @file device_observation.h
 * @brief Deviceの登録状態・属性読取り・問題状態の有限な観測契約。
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
 * @note Windows型・生ID・pathを保持せず、導入許可を発行しない。
 * @see docs/adr/0150-device-observation-and-candidate-assessment-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace drivercrate {

/** @brief 診断codeを解釈するAPI領域。 */
enum class DeviceDiagnosticDomain {
	/// 診断を持たない。
	NONE,
	/// Win32のGetLastError値である。
	WINDOWS_ERROR,
	/// Configuration Managerの戻り値である。
	CONFIGURATION_MANAGER,
	/// HRESULTの32-bit bit patternである。
	HRESULT_VALUE,
} ;

/** @brief 元APIの領域と32-bit診断値。 */
struct DeviceDiagnostic {
	/// 診断の出所。NONEではcodeを0に限定する。
	DeviceDiagnosticDomain domain{DeviceDiagnosticDomain::NONE} ;
	/// 元APIの値。成功した読取りでは0を保持する。
	std::uint32_t		   code{} ;
} ;

/** @brief 属性の値・欠損・API失敗・不正を区別する。 */
enum class DevicePropertyReadState {
	/// 当該属性を照会していない。
	NOT_READ,
	/// 型と境界を検証した値を得た。
	VALUE,
	/// 正規の空文字列を得た。
	EMPTY,
	/// OSが当該propertyの不存在を返した。
	NOT_PRESENT,
	/// APIが値を返せなかった。
	FAILED,
	/// 型・size・終端または観測整合性が不正である。
	INVALID_DATA,
	/// 有限容量を超えたか、必要量が取得中に増大した。
	LIMIT_REACHED,
} ;

/** @brief 生属性を含まない読取り結果。 */
struct DevicePropertyReadStatus {
	/// 読取りの到達区分。
	DevicePropertyReadState state{DevicePropertyReadState::NOT_READ} ;
	/// 失敗・欠損・不正・上限時の元または合成診断。
	DeviceDiagnostic		diagnostic ;
} ;

/** @brief 一回のOS照会が返すdevnode statusとproblem code。 */
struct DeviceNodeObservation {
	/// Status照会の結果。VALUE以外では値を持たない。
	DevicePropertyReadStatus	 read ;
	/// 成功時のstatus bit集合。
	std::optional<std::uint32_t> statusFlags ;
	/// DN_HAS_PROBLEM時だけ有効なproblem code。
	std::optional<std::uint32_t> problemCode ;
} ;

/** @brief 現在版や動作成功とは独立したdriver登録状態。 */
enum class DeviceDriverPresence {
	/// 存在・未導入の根拠を確認できない。
	UNKNOWN,
	/// OSのdriver keyに正規の非空値を確認した。
	REGISTERED,
	/// WindowsがCode 28として未導入を報告した。
	NOT_INSTALLED,
} ;

/** @brief 一つのscanとopaque deviceへ結合したimmutable表示用観測。 */
struct DeviceObservation {
	/// 観測元の0ではないscan session。
	std::uint64_t			 scanSessionId{} ;
	/// 同じ代表行のopaque identity。生instance IDを含めない。
	std::wstring			 deviceIdentity ;
	/// 登録状態の純粋分類。動作成功や導入許可ではない。
	DeviceDriverPresence	 driverPresence{DeviceDriverPresence::UNKNOWN} ;
	/// 同一OS照会のdevnode状態。
	DeviceNodeObservation	 node ;
	/// FriendlyNameの読取り結果。Fallback元も保持する。
	DevicePropertyReadStatus friendlyName ;
	/// FriendlyNameが使えない場合のDeviceDesc読取り結果。
	DevicePropertyReadStatus deviceDescription ;
	/// Manufacturer表示属性の読取り結果。
	DevicePropertyReadStatus manufacturer ;
	/// Setup class表示属性の読取り結果。
	DevicePropertyReadStatus deviceClass ;
	/// Worker内driver keyの読取り状態だけを持つ。
	DevicePropertyReadStatus driverKey ;
	/// Worker内INF名の読取り状態だけを持つ。
	DevicePropertyReadStatus infName ;
	/// 現在driver Providerの読取り状態。
	DevicePropertyReadStatus provider ;
	/// 現在版の読取り状態。空だけで未導入としない。
	DevicePropertyReadStatus version ;
	/// 現在driver日付の読取り状態。
	DevicePropertyReadStatus date ;
	/// Worker内instance IDの解決状態。値は持たない。
	DevicePropertyReadStatus instanceIdentity ;
} ;

/**
 * @brief 読取り区分と診断領域・値の整合性を確認する。
 * @param[in] status 属性を含まない読取り結果。
 * @return 定義済みの矛盾しない状態ならtrue。
 */
[[nodiscard]] bool isDevicePropertyReadStatusValid( const DevicePropertyReadStatus &status) noexcept ;

/**
 * @brief Status成功とproblem codeの有効条件を照合する。
 * @param[in] node 一回のOS照会の観測。
 * @return 値と読取り状態が整合する場合true。
 */
[[nodiscard]] bool isDeviceNodeObservationValid( const DeviceNodeObservation &node) noexcept ;

/**
 * @brief WindowsのCode 28またはdriver keyの観測から登録状態を分類する。
 * @param[in] node 有限なdevnode観測。不正な観測はUNKNOWNになる。
 * @param[in] driverKey 生keyを含まない読取り結果。
 * @return Code 28を優先した登録状態。正常動作や導入適合性を保証しない。
 */
[[nodiscard]] DeviceDriverPresence classifyDeviceDriverPresence(
	const DeviceNodeObservation &node, const DevicePropertyReadStatus &driverKey) noexcept ;

/**
 * @brief 一device観測の有限性・全属性・登録分類を検証する。
 * @param[in] observation 候補へ結合する表示用観測。
 * @return 既知の状態であり登録分類も観測根拠と一致する場合true。
 */
[[nodiscard]] bool isDeviceObservationValid( const DeviceObservation &observation) noexcept ;

/**
 * @brief 観測を今回のsessionとdeviceへ完全一致で結合する。
 * @param[in] observation 検証する観測。
 * @param[in] scanSessionId 今回の0ではないsession。
 * @param[in] deviceIdentity 借用した今回のopaque device identity。
 * @return 観測全体が妥当で両identityが一致する場合true。
 */
[[nodiscard]] bool isDeviceObservationBound( const DeviceObservation &observation,
											std::uint64_t			 scanSessionId,
											std::wstring_view		 deviceIdentity) noexcept ;

} // namespace drivercrate
