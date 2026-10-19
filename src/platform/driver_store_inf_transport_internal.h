//------------------------------------------------------------------------------
/**
 * @file driver_store_inf_transport_internal.h
 * @brief 実Driver Store guardの低位APIを同workerの固定表へ結合します。
 * @version 01.02.00
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  同workerの索引候補と指定導入の内部境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  登録済みWindows INF rootの完全低位照会を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/13  実INFのClass名/GUIDを独立確認する完全低位呼出しを追加。
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/driver_store_inventory_transport.h"
#include <newdev.h>
#include <memory>
namespace drivercrate::driver_store_inf_detail {
/** @brief 判定・node選択・bindingは本体へ残した完全な低位API表です。 */
struct Transport {
	/// 現在state属性の同backend。一つもnativeへ補完しません。
	DriverStoreInventoryTransport			  inventory ;
	/// SetupDiCreateDeviceInfoListと同ABIの固定低位呼出しです。
	decltype( &SetupDiCreateDeviceInfoList)	  create{} ;
	/// SetupDiOpenDeviceInfoWと同ABIの固定低位呼出しです。
	decltype( &SetupDiOpenDeviceInfoW)		  open{} ;
	/// SetupDiBuildDriverInfoListと同ABIの固定低位呼出しです。
	decltype( &SetupDiBuildDriverInfoList)	  build{} ;
	/// SetupDiEnumDriverInfoWと同ABIの固定低位呼出しです。
	decltype( &SetupDiEnumDriverInfoW)		  enumerate{} ;
	/// SetupDiGetDriverInfoDetailWと同ABIの固定低位呼出しです。
	decltype( &SetupDiGetDriverInfoDetailW)	  detail{} ;
	/// SetupDiGetDeviceInstallParamsWと同ABIの固定低位呼出しです。
	decltype( &SetupDiGetDeviceInstallParamsW) getParameters{} ;
	/// SetupDiSetDeviceInstallParamsWと同ABIの固定低位呼出しです。
	decltype( &SetupDiSetDeviceInstallParamsW) setParameters{} ;
	/// SetupDiGetDriverInstallParamsWと同ABIの固定低位呼出しです。
	decltype( &SetupDiGetDriverInstallParamsW) rank{} ;
	/// SetupDiDestroyDriverInfoListと同ABIの固定低位呼出しです。
	decltype( &SetupDiDestroyDriverInfoList)	  destroyDrivers{} ;
	/// SetupCopyOEMInfWと同ABIの固定低位呼出しです。
	decltype( &SetupCopyOEMInfW)				  stage{} ;
	/// DiInstallDeviceと同ABIの固定低位呼出しです。
	decltype( &DiInstallDevice)				  install{} ;
	/// GetNativeSystemInfoと同ABIの固定低位呼出しです。
	decltype( &GetNativeSystemInfo)			  architecture{} ;
	/// GetWindowsDirectoryWと同ABIの既知Windows root照会です。欠損fallbackを認めません。
	decltype( &GetWindowsDirectoryW)			  windowsDirectory{} ;
	/// 同じ保護INFのClass名/GUIDを確認する低位API。欠損native補完はしません。
	decltype( &SetupDiGetINFClassW)			  infClass{} ;
} ;
struct Access ;
/** @brief 同worker lifetimeの完全API表をscope所有します。 */
class ScopedFixture final {
public:
	/** @brief 同workerのAPI表を解除します。 */
	~ScopedFixture() noexcept ;
	/** @brief 同worker低位表の所有scopeの複写を禁止します。
	 * @param[in] other 複写元として指定できない既存scopeです。
	 * @note 削除宣言のため実行・I/O・所有権移動・例外発生はありません。
	 */
	ScopedFixture( const ScopedFixture &other) = delete ;
	/** @brief 同worker低位表の所有scopeの複写代入を禁止します。
	 * @param[in] other 代入元として指定できない既存scopeです。
	 * @return 削除宣言のため返却される参照は存在しません。
	 * @note 呼出しはcompile時に拒否され、外部状態とscopeの寿命を変更しません。
	 */
	ScopedFixture &operator=( const ScopedFixture &other) = delete ;

private:
	friend struct Access ;
	/** @brief 全guardが使用する完全表を固定します。
	 * @param[in] calls Nativeを含まない完全fake表。
	 */
	explicit ScopedFixture( Transport calls) noexcept ;
	/// このworkerだけが借りる固定API表。
	Transport				calls_ ;
	friend const Transport &transport() noexcept ;
} ;
/** @brief 製品nativeまたは同worker固定完全表を参照します。
 * @return 同期呼出し中有効な借用参照。欠損fallbackはありません。
 */
[[nodiscard]] const Transport &transport() noexcept ;
/** @brief 同workerへ完全fake表が固定されているか確認します。
 * @return 内部scopeの生存中だけtrueです。
 */
[[nodiscard]] bool			   fixtureActive() noexcept ;
// 完全fake factoryだけを内部試験へ提供します。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @brief 同workerの生存期間へ低位APIだけを固定する内部factoryです。 */
struct Access {
	/** @brief 欠損・native混在・scope上書きを拒否します。
	 * @param[in] calls 完全なfake WinAPI表。成功DTOを受けません。
	 * @return 完全表だけを所有するscope。不足時はnullptrです。
	 */
	[[nodiscard]] static std::unique_ptr<ScopedFixture> create( Transport calls) ;
} ;
#endif
} // namespace drivercrate::driver_store_inf_detail
