//------------------------------------------------------------------------------
/**
 * @file driver_store_inf_transport_internal.h
 * @brief 実Driver Store guardの低位APIを同workerの固定表へ結合します
 * @version 01.08.00
 * @date 2026/10/12
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  登録済みWindows INF rootの完全低位照会を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/13  実INFのClass名/GUIDを独立確認する完全低位呼出しを追加
 * Ver.01.02.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.02.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.03.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.04.00 Shunji Ogawa  2026/11/16  MTDのqueueと共有file用低位表を旧経路と分離
 * Ver.01.05.00 Shunji Ogawa  2026/11/17  同登録StoreとMTD元Windows rootを閉表へ追加
 * Ver.01.06.00 Shunji Ogawa  2026/11/19  互換nodeの可変長Models ID読取契約を追加
 * Ver.01.07.00 Shunji Ogawa  2026/11/19  独自クラスの読取りと配置先照会を完全API表に追加
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  現在ストレージ配布の登録先照会を追加
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/driver_store_inventory_transport.h"
#include "platform/mtd_handler_internal.h"
#include <AclAPI.h>
#include <newdev.h>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace drivercrate::driver_store_inf_detail {
//------------------------------------------------------------------------------
/**
 * @brief Windowsが返す一nodeの元Hardware IDとCompatible IDを読み取る
 * @param[in] buffer Windowsが有効長を返した可変ID領域
 * @param[in] compatOffset Hardware IDの終端直後のCompatible ID開始位置
 * @param[in] compatLength Windowsが返したCompatible IDの総文字数
 * @param[out] modelIds 正常終了した場合の元ID列。失敗時は使用しない
 * @return 型・長さ・終端を確認できた場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDriverModelIds( std::span<const wchar_t> buffer, std::size_t compatOffset,
									  std::size_t				 compatLength,
									  std::vector<std::wstring> &modelIds) ;

/** @brief MTD選択queueと共有fileが使う完全な低位API集合です */
struct MtdTransport {
	/// 同deviceの選択nodeを設定します
	decltype( &SetupDiSetSelectedDriverW)	   setSelected{} ;
	/// 同deviceの選択nodeを読み戻します
	decltype( &SetupDiGetSelectedDriverW)	   getSelected{} ;
	/// 検査済みclass installerへのDIFです
	decltype( &SetupDiCallClassInstaller)	   callInstaller{} ;
	/// 操作が所有するfile queueを開きます
	decltype( &SetupOpenFileQueue)			   openQueue{} ;
	/// 原queueの種類別件数を読みます
	decltype( &SetupGetFileQueueCount)		   queueCount{} ;
	/// 原queueの各公開tupleを読みます
	decltype( &SetupScanFileQueueW)			   scanQueue{} ;
	/// 同原INFの一節を制御queueへ追加します
	decltype( &SetupQueueCopySectionW)		   queueSection{} ;
	/// 照合済みqueueをcommitします
	decltype( &SetupCommitFileQueueW)		   commitQueue{} ;
	/// 操作が所有するqueueだけを閉じます
	decltype( &SetupCloseFileQueue)			   closeQueue{} ;
	/// 同原INFをWindows readerで開きます
	decltype( &SetupOpenInfFileW)			   openInf{} ;
	/// 操作が開いたINFを閉じます
	decltype( &SetupCloseInfFile)			   closeInf{} ;
	/// 登録INFに対応するDriver Store内の正式位置を照会します
	decltype( &SetupGetInfDriverStoreLocationW) storeLocation{} ;
	/// MTDのSystem32原targetを解決した同Windows rootを取得します
	decltype( &GetWindowsDirectoryW)			   windowsDirectory{} ;
	/// class登録のread-only確認用keyを開きます
	decltype( &SetupDiOpenClassRegKeyExW)	   openClassKey{} ;
	/// device登録のread-only確認用keyを開きます
	decltype( &SetupDiOpenDevRegKey)			   openDeviceKey{} ;
	/// setup classのinstaller/co-installer propertyを読みます
	decltype( &SetupDiGetClassPropertyW)		   classProperty{} ;
	/// 元登録値の型と全byteを読みます
	decltype( &RegQueryValueExW)				   queryRegistry{} ;
	/// 同操作のregistry keyを閉じます
	decltype( &RegCloseKey)					   closeRegistry{} ;
	/// 親と既存target又は新規tempを開きます
	decltype( &CreateFileW)					   createFile{} ;
	/// file identityと通常file属性を読みます
	decltype( &GetFileInformationByHandle)	   fileInfo{} ;
	/// file identity等の型付き情報を読みます
	decltype( &GetFileInformationByHandleEx)	   fileInfoEx{} ;
	/// file handleの実pathを再確認します
	decltype( &GetFinalPathNameByHandleW)	   finalPath{} ;
	/// 同正規target volumeの残容量を照会します
	decltype( &GetDiskFreeSpaceExW)			   freeSpace{} ;
	/// 同handleのownerとDACLを読みます
	decltype( &GetSecurityInfo)				   securityInfo{} ;
	/// Windowsが返すsecurity領域を返却します
	decltype( &LocalFree)					   localFree{} ;
	/// source又は完成済みtempの原byteを読みます
	decltype( &ReadFile)						   readFile{} ;
	/// 新規tempだけへ原byteを書きます
	decltype( &WriteFile)					   writeFile{} ;
	/// 新規tempの完全書込みをflushします
	decltype( &FlushFileBuffers)				   flushFile{} ;
	/// 同handleを非置換配置又は所有tempの片付けへ使います
	decltype( &SetFileInformationByHandle)	   setFileInfo{} ;
	/// 操作が所有するfile handleだけを閉じます
	decltype( &CloseHandle)					   closeHandle{} ;
} ;
/** @brief 独自クラスの状態と同じOEM INFの配置先を読み取る完全API表 */
struct DeclarativeClassTransport {
	/// 対象クラス、元の端末と登録値を読み取る
	SetupClassReadApi						   observation ;
	/// 登録済みOEM INFに対応する元パッケージの位置を取得する
	decltype( &SetupGetInfDriverStoreLocationW) storeLocation{} ;
} ;
/** @brief 判定・node選択・bindingは本体へ残した完全な低位API表です */
struct Transport {
	/// 現在state属性の同backend。一つもnativeへ補完しません
	DriverStoreInventoryTransport			   inventory ;
	/// SetupDiCreateDeviceInfoListと同ABIの固定低位呼出しです
	decltype( &SetupDiCreateDeviceInfoList)	   create{} ;
	/// SetupDiOpenDeviceInfoWと同ABIの固定低位呼出しです
	decltype( &SetupDiOpenDeviceInfoW)		   open{} ;
	/// SetupDiBuildDriverInfoListと同ABIの固定低位呼出しです
	decltype( &SetupDiBuildDriverInfoList)	   build{} ;
	/// SetupDiEnumDriverInfoWと同ABIの固定低位呼出しです
	decltype( &SetupDiEnumDriverInfoW)		   enumerate{} ;
	/// SetupDiGetDriverInfoDetailWと同ABIの固定低位呼出しです
	decltype( &SetupDiGetDriverInfoDetailW)	   detail{} ;
	/// SetupDiGetDeviceInstallParamsWと同ABIの固定低位呼出しです
	decltype( &SetupDiGetDeviceInstallParamsW)  getParameters{} ;
	/// SetupDiSetDeviceInstallParamsWと同ABIの固定低位呼出しです
	decltype( &SetupDiSetDeviceInstallParamsW)  setParameters{} ;
	/// SetupDiGetDriverInstallParamsWと同ABIの固定低位呼出しです
	decltype( &SetupDiGetDriverInstallParamsW)  rank{} ;
	/// SetupDiDestroyDriverInfoListと同ABIの固定低位呼出しです
	decltype( &SetupDiDestroyDriverInfoList)	   destroyDrivers{} ;
	/// SetupCopyOEMInfWと同ABIの固定低位呼出しです
	decltype( &SetupCopyOEMInfW)				   stage{} ;
	/// DiInstallDeviceと同ABIの固定低位呼出しです
	decltype( &DiInstallDevice)				   install{} ;
	/// GetNativeSystemInfoと同ABIの固定低位呼出しです
	decltype( &GetNativeSystemInfo)			   architecture{} ;
	/// GetWindowsDirectoryWと同ABIの既知Windows root照会です。欠損fallbackを認めません
	decltype( &GetWindowsDirectoryW)			   windowsDirectory{} ;
	/// 現在ストレージ機器の登録INFから同じDriver Store内の配置先を取得します
	decltype( &SetupGetInfDriverStoreLocationW) storageStoreLocation{} ;
	/// 同じ保護INFのClass名/GUIDを確認する低位API。欠損native補完はしません
	decltype( &SetupDiGetINFClassW)			   infClass{} ;
	/// exact serviceのpresent device数だけを照会します。全列挙を行いません
	decltype( &CM_Get_Device_ID_List_SizeW)	   serviceDeviceListSize{} ;
	/// SERVICE/PRESENT/DONOTGENERATEに固定した所有関係の読取です
	decltype( &CM_Get_Device_ID_ListW)		   serviceDeviceList{} ;
	/// MTD専用の閉じた低位表です。旧通常/SCSIは空でも動作します
	MtdTransport							   mtd ;
	/// 独自クラスの読み取りを有効にする完全表。内部試験では省略できる
	std::optional<DeclarativeClassTransport>   declarativeClass ;
} ;
struct Access ;
/** @brief 同worker lifetimeの完全API表をscope所有します */
class ScopedFixture final {
public:
	/**
	 * @brief 同workerのAPI表を解除します
	 */
	~ScopedFixture() noexcept ;
	/**
	 * @brief 同worker低位表の所有scopeの複写を禁止します
	 * @param[in] other 複写元として指定できない既存scopeです
	 * @note 削除宣言のため実行・I/O・所有権移動・例外発生はありません
	 */
	ScopedFixture( const ScopedFixture &other) = delete ;
	/**
	 * @brief 同worker低位表の所有scopeの複写代入を禁止します
	 * @param[in] other 代入元として指定できない既存scopeです
	 * @note 呼出しはcompile時に拒否され、外部状態とscopeの寿命を変更しません
	 */
	ScopedFixture &operator=( const ScopedFixture &other) = delete ;

private:
	friend struct Access ;
	/**
	 * @brief 全guardが使用する完全表を固定します
	 * @param[in] calls Nativeを含まない完全fake表
	 */
	explicit ScopedFixture( Transport calls) noexcept ;
	/// このworkerだけが借りる固定API表
	Transport				calls_ ;
	/**
	 * @brief 製品nativeまたは同worker固定完全表を参照します
	 * @return 同期呼出し中有効な借用参照。欠損fallbackはありません
	 */
	friend const Transport &transport() noexcept ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 製品nativeまたは同worker固定完全表を参照します
 * @return 同期呼出し中有効な借用参照。欠損fallbackはありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] const Transport &transport() noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 同workerでMTD操作に必要な全低位slotを確認します
 * @return 全slotがある場合だけtrueです。欠損時のnative補完はありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool			   mtdTransportReady() noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 同workerへ完全fake表が固定されているか確認します
 * @return 内部scopeの生存中だけtrueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool			   fixtureActive() noexcept ;
// 完全fake factoryだけを内部試験へ提供します
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @brief 同workerの生存期間へ低位APIだけを固定する内部factoryです */
struct Access {
	/**
	 * @brief 欠損・native混在・scope上書きを拒否します
	 * @param[in] calls 完全なfake WinAPI表。成功DTOを受けません
	 * @return 完全表だけを所有するscope。不足時はnullptrです
	 */
	[[nodiscard]] static std::unique_ptr<ScopedFixture> create( Transport calls) ;
} ;
#endif
} // namespace drivercrate::driver_store_inf_detail
