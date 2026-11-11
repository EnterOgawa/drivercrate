//------------------------------------------------------------------------------
/**
 * @file driver_store_provider.cpp
 * @brief Driver Store provider実装。
 * @version 01.24.01
 * @date 2026/10/24
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Binding指定INF導入を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  個別binding破棄境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Device列挙進捗通知追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Setup class GUID取得追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通scan条件対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  検証済み外部INF導入境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local coverage集計追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Local探索経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  PnP rank非退行監査追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Windows管理監査状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  現在版を推奨候補にしないよう修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  端末内binding生成境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Local列挙計測と上限終端確認を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Device観測と読取り失敗時の表示保持を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  現在版を要求しない単一INF適合観測を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  Native IDから有限bus分類だけを現在行へ追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/11  種別別の同scan秘密snapshotと失効resolverを追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/12  Native初回状態と登録INF root/実byteの再検証を接続。
 * Ver.01.06.01 Shunji Ogawa  2026/10/12  Session失効時の重複stage cache清掃を整理。
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.07.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.08.00 Shunji Ogawa  2026/10/13  元Class未確定の真初回と実INF/native Class拘束を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  同親と必要SWC子だけの指定APIと未確認役割を分離。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  元INF完全pathとbounded detailから必要構成を再確認。
 * Ver.01.11.00 Shunji Ogawa  2026/10/14  明示local liveの索引resolverへ匿名分岐診断を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/14  公表INFとnativeの両ID役割を照合し既知部分根拠を発行。
 * Ver.01.12.01 Shunji Ogawa  2026/10/15  必要roleの登録INFを計画終端まで変更非共有で保持。
 * Ver.01.13.00 Shunji Ogawa  2026/10/15  必要INF bindingの拒否段階を非機密数値として採取。
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  実選択Needs件数を必要計画の再検証へ結合。
 * Ver.01.14.01 Shunji Ogawa  2026/10/17  Native IDの実一文字NULだけを明示空listとして検証。
 * Ver.01.15.00 Shunji Ogawa  2026/10/24  原公開PnPのcaseを保持して既存native照合keyへ結合。
 * Ver.01.16.00 Shunji Ogawa  2026/10/27  完全個別観測と初回Hardware根拠から専用証拠を発行。
 * Ver.01.17.00 Shunji Ogawa  2026/10/27  元完全tuple内の唯一最小Windows rankを固定し直前再選択。
 * Ver.01.17.01 Shunji Ogawa  2026/10/28  同ID二件の元proof寿命を選択batch終端まで保持。
 * Ver.01.18.00 Shunji Ogawa  2026/10/28  選択対象の導入後実観測と現在行の自動更新を接続。
 * Ver.01.19.00 Shunji Ogawa  2026/11/06  元CopyINF stage内容と別deviceの機能導入を分離。
 * Ver.01.20.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合。
 * Ver.01.21.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続。
 * Ver.01.22.00 Shunji Ogawa  2026/11/09  導入後の一回fresh候補再評価と元表示保持を接続。
 * Ver.01.23.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続。
 * Ver.01.24.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続。
 * Ver.01.24.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note SetupAPIによるPnP deviceとDriver Store履歴の列挙を実装します。選択された指定版は実行直前に再照合します。Native device identityと
 *       INF pathはworker内だけで保持します。
 */
//------------------------------------------------------------------------------

#include "core/index_capacity_limits.h"
#include "platform/driver_store_provider.h"
#include "platform/driver_store_inf_transport_internal.h"

#include "core/device_observation.h"
#include "core/metadata_search_budget.h"

#include "platform/official_catalog_device.h"
#include "platform/official_discovery_inventory.h"
#include "platform/official_release_local_probe.h"

#include "core/candidate_audit.h"
#include "core/provider_registry.h"
#include "core/scan_measurement.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/common_driver_package.h"
#include "platform/official_file_verifier.h"
// Windows.h は SetupAPI の基本型より先、initguid.h は DEVPROPKEY 定義より先に必要である。
// clang-format off
#include <Windows.h>
#include <Objbase.h>
#include <SetupAPI.h>
#include <initguid.h>
#include <devpkey.h>
#include <devguid.h>
#include <newdev.h>
#include <cfg.h>
// clang-format on

#include <algorithm>
#include <array>
#include <cwchar>
#include <cwctype>
#include <cstring>
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
#include <cstdio>
#endif
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace driver_store_inf_detail {
// 本worker lifetimeだけの内部fixture。製品は常にnullptrです。
thread_local ScopedFixture *activeFixture = nullptr ;
//------------------------------------------------------------------------------
/**
 * @brief 同workerへ完全fake表が固定されているか確認します。
 * @return 内部scopeの生存中だけtrueです。
 */
//------------------------------------------------------------------------------
bool						fixtureActive() noexcept
{
	return activeFixture != nullptr ;
}
// 製品が使用する変更不能な完全Windows API表です。
const Transport NATIVE_CALLS{.inventory		   = {},
							 .create		   = SetupDiCreateDeviceInfoList,
							 .open			   = SetupDiOpenDeviceInfoW,
							 .build			   = SetupDiBuildDriverInfoList,
							 .enumerate		   = SetupDiEnumDriverInfoW,
							 .detail		   = SetupDiGetDriverInfoDetailW,
							 .getParameters	   = SetupDiGetDeviceInstallParamsW,
							 .setParameters	   = SetupDiSetDeviceInstallParamsW,
							 .rank			   = SetupDiGetDriverInstallParamsW,
							 .destroyDrivers   = SetupDiDestroyDriverInfoList,
							 .stage			   = SetupCopyOEMInfW,
							 .install		   = DiInstallDevice,
							 .architecture	   = GetNativeSystemInfo,
							 .windowsDirectory = GetWindowsDirectoryW,
							 .infClass		   = SetupDiGetINFClassW} ;
//------------------------------------------------------------------------------
/**
 * @brief 全guardが使用する完全表を固定します。
 * @param[in] calls Nativeを含まない完全fake表。
 */
//------------------------------------------------------------------------------
ScopedFixture::ScopedFixture( Transport calls) noexcept : calls_( std::move( calls))
{
	activeFixture = this ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同workerのAPI表を解除します。
 */
//------------------------------------------------------------------------------
ScopedFixture::~ScopedFixture() noexcept
{
	// 別workerや既存scopeのtableを解除しません。
	if( activeFixture == this) {
		activeFixture = nullptr ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 製品nativeまたは同worker固定完全表を参照します。
 * @return 同期呼出し中有効な借用参照。欠損fallbackはありません。
 */
//------------------------------------------------------------------------------
const Transport &transport() noexcept
{
	return activeFixture ? activeFixture->calls_ : NATIVE_CALLS ;
}
// 固定低位表のfactoryは内部test構成へ限定します。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
//------------------------------------------------------------------------------
/**
 * @brief 欠損・native混在・scope上書きを拒否します。
 * @param[in] calls 完全なfake WinAPI表。成功DTOを受けません。
 * @return 完全表だけを所有するscope。不足時はnullptrです。
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedFixture> Access::create( Transport calls)
{
	// 欠損やnative混在を拒否し、fixture要求で実OSを変更しません。
	if( activeFixture || !calls.create || calls.create == SetupDiCreateDeviceInfoList ||
	   !calls.open || calls.open == SetupDiOpenDeviceInfoW || !calls.build ||
	   calls.build == SetupDiBuildDriverInfoList || !calls.enumerate ||
	   calls.enumerate == SetupDiEnumDriverInfoW || !calls.detail ||
	   calls.detail == SetupDiGetDriverInfoDetailW || !calls.getParameters ||
	   calls.getParameters == SetupDiGetDeviceInstallParamsW || !calls.setParameters ||
	   calls.setParameters == SetupDiSetDeviceInstallParamsW || !calls.rank ||
	   calls.rank == SetupDiGetDriverInstallParamsW || !calls.destroyDrivers ||
	   calls.destroyDrivers == SetupDiDestroyDriverInfoList || !calls.stage ||
	   calls.stage == SetupCopyOEMInfW || !calls.install || calls.install == DiInstallDevice ||
	   !calls.architecture || calls.architecture == GetNativeSystemInfo || !calls.inventory.open ||
	   !calls.windowsDirectory || calls.windowsDirectory == GetWindowsDirectoryW ||
	   !calls.infClass || calls.infClass == SetupDiGetINFClassW ||
	   calls.inventory.open == SetupDiGetClassDevsW || !calls.inventory.enumerate ||
	   calls.inventory.enumerate == SetupDiEnumDeviceInfo || !calls.inventory.property ||
	   calls.inventory.property == SetupDiGetDevicePropertyW || !calls.inventory.instanceId ||
	   calls.inventory.instanceId == SetupDiGetDeviceInstanceIdW || !calls.inventory.close ||
	   calls.inventory.close == SetupDiDestroyDeviceInfoList || !calls.inventory.nodeStatus ||
	   calls.inventory.nodeStatus == CM_Get_DevNode_Status) {
		return nullptr ;
	}

	return std::unique_ptr<ScopedFixture>{new ScopedFixture( std::move( calls))} ;
}
#endif
} // namespace driver_store_inf_detail
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr DWORD MAXIMUM_DEVICE_PROPERTY_BYTES = 64U * 1024U ;	// Device property受信上限（byte）。
constexpr DWORD MAXIMUM_DRIVER_DETAIL_BYTES	  = 64U * 1024U ;	// Driver detail受信上限（byte）。
constexpr DWORD MAXIMUM_DEVICE_INSTANCE_CHARACTERS = 4096 ;		// Instance ID上限（UTF-16文字）。
constexpr DWORD MAXIMUM_DEVICES			   = 4096 ;				// 一回のscanで列挙するpresent device数の上限。
constexpr DWORD MAXIMUM_DRIVERS_PER_DEVICE = 512 ;				// 一deviceで列挙するcompatible driver数上限。
constexpr std::size_t MAXIMUM_TOTAL_CANDIDATES		= 32768 ;	// 全device合計candidate数上限。
constexpr std::size_t MAXIMUM_OFFICIAL_INF_BINDINGS = 4096U ;	// 一scanの公式INF binding上限。
constexpr int		  GUID_STRING_CHARACTERS		= 39 ;		// Brace付きGUIDと終端nullのUTF-16文字数。

// 通常経路が使う不変のWindows API表。実行中のglobal差替えを行わない。
const DriverStoreInventoryTransport NATIVE_INVENTORY_TRANSPORT{} ;

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief HDEVINFO を SetupDiDestroyDeviceInfoList で解放する RAII wrapper である。
 */
class DeviceInfoSet					final {
public:
	/**
     * @brief 指定 handle の device information set ownership を取得する。
     * @param[in] value `SetupDiGetClassDevsW` が返した handle。
     * @param[in] transport Handle生成元のAPI表。Close関数をcopyして保持する。
     */
	//------------------------------------------------------------------------------
	explicit DeviceInfoSet( const HDEVINFO						value,
										   const DriverStoreInventoryTransport &transport =
											   driver_store_inf_detail::transport().inventory) noexcept
		: value_( value), close_( transport.close)
	{
	}

	/**
     * @brief 有効な device information set handle を解放する。
     */
	//------------------------------------------------------------------------------
	~DeviceInfoSet()
	{
		// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
		if( value_ != INVALID_HANDLE_VALUE) {
			close_( value_) ;
		}
	}

	// 一つのHDEVINFOを重複解放しないようcopyを禁止する。
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	DeviceInfoSet( const DeviceInfoSet &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	DeviceInfoSet		  &operator=( const DeviceInfoSet &) = delete ;

	/**
     * @brief 所有する device information set handle を返す。
     * @return 呼出し側へ ownership を移さない HDEVINFO。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HDEVINFO get() const noexcept
	{
		return value_ ;
	}

	/**
     * @brief 所有 handle が SetupAPI の失敗 sentinel でないかを判定する。
     * @return 解放可能な handle の場合は `true`。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] bool valid() const noexcept
	{
		return value_ != INVALID_HANDLE_VALUE ;
	}

private:
	/// DestroyDeviceInfoListで解放する所有handle。
	HDEVINFO								value_{INVALID_HANDLE_VALUE} ;
	/// 同じbackendの解放関数。API表自体の寿命へ依存しない。
	decltype( &SetupDiDestroyDeviceInfoList) close_{
		driver_store_inf_detail::transport().inventory.close} ;
} ;

/**
 * @brief device に関連付けた compatible driver list を確実に破棄する RAII guard である。
 */
class DriverInfoList final {
public:
	/**
     * @brief 指定 device に構築される compatible driver list の解放条件を保持する。
     * @param[in] set device information set。
     * @param[in,out] device list を構築する対象 device metadata。
     * 指定 device に構築される compatible driver listの解放条件を保持する。
     */
	//------------------------------------------------------------------------------
	DriverInfoList( const HDEVINFO set, SP_DEVINFO_DATA &device) noexcept
		: set_( set), device_( &device)
	{
	}

	/**
     * @brief 構築済みの場合だけ compatible driver list を破棄する。
     */
	//------------------------------------------------------------------------------
	~DriverInfoList()
	{
		// 構築が成功した互換driver listに対してだけSetupAPIの解放を行う。
		if( built_) {
			driver_store_inf_detail::transport().destroyDrivers( set_, device_, SPDIT_COMPATDRIVER) ;
		}
	}

	// 同一compatible listを重複破棄しないようcopyを禁止する。
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	DriverInfoList( const DriverInfoList &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	DriverInfoList &operator=( const DriverInfoList &) = delete ;

	/**
     * @brief compatible driver list の構築成功を記録する。
     */
	//------------------------------------------------------------------------------
	void			markBuilt() noexcept
	{
		built_ = true ;
	}

private:
	/// Driver listを所有する非所有device information set。
	HDEVINFO		 set_{} ;
	/// 呼出し元がlifetimeを保持する非所有device metadata。
	SP_DEVINFO_DATA *device_{} ;
	/// trueの場合だけdestructorでcompatible listを破棄する。
	bool			 built_{} ;
} ;

/**
 * @brief 現在使用中の driver を表示・比較するための local metadata である。
 */
struct CurrentDriverMetadata {
	/// 現在driverのINF file名。
	std::wstring				 infFileName ;
	/// 現在driverのprovider名。
	std::wstring				 provider ;
	/// 現在driverの表示version。
	std::wstring				 version ;
	/// 現在driverのYYYY/MM/DD表示日付。
	std::wstring				 date ;
	/// 解釈できたpacked version。
	std::optional<std::uint64_t> packedVersion ;
	/// INF属性の読取り結果。生file名はこのworker内だけに保持する。
	DevicePropertyReadStatus	 infRead ;
	/// Provider属性の読取り結果。
	DevicePropertyReadStatus	 providerRead ;
	/// 現在版属性の読取り結果。
	DevicePropertyReadStatus	 versionRead ;
	/// 日付属性の読取り結果。
	DevicePropertyReadStatus	 dateRead ;
} ;

/**
 * @brief driver node の導入時再照合に使用する非公開 metadata である。
 */
struct DriverDetail {
	/// Candidate driver nodeのINF file名。
	std::wstring infFileName ;
	/// Candidate driver nodeのinstall section名。
	std::wstring sectionName ;
} ;

/**
 * @brief G11-D監査中だけ保持する現在deviceとdriverの秘密metadataである。
 */
struct DeviceRankSnapshot {
	/// 現在deviceのsetup class名。
	std::wstring					   deviceClass ;
	/// 原Class propertyの不存在/空/失敗を区別した状態です。
	DevicePropertyReadStatus		   classRead ;
	/// 原ClassGUID propertyの型付き読取状態です。
	DevicePropertyReadStatus		   classGuidRead ;
	/// 原ClassGUID propertyの値。不存在時は空です。
	std::wstring					   observedClassGuid ;
	/// 再open直後のClassGUID。一覧構築で変更されるmetadataと分離します。
	std::wstring					   nativeClassGuid ;
	/// 原ClassとGUIDが整合した観測方式。未知現在driverを初回へ補完しません。
	OfficialDriverRankDeviceClassState classState{OfficialDriverRankDeviceClassState::KNOWN_CLASS} ;
	/// 具体性順のdevice Hardware ID群。
	std::vector<std::wstring>		   hardwareIds ;
	/// 具体性順のdevice Compatible ID群。
	std::vector<std::wstring>		   compatibleIds ;
	/// Windowsが現在driverに使用したPnP ID。
	std::wstring					   matchingDeviceId ;
	/// Matching IDの正式不存在を空文字や読取失敗と区別します。
	DevicePropertyReadStatus		   matchingRead ;
	/// 現在driver nodeの再照合metadata。
	CurrentDriverMetadata			   currentDriver ;
	/// NativeでPresent/Code28/全属性欠損/installed-node不在を確認した場合だけtrueです。
	bool							   noDriver{} ;
	/// 同一照会のdevnode statusとproblem。直前変化を検出するためworker内で保持します。
	DeviceNodeObservation			   node ;
	/// 生driver keyの読取り状態。欠損をAPI失敗から区別します。
	DevicePropertyReadStatus		   driverKeyRead ;
	/// 現在driver keyのworker内限定値。
	std::wstring					   driverKey ;
} ;

/**
 * @brief 単一外部INFから一意に特定したWindows compatible driver nodeである。
 */
struct CandidateDriverNodeSnapshot {
	/// 同じ検査済みINFがWindowsへ申告したClassGUIDです。
	std::wstring  infClassGuid ;
	/// 単一INFの互換一覧が返したClassGUIDです。元device観測とは別軸です。
	std::wstring  classGuid ;
	/// SetupAPIが返したinstall section名。
	std::wstring  sectionName ;
	/// SetupAPIが返したProvider表示名。
	std::wstring  provider ;
	/// SetupAPIが返した4要素version。
	std::wstring  version ;
	/// SetupAPIが返したYYYY/MM/DD日付。
	std::wstring  date ;
	/// SetupAPIが返したpacked version。
	std::uint64_t packedVersion{} ;
	/// SetupAPIが返したFILETIME日付。
	std::uint64_t dateTicks{} ;
	/// SetupAPIが算出したfull Windows rank。
	std::uint32_t rank{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 error を NativeError に保持できる HRESULT へ変換する。
 *
 * @param[in] error `GetLastError` が返した値。
 * @return HRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

/** @brief 登録先照合中のfile/directory handleを単独所有します。 */
class RegisteredInfHandle final {
public:
	/**
	 * @brief 未取得handleを作ります。
	 */
	RegisteredInfHandle() = default ;
	/**
	 * @brief 取得したhandleだけを解放します。
	 */
	~RegisteredInfHandle() noexcept
	{
		// 所有している一handleだけをWindowsへ返します。
		if( valid()) {
			CloseHandle( handle_) ;
		}
	}
	/**
	 * @brief Handleの二重所有を禁止します。
	 */
	RegisteredInfHandle( const RegisteredInfHandle &) = delete ;
	/**
	 * @brief Handleのcopy代入を禁止します。
	 */
	RegisteredInfHandle &operator=( const RegisteredInfHandle &) = delete ;
	/**
	 * @brief 新しい一handleの所有だけを取得します。
	 * @param[in] handle CreateFileWの返却値。INVALID_HANDLE_VALUEも保持できます。
	 */
	void				 reset( HANDLE handle) noexcept
	{
		// 以前の取得に成功している場合だけ古いhandleを返します。
		if( valid()) {
			CloseHandle( handle_) ;
		}

		handle_ = handle ;
	}
	/**
	 * @brief 読取り用の借用handleを返します。
	 * @return このguardの生存中だけ有効なhandleです。
	 */
	[[nodiscard]] HANDLE get() const noexcept
	{
		return handle_ ;
	}
	/**
	 * @brief Handle取得が成功しているか確認します。
	 * @return NullとINVALID_HANDLE_VALUE以外だけtrueです。
	 */
	[[nodiscard]] bool valid() const noexcept
	{
		return handle_ && handle_ != INVALID_HANDLE_VALUE ;
	}

private:
	/// 同scope内だけで所有するfile/directory handle。
	HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

/** @brief 登録rootと元INF/登録INFを指定導入終端までpinし、実byte一致を確認します。 */
class RegisteredInfGuard final {
public:
	/**
	 * @brief 既知Windows INF rootと元保護INFを変更不能な読取りへ固定します。
	 * @param[in] source 元保護workspaceの完全INF path。
	 * @return 全root/source確認成功0、元API失敗またはpath拒否HRESULTです。
	 */
	[[nodiscard]] NativeError initialize( const std::wstring &source)
	{
		std::array<wchar_t, MAX_PATH> directory{} ;	// 同backendの既知Windows rootだけです。
		const auto length = driver_store_inf_detail::transport().windowsDirectory(
			directory.data(),
			// Native/defaultまたは完全fake。
			static_cast<UINT>( directory.size())) ;
		// 切詰めや不正終端のrootから登録先を推測しません。
		if( length == 0U || length >= directory.size() || directory[length] != L'\0' ||
		   std::find( directory.begin(), directory.begin() + length, L'\0') !=
			   directory.begin() + length) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::wstring windowsRoot{directory.data(),
									   length} ;	// 元返却rootは正規化で範囲を広げません。
		// UNC/相対rootや再解析されたWindows directoryを登録先へ認めません。
		if( windowsRoot.size() < 3U || windowsRoot[1] != L':' || windowsRoot[2] != L'\\' ||
		   windowsRoot.find( L'/', 0U) != std::wstring::npos || windowsRoot.back() == L'\\') {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		const auto windowsAttributes = GetFileAttributesW( windowsRoot.c_str()) ;	// Rootの実属性。
		rootPath_					 = windowsRoot + L"\\INF" ;
		const auto rootAttributes =
			// 登録直下directoryの実属性。
			GetFileAttributesW( rootPath_.c_str()) ;
		// 欠損/再解析点/通常fileを既知登録directoryへ昇格しません。
		if( windowsAttributes == INVALID_FILE_ATTRIBUTES ||
		   rootAttributes == INVALID_FILE_ATTRIBUTES ||
		   (windowsAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   (rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   ((windowsAttributes | rootAttributes) & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		root_.reset( CreateFileW( rootPath_.c_str(), FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
								FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
								FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
								nullptr)) ;
		const auto sourceAttributes = GetFileAttributesW( source.c_str()) ;	// 元共通検査INFの属性。
		// 元INFの欠損・再解析点・directoryから内容証拠を生成しません。
		if( !root_.valid() || sourceAttributes == INVALID_FILE_ATTRIBUTES ||
		   (sourceAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		source_.reset( CreateFileW( source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
								  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
		// 元INFをwrite/deleteと共有せず、stageと指定導入の間も変更を防ぎます。
		if( !source_.valid()) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		LARGE_INTEGER size{} ;	// 元INFの正の完全byte数。
		// 長さ不明のINFを登録済み内容と比較しません。
		if( !GetFileSizeEx( source_.get(), &size) || size.QuadPart <= 0) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		sourceBytes_ = static_cast<std::uint64_t>( size.QuadPart) ;
		return computeFileSha256( source, sourceSha256_) ;
	}
	/**
	 * @brief 完全返却pathのroot containmentと元INF全byteを照合します。
	 * @param[in] staged Windows stageが返した未変更の完全path。
	 * @return 登録rootと全byte一致0、それ以外は元HRESULTです。
	 */
	[[nodiscard]] NativeError verify( const std::wstring &staged)
	{
		std::array<wchar_t, MAX_PATH> canonical{} ;	// 相対/別名/脱出を受理しない完全path。
		const auto					  length =
			GetFullPathNameW( staged.c_str(), static_cast<DWORD>( canonical.size()), canonical.data(),
							 nullptr) ;							// 書換えはせず元値との一致を要求します。
		const auto separator = staged.find_last_of( L'\\') ;	// 登録root直下の親境界。
		// 部分prefixや..、別root、nested directoryを登録先と扱いません。
		if( length == 0U || length >= canonical.size() || staged.size() != length ||
		   CompareStringOrdinal( staged.c_str(), -1, canonical.data(), -1, TRUE) != CSTR_EQUAL ||
		   separator == std::wstring::npos || separator + 1U >= staged.size() ||
		   CompareStringOrdinal( staged.substr( 0U, separator).c_str(), -1, rootPath_.c_str(), -1,
								TRUE) != CSTR_EQUAL) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		const auto attributes = GetFileAttributesW( staged.c_str()) ;	// 実登録fileの属性。
		// 登録pathの通常file以外を指定導入へ渡しません。
		if( attributes == INVALID_FILE_ATTRIBUTES ||
		   (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		// 最初の正常pathをwrite/deleteと共有せず指定導入終端までpinします。
		if( !staged_.valid()) {
			staged_.reset( CreateFileW( staged.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
									  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
		}

		// 実fileのopen失敗を保護sourceへのfallbackで補いません。
		if( !staged_.valid()) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::array<wchar_t, 1024U> rootFinal{} ;	// Pinしたdirectoryの実解決先。
		std::array<wchar_t, 1024U> stagedFinal{} ;	// Pinした登録fileの実解決先。
		const auto				   rootLength = GetFinalPathNameByHandleW(
			root_.get(), rootFinal.data(), static_cast<DWORD>( rootFinal.size()),
			FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// Pin済みrootの実解決長です。
		const auto stagedLength = GetFinalPathNameByHandleW(
			staged_.get(), stagedFinal.data(), static_cast<DWORD>( stagedFinal.size()),
			FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// Pin済み登録fileの実解決長です。
		// 各pinの実解決先も同directory直下でなければ親再解析/別名を拒否します。
		if( rootLength == 0U || rootLength >= rootFinal.size() || stagedLength == 0U ||
		   stagedLength >= stagedFinal.size()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::wstring expectedFinal = std::wstring{rootFinal.data(), rootLength} +
										   // 直下一fileだけ。
										   staged.substr( separator) ;
		// Rootの文字列一致だけでなくpinした実pathの完全一致を要求します。
		if( CompareStringOrdinal( expectedFinal.c_str(), -1, stagedFinal.data(), -1, TRUE) !=
		   CSTR_EQUAL) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		return verifyOfficialFileMetadata( staged, {sourceBytes_, sourceSha256_}) ;
	}
	/**
	 * @brief Stage cacheを元完全内容へ結合するhashを返します。
	 * @return Guard生存中の元INF SHA-256です。取得権限ではありません。
	 */
	[[nodiscard]] const std::wstring &sourceSha256() const noexcept
	{
		return sourceSha256_ ;
	}

private:
	/// 書換え/deletionと共有しない元INF handle。
	RegisteredInfHandle source_ ;
	/// 同backendの登録INF rootを移動/deletionと共有しないdirectory handle。
	RegisteredInfHandle root_ ;
	/// 書換え/deletionと共有しない登録INF handle。
	RegisteredInfHandle staged_ ;
	/// 完全照合する既知Windows root直下INF directory。
	std::wstring		rootPath_ ;
	/// 元共通検査INFの完全SHA-256。
	std::wstring		sourceSha256_ ;
	/// 元共通検査INFの正の完全byte数。
	std::uint64_t		sourceBytes_{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 大文字小文字を区別しない照合用に Windows identifierを正規化する。
 *
 * @param[in] value Hardware ID または path component。
 * @return invariant な大文字表現。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeIdentifier( const std::wstring_view value)
{
	std::wstring normalized( value) ;	// 大文字へ正規化するmutable識別子。
	// Windows の device identifier は大文字小文字を区別しないため、全 code unit を正規化する。
	std::transform(
		normalized.begin(), normalized.end(), normalized.begin(),
		[]( const wchar_t character) { return static_cast<wchar_t>( std::towupper( character)) ; }) ;
	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief path を UI へ渡さず、照合に必要な file name componentだけを得る。
 *
 * @param[in] path INF path または file name。
 * @return 最後の区切り以降を正規化した値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizedFileName( const std::wstring_view path)
{
	const std::size_t separator = path.find_last_of( L"\\/") ;	// 最後のpath区切り位置。
	return normalizeIdentifier( separator == std::wstring_view::npos ? path
																	: path.substr( separator + 1)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Win32失敗を属性欠損・不正・有限上限と区別して保持する。
 * @param[in] error 元APIまたは検証失敗のcode。0は不正応答として扱う。
 * @return 値を持たない読取り結果。
 */
//------------------------------------------------------------------------------
DevicePropertyReadStatus propertyFailure( const DWORD error) noexcept
{
	DevicePropertyReadState state = DevicePropertyReadState::FAILED ;	// 原因を保持する既定区分。
	// OSが明示したproperty不存在だけを欠損として扱う。
	if( error == ERROR_NOT_FOUND) {
		state = DevicePropertyReadState::NOT_PRESENT ;
	}
	// 型・終端不正や診断なし失敗を通常の欠損と混同しない。
	else if( error == ERROR_INVALID_DATA || error == ERROR_SUCCESS) {
		state = DevicePropertyReadState::INVALID_DATA ;
	}
	// 容量増大や有限上限を再確保ループで回避しない。
	else if( error == ERROR_INSUFFICIENT_BUFFER || error == ERROR_MORE_DATA) {
		state = DevicePropertyReadState::LIMIT_REACHED ;
	}

	return {state,
			{DeviceDiagnosticDomain::WINDOWS_ERROR,
			 error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Propertyを必要量照会と一回の取得で検証する。
 * @param[in] set 借用するdevice information set。
 * @param[in,out] device 同じ集合のdevice metadata。
 * @param[in] key 取得する固定property key。
 * @param[in] expectedType 許可するproperty型。
 * @param[out] bytes 成功時だけ実sizeの値を保持する。失敗時は空。
 * @param[in] transport 同じ集合のAPI表。
 * @return 型・size・API成否を区別した結果。
 * @note STRING_LISTの実一文字はここではbyte境界だけを確認し、内容と終端は専用parserで検証する。
 */
//------------------------------------------------------------------------------
DevicePropertyReadStatus readObservedProperty( const HDEVINFO set, SP_DEVINFO_DATA &device,
											  const DEVPROPKEY &key, const DEVPROPTYPE expectedType,
											  std::vector<std::byte>			  &bytes,
											  const DriverStoreInventoryTransport &transport)
{
	bytes.clear() ;
	DEVPROPTYPE type{} ;		// APIが返した型。
	DWORD		required{} ;	// 必要容量（byte）。
	// 必要容量を一度だけ照会し、二回目の増大時は再確保しない。
	const BOOL	sized	  = transport.property( set, &device, &key, &type, nullptr, 0, &required, 0) ;
	const DWORD sizeError = sized ? ERROR_SUCCESS : GetLastError() ;	// 直前の失敗だけを保持する。
	// 通常の必要量通知以外の失敗は取得を始めず保持する。
	if( !sized && sizeError != ERROR_INSUFFICIENT_BUFFER) {
		return propertyFailure( sizeError) ;
	}

	// 固定上限を超える値は確保しない。
	if( required > MAXIMUM_DEVICE_PROPERTY_BYTES) {
		return propertyFailure( ERROR_MORE_DATA) ;
	}

	// 文字列とFILETIMEの必要量を確保前に検証する。
	if( required == 0U ||
	   (expectedType == DEVPROP_TYPE_STRING && required % sizeof( wchar_t) != 0U) ||
	   (expectedType == DEVPROP_TYPE_STRING_LIST &&
		(required < sizeof( wchar_t) || required % sizeof( wchar_t) != 0U)) ||
	   (expectedType == DEVPROP_TYPE_FILETIME && required != sizeof( FILETIME))) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	std::vector<std::byte> buffer( required) ;	// 上限確認済みの借用API出力領域。
	DWORD				   returned{} ;			// 二回目にAPIが返した実size（byte）。
	// Windows byte buffer境界だけでcastし、型付き値へは検証後にcopyする。
	if( !transport.property( set, &device, &key, &type, reinterpret_cast<PBYTE>( buffer.data()),
						   required, &returned, 0)) {
		return propertyFailure( GetLastError()) ;
	}

	// 成功自己申告でも型・実size・UTF-16境界の不整合を拒否する。
	if( type != expectedType || returned == 0U || returned > required ||
	   (expectedType == DEVPROP_TYPE_STRING && returned % sizeof( wchar_t) != 0U) ||
	   (expectedType == DEVPROP_TYPE_STRING_LIST &&
		(returned < sizeof( wchar_t) || returned % sizeof( wchar_t) != 0U)) ||
	   (expectedType == DEVPROP_TYPE_FILETIME && returned != sizeof( FILETIME))) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	buffer.resize( returned) ;
	bytes = std::move( buffer) ;
	return {DevicePropertyReadState::VALUE, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 文字列の実sizeと終端を検証し、空値と失敗を分離する。
 * @param[in] set 借用するdevice information set。
 * @param[in,out] device 同じ集合のdevice metadata。
 * @param[in] key 固定property key。
 * @param[out] value 成功した文字列。失敗時は空。
 * @param[in] transport 同じ集合のAPI表。
 * @return 値・空・欠損・失敗・不正・上限を区別した結果。
 */
//------------------------------------------------------------------------------
DevicePropertyReadStatus readObservedDeviceString( const HDEVINFO set, SP_DEVINFO_DATA &device,
												  const DEVPROPKEY &key, std::wstring &value,
												  const DriverStoreInventoryTransport &transport)
{
	value.clear() ;
	std::vector<std::byte> bytes ;	// 実際に返されたbyte列だけを保持する。
	// 型・size・API成否を持つ、本文解釈前の結果。
	const auto			   status =
		readObservedProperty( set, device, key, DEVPROP_TYPE_STRING, bytes, transport) ;
	// API未成功の値を文字列として解釈しない。
	if( status.state != DevicePropertyReadState::VALUE) {
		return status ;
	}

	std::wstring text( bytes.size() / sizeof( wchar_t), L'\0') ;	// Alignmentを満たすcopy先。
	std::memcpy( text.data(), bytes.data(), bytes.size()) ;
	const auto end = std::find( text.begin(), text.end(), L'\0') ;	// 実size内の最初の終端。
	// 未終端と埋込みNUL後の余剰を拒否し、初期化領域を成功終端にしない。
	if( end == text.end() || end + 1 != text.end()) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	text.pop_back() ;
	value = std::move( text) ;
	return {value.empty() ? DevicePropertyReadState::EMPTY : DevicePropertyReadState::VALUE, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief DEVPROP_TYPE_STRING property を上限付きで取得する。
 * @param[in] set device information set。
 * @param[in] device 対象 device。
 * @param[in] key property key。
 * @param[out] value 取得できた文字列。
 * @param[in] transport 同じ情報集合を生成したAPI表。本呼出し中だけ借用する。
 * @return property を取得できた場合は `true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDeviceString(
	const HDEVINFO set, SP_DEVINFO_DATA &device, const DEVPROPKEY &key, std::wstring &value,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	const auto status =
		// 型付き観測。
		readObservedDeviceString( set, device, key, value, transport) ;
	const bool success = status.state == DevicePropertyReadState::VALUE ||
						 // 旧bool APIでは正規空文字も成功とする。
						 status.state == DevicePropertyReadState::EMPTY ;
	// 既存呼出し側が参照する診断を、今回の結果だけへ固定する。
	SetLastError( success ? ERROR_SUCCESS : status.diagnostic.code) ;
	return success ;
}

//------------------------------------------------------------------------------
/**
 * @brief DEVPROP_TYPE_STRING_LIST property を上限付きで取得する。
 *
 * @param[in] set device information set。
 * @param[in] device 対象 device。
 * @param[in] key property key。
 * @return 検証済みの各文字列。未定義または不正な property は空集合。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::wstring> readDeviceStringList( const HDEVINFO	   set,
															 SP_DEVINFO_DATA  &device,
															 const DEVPROPKEY &key)
{
	DEVPROPTYPE type{} ;		// SetupAPIが返すproperty型。
	DWORD		required{} ;	// MULTI_SZ取得に必要なbuffer size（byte）。
	driver_store_inf_detail::transport().inventory.property( set, &device, &key, &type, nullptr, 0,
															&required, 0) ;
	// 文字列listの最小終端・UTF-16境界・容量上限を確保前に検証する。
	if( GetLastError() != ERROR_INSUFFICIENT_BUFFER || required < sizeof( wchar_t) * 2U ||
	   required > MAXIMUM_DEVICE_PROPERTY_BYTES || required % sizeof( wchar_t) != 0) {
		return {} ;
	}

	std::vector<std::byte> buffer( required) ;	// 上限検証後に確保するMULTI_SZ受信領域。
	// 再取得に失敗したpropertyと文字列list型でないpropertyを照合へ渡さない。
	if( driver_store_inf_detail::transport().inventory.property(
		   set, &device, &key, &type, reinterpret_cast<PBYTE>( buffer.data()), required, nullptr,
		   0) == FALSE ||
	   type != DEVPROP_TYPE_STRING_LIST) {
		return {} ;
	}

	const auto		 *text = reinterpret_cast<const wchar_t *>( buffer.data()) ;	// MULTI_SZ先頭位置。
	const std::size_t characters = buffer.size() / sizeof( wchar_t) ;				// Buffer内のUTF-16文字数。
	std::vector<std::wstring> values ;												// 検証済みのproperty各要素。
	std::size_t				  offset{} ;											// 現在読み取る要素のbuffer内文字offset。

	// MULTI_SZ の二重 NUL までを buffer 上限内で走査する。
	while( offset < characters && text[offset] != L'\0') {
		const std::size_t	 remaining = characters - offset ;	// 未走査のUTF-16文字数。
		const wchar_t *const begin	   = text + offset ;		// 現在要素の先頭位置。
		// 現在要素の終端null位置。
		const wchar_t *const terminator = std::find( begin, begin + remaining, L'\0') ;
		// 残りbuffer内に終端がないlist要素を部分的に採用しない。
		if( terminator == begin + remaining) {
			return {} ;
		}

		// 現在要素の終端nullを除く文字数。
		const std::size_t length = static_cast<std::size_t>( terminator - begin) ;
		values.emplace_back( text + offset, length) ;
		offset += length + 1 ;
	}

	return values ;
}

//------------------------------------------------------------------------------
/**
 * @brief device instance IDを有限取得し、失敗と不正な応答を分離する。
 *
 * @param[in] set device information set。
 * @param[in] device 対象 device。
 * @param[out] instanceId worker 内だけで保持する instance ID。
 * @param[in] transport 同じ情報集合を生成したAPI表。本呼出し中だけ借用する。
 * @return 値または失敗の区分。失敗時のinstanceIdは空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DevicePropertyReadStatus readObservedInstanceId(
	const HDEVINFO set, SP_DEVINFO_DATA &device, std::wstring &instanceId,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	instanceId.clear() ;
	DWORD	   required{} ;	// Instance ID取得に必要なUTF-16文字数。
	const BOOL sized =
		// 必要文字数照会。
		transport.instanceId( set, &device, nullptr, 0, &required) ;
	const DWORD error = sized ? ERROR_SUCCESS : GetLastError() ;	// 当該APIの診断。
	// 容量通知以外の失敗をmissingや空文字へ変換しない。
	if( !sized && error != ERROR_INSUFFICIENT_BUFFER) {
		return propertyFailure( error) ;
	}

	// 上限を超えるidentityは再確保せず打ち切る。
	if( required > MAXIMUM_DEVICE_INSTANCE_CHARACTERS) {
		return propertyFailure( ERROR_MORE_DATA) ;
	}

	// 空identityをnative照合へ登録しない。
	if( required < 2U) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	std::vector<wchar_t> buffer( required, L'\xffff') ;	// 初期0を終端として採用しない受信領域。
	DWORD				 returned{} ;					// 実際に返されたNUL込み文字数。
	// instance IDの再取得に失敗した場合は未確定値を返さない。
	if( transport.instanceId( set, &device, buffer.data(), required, &returned) == FALSE) {
		return propertyFailure( GetLastError()) ;
	}

	// API成功でも実sizeが不正なら確保領域の余りを文字列にしない。
	if( returned < 2U || returned > required) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	buffer.resize( returned) ;

	const auto end =
		// 確保済み範囲内の終端だけを許す。
		std::find( buffer.begin(), buffer.end(), L'\0') ;
	// API成功でも未終端bufferを無制限の文字列constructorへ渡さない。
	if( end == buffer.end() || end == buffer.begin() || end + 1 != buffer.end()) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	instanceId.assign( buffer.begin(), end) ;
	return {DevicePropertyReadState::VALUE, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存のnative照合へ有限なinstance IDを渡す。
 * @param[in] set 借用device集合。
 * @param[in,out] device 同じ集合のdevice。
 * @param[out] instanceId 成功時のID。失敗時は空。
 * @param[in] transport 集合と同じAPI表。
 * @return 有効な非空IDを取得した場合true。失敗診断をGetLastErrorへ保持する。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDeviceInstanceId(
	const HDEVINFO set, SP_DEVINFO_DATA &device, std::wstring &instanceId,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	const auto status = readObservedInstanceId( set, device, instanceId, transport) ;	// 型付き観測。
	SetLastError( status.state == DevicePropertyReadState::VALUE ? ERROR_SUCCESS
																: status.diagnostic.code) ;
	return status.state == DevicePropertyReadState::VALUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief installed driver の FILETIME property を日付表示へ変換する。
 *
 * @param[in] set device information set。
 * @param[in] device 対象 device。
 * @param[out] date 成功時のYYYY/MM/DD。失敗時は空。
 * @param[in] transport 同じ情報集合を生成したAPI表。本呼出し中だけ借用する。
 * @return 日付の読取り・変換結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DevicePropertyReadStatus readObservedDriverDate(
	const HDEVINFO set, SP_DEVINFO_DATA &device, std::wstring &date,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	date.clear() ;
	std::vector<std::byte> bytes ;	// 検証済みFILETIMEのbyte列。
	const auto			   status =
		readObservedProperty( set, device, DEVPKEY_Device_DriverDate, DEVPROP_TYPE_FILETIME, bytes,
							 transport) ;	// 固定型・固定size検証。
	// 不明日付を0時刻や現在時刻へ補完しない。
	if( status.state != DevicePropertyReadState::VALUE) {
		return status ;
	}

	FILETIME value{} ;	// Alignmentを満たすUTC値のcopy先。
	std::memcpy( &value, bytes.data(), sizeof( value)) ;

	SYSTEMTIME systemTime{} ;	// 表示用に分解したUTC driver日付。
	// FILETIMEを有効なcalendar値へ変換できなければ日付を推測しない。
	if( FileTimeToSystemTime( &value, &systemTime) == FALSE) {
		auto failure  = propertyFailure( GetLastError()) ;	// 変換APIの元診断を直ちに保持する。
		failure.state = DevicePropertyReadState::INVALID_DATA ;
		return failure ;
	}

	std::array<wchar_t, 16> formatted{} ;	// YYYY/MM/DDと終端nullの受信領域。
	// 終端nullを除いて整形されたUTF-16文字数。
	const int written = swprintf_s( formatted.data(), formatted.size(), L"%04u/%02u/%02u",
								   systemTime.wYear, systemTime.wMonth, systemTime.wDay) ;
	// 不正calendarや表示容量不足を正規の空日付にしない。
	if( written <= 0) {
		return propertyFailure( ERROR_INVALID_DATA) ;
	}

	date.assign( formatted.data(), static_cast<std::size_t>( written)) ;
	return {DevicePropertyReadState::VALUE, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一回のConfiguration Manager照会から有限なnode状態を得る。
 * @param[in] device 列挙したdevice。DevInstを同じmachineでのみ使用する。
 * @param[in] transport 照会するread-only API表。
 * @return 元CONFIGRETまたは成功時のstatus／problem。秘密を保持しない。
 */
//------------------------------------------------------------------------------
DeviceNodeObservation readObservedNode( const SP_DEVINFO_DATA			   &device,
									   const DriverStoreInventoryTransport &transport) noexcept
{
	ULONG			flags{} ;	// 同一呼出しで得るstatus bit集合。
	ULONG			problem{} ;	// DN_HAS_PROBLEM時だけ有効なcode。
	const CONFIGRET result =
		// 元APIの戻り値。
		transport.nodeStatus( &flags, &problem, device.DevInst, 0) ;
	// GetLastErrorとは別のCONFIGRETをそのまま保持する。
	if( result != CR_SUCCESS) {
		return {{DevicePropertyReadState::FAILED,
				 {DeviceDiagnosticDomain::CONFIGURATION_MANAGER, result}},
				{},
				{}} ;
	}

	DeviceNodeObservation observed{
		{DevicePropertyReadState::VALUE, {}}, flags, {}} ;	// 成功した一組。
	// 有効bitがないときはAPI出力bufferのproblemを採用しない。
	if( (flags & DN_HAS_PROBLEM) != 0U) {
		observed.problemCode = problem ;
	}

	// 成功自己申告でも不整合を持つ一組は値を破棄する。
	if( !isDeviceNodeObservationValid( observed)) {
		return {propertyFailure( ERROR_INVALID_DATA), {}, {}} ;
	}

	return observed ;
}

//------------------------------------------------------------------------------
/**
 * @brief DWORDLONG 形式の driver version を四要素へ整形する。
 *
 * @param[in] version SP_DRVINFO_DATA が返した version。
 * @return `a.b.c.d` 形式。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatDriverVersion( const std::uint64_t version)
{
	return std::to_wstring( (version >> 48U) & 0xFFFFU) + L"." +
		   std::to_wstring( (version >> 32U) & 0xFFFFU) + L"." +
		   std::to_wstring( (version >> 16U) & 0xFFFFU) + L"." + std::to_wstring( version & 0xFFFFU) ;
}

//------------------------------------------------------------------------------
/**
 * @brief setup class GUIDをcanonical文字列へ変換する。
 *
 * Windows固有のGUID型をcore DTOに公開せず、UIがSetupAPI class iconを選択できる文字列へ変換する。
 *
 * @param[in] classGuid SP_DEVINFO_DATAが返したsetup class GUID。
 * @return Brace付きcanonical GUID文字列。変換失敗時は空文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatClassGuid( const GUID &classGuid)
{
	std::array<wchar_t, GUID_STRING_CHARACTERS> text{} ;	// GUID文字列の受信領域。
	const int									written =
		// 終端込み文字数。
		StringFromGUID2( classGuid, text.data(), static_cast<int>( text.size())) ;
	return written > 1 ? std::wstring( text.data(), static_cast<std::size_t>( written - 1))
					   : std::wstring{} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 四要素までの表示 version を DWORDLONG へ変換する。
 *
 * @param[in] version device property が返した version。
 * @return 全要素が 16-bit 範囲で解釈できた場合の packed version。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseDriverVersion( const std::wstring_view version)
{
	std::array<std::uint64_t, 4> parts{} ;		// 左から最大四個の16-bit version要素。
	std::size_t					 partIndex{} ;	// 次に格納するparts内index。
	std::size_t					 offset{} ;		// 次に解析するversion文字列内offset。

	// 最大四要素を左から読み、空要素、非数字、16-bit 超過を拒否する。
	while( offset < version.size() && partIndex < parts.size()) {
		const std::size_t separator = version.find( L'.', offset) ;	// 次の区切り位置。
		// 現在要素の終端位置。
		const std::size_t end = separator == std::wstring_view::npos ? version.size() : separator ;
		// 空のversion componentをゼロで補って比較しない。
		if( end == offset) {
			return std::nullopt ;
		}

		std::uint64_t value{} ;	// 現在解析中のversion要素値。
		// 現在要素の全文字を10進数字として検証し、16-bit上限内で組み立てる。
		for( std::size_t index = offset; index < end; ++index) {
			// version componentにASCII数字以外を許可しない。
			if( version[index] < L'0' || version[index] > L'9') {
				return std::nullopt ;
			}

			value = value * 10U + static_cast<std::uint64_t>( version[index] - L'0') ;
			// DWORDLONGの一componentに対応する16-bit範囲を超える値を拒否する。
			if( value > 0xFFFFU) {
				return std::nullopt ;
			}
		}

		parts[partIndex] = value ;
		++partIndex ;
		// dotが残っていない場合は入力末尾まで消費済みとして確定する。
		if( separator == std::wstring_view::npos) {
			offset = version.size() ;
		} else {
			offset = separator + 1 ;
		}
	}

	// component未取得と四要素に収まらない残余入力を拒否する。
	if( partIndex == 0 || offset < version.size()) {
		return std::nullopt ;
	}

	return (parts[0] << 48U) | (parts[1] << 32U) | (parts[2] << 16U) | parts[3] ;
}

//------------------------------------------------------------------------------
/**
 * @brief FILETIME を日付文字列へ変換する。
 *
 * @param[in] value driver metadata の UTC 日付。
 * @return `YYYY/MM/DD` または空文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatDriverDate( const FILETIME &value)
{
	SYSTEMTIME systemTime{} ;	// 表示用に分解したUTC driver日付。
	// 無効なFILETIMEは空表示とし、推測の日付を返さない。
	if( FileTimeToSystemTime( &value, &systemTime) == FALSE) {
		return {} ;
	}

	std::array<wchar_t, 16> formatted{} ;	// YYYY/MM/DDと終端nullの受信領域。
	// 終端nullを除いて整形されたUTF-16文字数。
	const int written = swprintf_s( formatted.data(), formatted.size(), L"%04u/%02u/%02u",
								   systemTime.wYear, systemTime.wMonth, systemTime.wDay) ;
	return written > 0 ? std::wstring( formatted.data(), static_cast<std::size_t>( written))
					   : std::wstring{} ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF DriverVerの日付を検証してWindows node表示形式へ揃える。
 *
 * 区切りと全数字を検証し、Windowsの暦日変換を往復して存在しない日付をfail-closedで拒否する。
 *
 * @param[in] value INF DriverVerのMM/DD/YYYY日付。
 * @return 妥当な暦日のYYYY/MM/DD表記。不正な場合は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeInfDriverDate( const std::wstring_view value)
{
	// INF DriverVer日付の固定長とslash位置が一致しなければ拒否する。
	if( value.size() != 10U || value[2U] != L'/' || value[5U] != L'/') {
		return std::nullopt ;
	}

	// 区切り以外をASCII数字へ限定し、locale依存の解釈を避ける。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		// 日付の数字位置にASCII数字以外を許可しない。
		if( index != 2U && index != 5U && (value[index] < L'0' || value[index] > L'9')) {
			return std::nullopt ;
		}
	}

	// INF表記から取得する月。
	const WORD month = static_cast<WORD>( (value[0U] - L'0') * 10 + (value[1U] - L'0')) ;
	// INF表記から取得する日。
	const WORD day = static_cast<WORD>( (value[3U] - L'0') * 10 + (value[4U] - L'0')) ;
	// INF表記から取得する西暦年。
	const WORD year = static_cast<WORD>( (value[6U] - L'0') * 1000 + (value[7U] - L'0') * 100 +
										(value[8U] - L'0') * 10 + (value[9U] - L'0')) ;
	SYSTEMTIME source{} ;	// INF値から構築する検証前の暦日。
	source.wYear  = year ;
	source.wMonth = month ;
	source.wDay	  = day ;
	FILETIME fileTime{} ;	// Windowsの暦日検証を通したUTC FILETIME。
	// calendar値をFILETIMEへ変換できなければ不正日付として拒否する。
	if( SystemTimeToFileTime( &source, &fileTime) == FALSE) {
		return std::nullopt ;
	}

	SYSTEMTIME roundTrip{} ;	// 自動補正がないことを確認する往復後の暦日。
	// calendarのround-tripで年月日が変化する値を実在日付として扱わない。
	if( FileTimeToSystemTime( &fileTime, &roundTrip) == FALSE || roundTrip.wYear != year ||
	   roundTrip.wMonth != month || roundTrip.wDay != day) {
		return std::nullopt ;
	}

	std::wstring normalized = formatDriverDate( fileTime) ;	// Windows node比較用表記。
	// 検証済み日付でも表示形式を生成できなければ未確定として返す。
	if( normalized.empty()) {
		return std::nullopt ;
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief FILETIME の bit pattern を比較・再照合用整数へ変換する。
 *
 * @param[in] value 変換元 FILETIME。
 * @return 64-bit tick 値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t fileTimeTicks( const FILETIME &value) noexcept
{
	ULARGE_INTEGER ticks{} ;	// FILETIMEのlow/highを連結する共用体。
	ticks.LowPart  = value.dwLowDateTime ;
	ticks.HighPart = value.dwHighDateTime ;
	return ticks.QuadPart ;
}

//------------------------------------------------------------------------------
/**
 * @brief driver node の INF と section metadata を上限付きで取得する。
 *
 * driver node の INF と section metadataを上限付きで取得する。
 *
 * @param[in] set device information set。
 * @param[in] device 対象 device。
 * @param[in] driver driver node metadata。
 * @param[out] detail UI へ公開しない照合 metadata。
 * @return 取得できた場合は `true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDriverDetail( const HDEVINFO set, SP_DEVINFO_DATA &device,
									SP_DRVINFO_DATA_W &driver, DriverDetail &detail)
{
	detail = {} ;
	DWORD required{} ;	// Driver detail取得に必要なbuffer size（byte）。
	SetLastError( ERROR_SUCCESS) ;
	driver_store_inf_detail::transport().detail( set, &device, &driver, nullptr, 0, &required) ;
	// driver詳細の必要量が構造体以上かつ上限以下でなければ確保しない。
	if( GetLastError() != ERROR_INSUFFICIENT_BUFFER || required < sizeof( SP_DRVINFO_DETAIL_DATA_W) ||
	   required > MAXIMUM_DRIVER_DETAIL_BYTES || required % sizeof( wchar_t) != 0U) {
		return false ;
	}

	std::vector<std::byte> buffer( required) ;	// 上限検証後に確保するdetail受信領域。
	// Buffer上の可変長SP_DRVINFO_DETAIL_DATA view。
	auto *nativeDetail	 = reinterpret_cast<SP_DRVINFO_DETAIL_DATA_W *>( buffer.data()) ;
	nativeDetail->cbSize = sizeof( SP_DRVINFO_DETAIL_DATA_W) ;
	DWORD returned{} ;	// 可変IDを含む二回目の必要byte長です。固定fieldだけのFALSEと分けます。
	// static fieldを得たINSUFFICIENT_BUFFERでも完全detail成功へ昇格しません。
	if( driver_store_inf_detail::transport().detail( set, &device, &driver, nativeDetail, required,
												   &returned) == FALSE) {
		return false ;
	}

	const auto infEnd =
		std::find( std::begin( nativeDetail->InfFileName), std::end( nativeDetail->InfFileName),
				  L'\0') ;	// 固定MAX_PATHの範囲内終端です。
	const auto sectionEnd =
		std::find( std::begin( nativeDetail->SectionName), std::end( nativeDetail->SectionName),
				  L'\0') ;	// 固定LINE_LENの範囲内終端です。
	// byte容量、再照会必要長、固定文字列の終端を別々に検証します。
	if( returned > required || (returned != 0U && returned < sizeof( SP_DRVINFO_DETAIL_DATA_W)) ||
	   infEnd == std::end( nativeDetail->InfFileName) ||
	   sectionEnd == std::end( nativeDetail->SectionName)) {
		SetLastError( ERROR_INVALID_DATA) ;
		return false ;
	}

	detail.infFileName.assign( nativeDetail->InfFileName, infEnd) ;
	detail.sectionName.assign( nativeDetail->SectionName, sectionEnd) ;
	return !detail.infFileName.empty() && !detail.sectionName.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief compatible driver list を構築するための device install parameter を設定する。
 *
 * @param[in] set device information set。
 * @param[in] device 対象 device。
 * @return 設定できた場合は `true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool configureCompatibleDriverSearch( const HDEVINFO set, SP_DEVINFO_DATA &device)
{
	SP_DEVINSTALL_PARAMS_W parameters{} ;	// Compatible list構築条件を保持するparameter。
	parameters.cbSize = sizeof( parameters) ;
	// 現在のinstall parameterを取得できなければ互換listの条件を変更しない。
	if( driver_store_inf_detail::transport().getParameters( set, &device, &parameters) == FALSE) {
		return false ;
	}

	// PnP driver の多くは ExcludeFromSelect のため、この flag がないと履歴を列挙できない。
	parameters.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS ;
	return driver_store_inf_detail::transport().setParameters( set, &device, &parameters) != FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在使用中 driver の表示・照合 metadata を取得する。
 *
 * @param[in] set device information set。
 * @param[in] device 対象 device。
 * @param[in] transport 同じ情報集合を生成したAPI表。本呼出し中だけ借用する。
 * @return property がない項目を空値とした metadata。
 */
//------------------------------------------------------------------------------
[[nodiscard]] CurrentDriverMetadata readCurrentDriver(
	const HDEVINFO set, SP_DEVINFO_DATA &device,
	const DriverStoreInventoryTransport &transport = driver_store_inf_detail::transport().inventory)
{
	CurrentDriverMetadata current ;	// Property欠損を空値で保持する現在driver metadata。
	current.infRead		  = readObservedDeviceString( set, device, DEVPKEY_Device_DriverInfPath,
													 current.infFileName, transport) ;
	current.providerRead  = readObservedDeviceString( set, device, DEVPKEY_Device_DriverProvider,
													 current.provider, transport) ;
	current.versionRead	  = readObservedDeviceString( set, device, DEVPKEY_Device_DriverVersion,
													 current.version, transport) ;
	current.dateRead	  = readObservedDriverDate( set, device, current.date, transport) ;
	current.packedVersion = parseDriverVersion( current.version) ;
	return current ;
}

//------------------------------------------------------------------------------
/**
 * @brief 再open直後のClass名/GUIDを失敗と未確定から区別します。
 * @param[in] set 同deviceを所有する借用集合です。
 * @param[in,out] device 一覧構築前の元deviceです。Classを推測更新しません。
 * @param[in] inventory 同backendの完全property表です。
 * @param[out] snapshot 元Class観測と方式だけを保存します。不正時は許可を発行しません。
 * @return 整合した観測なら0、失敗/不正/上限なら元HRESULTです。
 * @note Worker内で同期使用し、公開recordやnetworkを参照しません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDeviceClassSnapshot( const HDEVINFO set, SP_DEVINFO_DATA &device,
												  const DriverStoreInventoryTransport &inventory,
												  DeviceRankSnapshot				  &snapshot)
{
	snapshot.nativeClassGuid = formatClassGuid( device.ClassGuid) ;
	snapshot.classRead		 = readObservedDeviceString( set, device, DEVPKEY_Device_Class,
														snapshot.deviceClass, inventory) ;
	std::vector<std::byte> bytes ;	// GUID propertyの型付き実byteです。
	snapshot.classGuidRead = readObservedProperty( set, device, DEVPKEY_Device_ClassGuid,
												  DEVPROP_TYPE_GUID, bytes, inventory) ;
	const std::array reads{&snapshot.classRead, &snapshot.classGuidRead} ;	// 原診断の固定二軸です。
	// API失敗/不正型/容量上限をClassの不存在へ変換しません。
	for( const auto *read : reads) {
		// 明示的な不存在以外の失敗を元HRESULTへ保持します。
		if( read->state == DevicePropertyReadState::FAILED ||
		   read->state == DevicePropertyReadState::INVALID_DATA ||
		   read->state == DevicePropertyReadState::LIMIT_REACHED) {
			return nativeErrorFromWin32( read->diagnostic.code != 0U ? read->diagnostic.code
																	: ERROR_INVALID_DATA) ;
		}
	}

	GUID observed{} ;	// 検証した実GUID propertyの値だけです。
	// 値を返したGUIDはSDK幅と元node GUIDの一致を必須にします。
	if( snapshot.classGuidRead.state == DevicePropertyReadState::VALUE) {
		// 短いGUIDや同device内のClass矛盾を許可へ補完しません。
		if( bytes.size() != sizeof( observed)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::memcpy( &observed, bytes.data(), sizeof( observed)) ;
		snapshot.observedClassGuid = formatClassGuid( observed) ;
		// 元nodeとpropertyが異なる観測を同一Classと扱いません。
		if( !IsEqualGUID( observed, device.ClassGuid)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	const bool nativeUnknown = IsEqualGUID( device.ClassGuid, GUID_NULL) ||
							   // 既知GUIDを欠損名から推測しません。
							   IsEqualGUID( device.ClassGuid, GUID_DEVCLASS_UNKNOWN) ;
	// 正式不存在とnull/Unknown native値の整合を別方式へ保持します。
	if( snapshot.classRead.state == DevicePropertyReadState::NOT_PRESENT && nativeUnknown &&
	   (snapshot.classGuidRead.state == DevicePropertyReadState::NOT_PRESENT ||
		snapshot.classGuidRead.state == DevicePropertyReadState::VALUE)) {
		snapshot.classState = OfficialDriverRankDeviceClassState::NOT_PRESENT ;
		return 0U ;
	}

	// 正式Unknown名は正式Unknown GUIDと型付き実propertyがある場合だけ認めます。
	if( snapshot.classRead.state == DevicePropertyReadState::VALUE &&
	   normalizeIdentifier( snapshot.deviceClass) == L"UNKNOWN" &&
	   snapshot.classGuidRead.state == DevicePropertyReadState::VALUE &&
	   IsEqualGUID( device.ClassGuid, GUID_DEVCLASS_UNKNOWN)) {
		snapshot.classState = OfficialDriverRankDeviceClassState::UNKNOWN_CLASS ;
		return 0U ;
	}

	// 空文字・曖昧name/GUID・既知nameと未知GUIDを未確定初回へ転用しません。
	if( snapshot.classRead.state != DevicePropertyReadState::VALUE || nativeUnknown ||
	   normalizeIdentifier( snapshot.deviceClass) == L"UNKNOWN" ||
	   snapshot.classGuidRead.state != DevicePropertyReadState::VALUE) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	snapshot.classState = OfficialDriverRankDeviceClassState::KNOWN_CLASS ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのdevice監査snapshotが同じ実状態を表すか判定する。
 *
 * 監査中のdevice変更を検出し、異なる時点の根拠を混在させない。
 *
 * @param[in] left Rank取得前のdevice監査snapshot。
 * @param[in] right Rank取得後のdevice監査snapshot。
 * @return Rank判定に使用する全metadataが一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool deviceRankSnapshotsEqual( const DeviceRankSnapshot &left,
											const DeviceRankSnapshot &right) noexcept
{
	return left.deviceClass == right.deviceClass && left.classState == right.classState &&
		   left.classRead.state == right.classRead.state &&
		   left.classGuidRead.state == right.classGuidRead.state &&
		   left.observedClassGuid == right.observedClassGuid &&
		   left.nativeClassGuid == right.nativeClassGuid &&
		   left.matchingRead.state == right.matchingRead.state &&
		   left.hardwareIds == right.hardwareIds && left.compatibleIds == right.compatibleIds &&
		   left.matchingDeviceId == right.matchingDeviceId &&
		   left.currentDriver.infFileName == right.currentDriver.infFileName &&
		   left.currentDriver.provider == right.currentDriver.provider &&
		   left.currentDriver.version == right.currentDriver.version &&
		   left.currentDriver.date == right.currentDriver.date &&
		   left.currentDriver.packedVersion == right.currentDriver.packedVersion &&
		   left.noDriver == right.noDriver && left.node.read.state == right.node.read.state &&
		   left.node.statusFlags == right.node.statusFlags &&
		   left.node.problemCode == right.node.problemCode &&
		   left.driverKeyRead.state == right.driverKeyRead.state &&
		   left.driverKey == right.driverKey ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの公式driver rank監査結果が完全に一致するか判定する。
 *
 * 同じApplicable判断でも根拠が変化した場合は同一視しない。
 *
 * @param[in] left 発行時または呼出側が保持するrank監査結果。
 * @param[in] right 現在のWindows状態から再生成したrank監査結果。
 * @return 全判断値、位置、rank、scoreが一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool officialRankAuditsEqual( const OfficialDriverRankAudit &left,
										   const OfficialDriverRankAudit &right) noexcept
{
	return left.decision == right.decision && left.currentState == right.currentState &&
		   left.currentPosition.kind == right.currentPosition.kind &&
		   left.currentPosition.index == right.currentPosition.index &&
		   left.candidatePosition.kind == right.candidatePosition.kind &&
		   left.candidatePosition.index == right.candidatePosition.index &&
		   left.currentRank == right.currentRank && left.candidateRank == right.candidateRank &&
		   left.currentIdentifierScore == right.currentIdentifierScore &&
		   left.candidateIdentifierScore == right.candidateIdentifierScore ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのcandidate Windows node snapshotが完全一致するか判定。
 *
 * INF名だけが同じ別DDInstall nodeへの差替えを拒否する。
 *
 * @param[in] left Binding発行時のcandidate node。
 * @param[in] right 導入前に再列挙したcandidate node。
 * @return Section、Provider、版、日付、rankが一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool candidateNodeSnapshotsEqual( const CandidateDriverNodeSnapshot &left,
											   const CandidateDriverNodeSnapshot &right) noexcept
{
	return left.infClassGuid == right.infClassGuid && left.classGuid == right.classGuid &&
		   left.sectionName == right.sectionName && left.provider == right.provider &&
		   left.version == right.version && left.date == right.date &&
		   left.packedVersion == right.packedVersion && left.dateTicks == right.dateTicks &&
		   left.rank == right.rank ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一deviceのPnP具体性と現在driver照合metadataを取得する。
 *
 * 新しいdevice information setで実状態を固定し、PnP IDをUI、logまたはnetworkへ渡さない。
 *
 * @param[in] instanceId Worker内だけで保持するdevice instance ID。
 * @param[out] snapshot 成功時の秘密metadata。
 * @return 取得成功時は0、不足またはSetupAPI失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDeviceRankSnapshot( const std::wstring_view instanceId,
												 DeviceRankSnapshot		&snapshot)
{
	snapshot = {} ;
	// 空または途中NULのinstance IDを端末内照合へ渡さない。
	if( instanceId.empty() || instanceId.find( L'\0') != std::wstring_view::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	DeviceInfoSet devices(
		// 一device用set。
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合を作成できない場合はOSの診断を返す。
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const std::wstring nativeInstanceId( instanceId) ;	// API用のnull終端instance ID。
	SP_DEVINFO_DATA	   device{} ;						// Instance IDから再openするdevice metadata。
	device.cbSize = sizeof( device) ;
	// 指定deviceを開けない場合は別deviceへ照合を広げず失敗を返す。
	if( driver_store_inf_detail::transport().open( devices.get(), nativeInstanceId.c_str(), nullptr,
												 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const auto &inventory =
		// 同backendの全propertyです。
		driver_store_inf_detail::transport().inventory ;
	const NativeError classError = readDeviceClassSnapshot( devices.get(), device, inventory,
														   snapshot) ;	// 元Classだけを読みます。
	// ClassのAPI失敗・不正・上限を不存在や正式Unknownへ補完しません。
	if( classError != 0U) {
		return classError ;
	}

	snapshot.hardwareIds = readDeviceStringList( devices.get(), device, DEVPKEY_Device_HardwareIds) ;
	snapshot.compatibleIds =
		readDeviceStringList( devices.get(), device, DEVPKEY_Device_CompatibleIds) ;
	snapshot.matchingRead =
		readObservedDeviceString( devices.get(), device, DEVPKEY_Device_MatchingDeviceId,
								 snapshot.matchingDeviceId, inventory) ;
	snapshot.driverKeyRead = readObservedDeviceString( devices.get(), device, DEVPKEY_Device_Driver,
													  snapshot.driverKey, inventory) ;
	snapshot.node		   = readObservedNode( device, inventory) ;
	snapshot.currentDriver = readCurrentDriver( devices.get(), device) ;
	const std::array<const DevicePropertyReadStatus *, 6U> currentReads{
		&snapshot.driverKeyRead,
		&snapshot.matchingRead,
		&snapshot.currentDriver.infRead,
		&snapshot.currentDriver.providerRead,
		&snapshot.currentDriver.versionRead,
		&snapshot.currentDriver.dateRead} ;	// 明示欠損と元API失敗を混同しません。
	// 現在属性の取得失敗は元Windows診断を返し、NO_DRIVERへ補完しません。
	for( const auto *read : currentReads) {
		// 欠損以外のAPI失敗や不正値を初回/既知どちらのbindingへも採用しません。
		if( read->state == DevicePropertyReadState::FAILED ||
		   read->state == DevicePropertyReadState::INVALID_DATA ||
		   read->state == DevicePropertyReadState::LIMIT_REACHED) {
			return nativeErrorFromWin32( read->diagnostic.code != 0U ? read->diagnostic.code
																	: ERROR_INVALID_DATA) ;
		}
	}

	std::vector<std::byte> presentBytes ;	// 正式BOOLEAN型の実present属性だけです。
	const auto			   presentRead =
		readObservedProperty( devices.get(), device, DEVPKEY_Device_IsPresent, DEVPROP_TYPE_BOOLEAN,
							 presentBytes, inventory) ;	// Opaque scanの旧presentだけを信用しません。
	// Present属性の元Windows読取失敗を単なる不在へ置換しません。
	if( presentRead.state == DevicePropertyReadState::FAILED) {
		return nativeErrorFromWin32( presentRead.diagnostic.code) ;
	}

	// Node statusのCONFIGRETとWindows errorを混同せず変更直前拒否へ保持します。
	if( snapshot.node.read.state == DevicePropertyReadState::FAILED) {
		const auto diagnostic = snapshot.node.read.diagnostic ;	// 当該nodeの元API診断です。
		return nativeErrorFromWin32( diagnostic.domain ==
											DeviceDiagnosticDomain::CONFIGURATION_MANAGER
										? CM_MapCrToWin32Err( diagnostic.code, ERROR_INVALID_DATA)
										: diagnostic.code) ;
	}

	// Device消失・present不明・型不整合を未導入へ補完しません。
	if( presentRead.state != DevicePropertyReadState::VALUE ||
	   presentBytes.size() != sizeof( DEVPROP_BOOLEAN) ||
	   presentBytes.front() != std::byte{static_cast<unsigned char>( DEVPROP_TRUE)} ||
	   snapshot.node.read.state != DevicePropertyReadState::VALUE) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const bool missingDriverProperties =
		snapshot.driverKeyRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.matchingRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.currentDriver.infRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.currentDriver.providerRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.currentDriver.versionRead.state == DevicePropertyReadState::NOT_PRESENT &&
		snapshot.currentDriver.dateRead.state ==
			DevicePropertyReadState::NOT_PRESENT ;	// 全不在の整合根拠。
	// Native Code28だけで現在node不在を推測せず、installed-only listを完全に確認します。
	if( missingDriverProperties &&
	   snapshot.node.problemCode == static_cast<std::uint32_t>( CM_PROB_FAILED_INSTALL) &&
	   snapshot.node.statusFlags && (*snapshot.node.statusFlags & DN_HAS_PROBLEM) != 0U &&
	   (!snapshot.hardwareIds.empty() || !snapshot.compatibleIds.empty())) {
		SP_DEVINSTALL_PARAMS_W parameters{} ;	// 同deviceをinstalled-onlyへ限定する読取り条件。
		parameters.cbSize = sizeof( parameters) ;
		// 現在node一覧の条件が取得不能なら初回bindingを発行しません。
		if( driver_store_inf_detail::transport().getParameters( devices.get(), &device,
															  &parameters) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		parameters.Flags &= ~DI_ENUMSINGLEINF ;
		parameters.FlagsEx |= DI_FLAGSEX_INSTALLEDDRIVER | DI_FLAGSEX_ALLOWEXCLUDEDDRVS ;
		parameters.DriverPath[0] = L'\0' ;
		DriverInfoList installedList{devices.get(), device} ;	// 同backendの一覧を必ず解放します。
		// Installed-only条件と全列挙開始の失敗を欠損へ変換しません。
		if( driver_store_inf_detail::transport().setParameters( devices.get(), &device,
															  &parameters) == FALSE ||
		   driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
			   FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		installedList.markBuilt() ;
		SP_DRVINFO_DATA_W installed{} ;	// 現在nodeが一件でもあれば初回を拒否します。
		installed.cbSize = sizeof( installed) ;
		// Code28と属性欠損に矛盾する実nodeを成功へ補完しません。
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, 0U, &installed) != FALSE) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto installedError = GetLastError() ;	// 完全空終端かAPI失敗かを区別します。
		// 正式な空終端以外は未導入の証明に使用しません。
		if( installedError != ERROR_NO_MORE_ITEMS) {
			return nativeErrorFromWin32( installedError) ;
		}

		snapshot.noDriver = true ;
		return 0U ;
	}

	// Rankを現在driverへ拘束できないproperty欠損は、推測で補わず拒否する。
	if( snapshot.classState != OfficialDriverRankDeviceClassState::KNOWN_CLASS ||
	   snapshot.matchingRead.state != DevicePropertyReadState::VALUE ||
	   snapshot.deviceClass.empty() ||
	   (snapshot.hardwareIds.empty() && snapshot.compatibleIds.empty()) ||
	   snapshot.currentDriver.infFileName.empty() || snapshot.currentDriver.provider.empty() ||
	   !snapshot.currentDriver.packedVersion.has_value()) {
		snapshot = {} ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの外部INFだけをcompatible listの検索対象に設定する。
 *
 * `DI_ENUMSINGLEINF`で候補範囲を一fileへ限定する。Driver Storeへのstage、選択またはinstallは行わない。
 *
 * @param[in] set 対象deviceを所有するinformation set。
 * @param[in] device 対象device metadata。
 * @param[in] infPath G11-C workspace内のnullを含まない絶対path。
 * @return 条件設定成功時は0、入力またはSetupAPI失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError configureSingleInfDriverSearch( const HDEVINFO			 set,
														 SP_DEVINFO_DATA		&device,
														 const std::wstring_view infPath)
{
	SP_DEVINSTALL_PARAMS_W parameters{} ;	// 単一INF list構築条件。
	parameters.cbSize = sizeof( parameters) ;
	// 既存install parameterを取得できなければ外部INF検索条件を変更しない。
	if( driver_store_inf_detail::transport().getParameters( set, &device, &parameters) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 空または途中NULのINF pathをSetupAPIへ渡さない。
	if( infPath.empty() || infPath.find( L'\0') != std::wstring_view::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// INF pathがDriverPath fieldに収まらない場合は切り詰めず拒否する。
	if( infPath.size() >= std::size( parameters.DriverPath)) {
		return nativeErrorFromWin32( ERROR_FILENAME_EXCED_RANGE) ;
	}

	parameters.Flags |= DI_ENUMSINGLEINF ;
	parameters.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS ;
	std::ranges::copy( infPath, parameters.DriverPath) ;
	parameters.DriverPath[infPath.size()] = L'\0' ;
	// 特定INFへの検索条件設定が失敗した場合は広い検索へ戻さず診断を返す。
	if( driver_store_inf_detail::transport().setParameters( set, &device, &parameters) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ保護INFのClass名/GUIDをWindowsへ独立確認します。
 * @param[in] infPath 検査済み実INFの絶対pathです。呼出中だけ借用します。
 * @param[in] expectedClass 内容検査が確認したClass名です。公開recordの値ではありません。
 * @param[out] classGuid 成功時だけ確定するINFのClassGUIDです。不正時はnullです。
 * @return 整合時0、元API失敗または不正応答時HRESULTです。
 * @note Stage/導入やClassのregistry設定を行いません。再試行しません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCandidateInfClass( const std::wstring_view infPath,
												const std::wstring_view expectedClass,
												GUID				   &classGuid)
{
	classGuid = {} ;
	// 絶対pathの元INFと検査済みClassを欠く要求を拒否します。
	if( infPath.empty() || infPath.size() >= MAX_PATH ||
	   infPath.find( L'\0') != std::wstring_view::npos || expectedClass.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring path{infPath} ;						// 作用範囲を固定したnull終端API入力です。
	std::array<wchar_t, MAX_CLASS_NAME_LEN> name{} ;		// SDKの有限Class名受信です。
	DWORD									required{} ;	// 終端込みClass名要素数です。
	GUID									observed{} ;	// 全検証までcallerへ出力しません。
	// 元実INFの読取失敗を内容成功や公開Classへ補完しません。
	if( driver_store_inf_detail::transport().infClass( path.c_str(), &observed, name.data(),
													 static_cast<DWORD>( name.size()),
													 &required) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 型のないClass名bufferも終端/実長/検査済み名/既知GUIDへ照合します。
	if( required <= 1U || required > name.size() || name[required - 1U] != L'\0' ||
	   std::wcslen( name.data()) != required - 1U ||
	   normalizeIdentifier( name.data()) != normalizeIdentifier( expectedClass) ||
	   IsEqualGUID( observed, GUID_NULL) || IsEqualGUID( observed, GUID_DEVCLASS_UNKNOWN)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	classGuid = observed ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief SetupAPIが一driver nodeへ算出したrankを取得する。
 *
 * Rankの算式を再実装せず、SetupAPIが保持する値を正本とする。
 *
 * @param[in] set Compatible listを所有するinformation set。
 * @param[in] device 対象device metadata。
 * @param[in] driver 列挙済みdriver node。
 * @param[out] rank Windowsが算出したfull rank。
 * @return 取得成功時は0、SetupAPI失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDriverRank( const HDEVINFO set, SP_DEVINFO_DATA &device,
										 SP_DRVINFO_DATA_W &driver, std::uint32_t &rank)
{
	SP_DRVINSTALL_PARAMS parameters{} ;	// Driver node固有のinstall parameter。
	parameters.cbSize = sizeof( parameters) ;
	// SetupAPIのrank取得が失敗した場合は順位を推測せず診断を返す。
	if( driver_store_inf_detail::transport().rank( set, &device, &driver, &parameters) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	rank = parameters.Rank ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一deviceのcompatible listから照合対象driverの最良rankを得る。
 *
 * Rank順を仮定せず一致nodeを全件調べ、最良のWindows rankを採用する。Device状態を変更するAPIは呼ばない。
 *
 * @param[in] instanceId Worker内のdevice instance ID。
 * @param[in] singleInfPath Candidate時だけ指定する単一INF path。
 * @param[in] expectedInf 照合するINF file名または絶対path。
 * @param[in] expectedProvider 完全一致させるProvider名。
 * @param[in] expectedVersion 完全一致させるpacked version。
 * @param[in] expectedDate 指定時に完全一致させるYYYY/MM/DD日付。
 * @param[out] rank 一致nodeがあれば最小rank、なければ空値。
 * @param[in] expectedClass 単一INF検索で要求する内容検査済みClass名。現在検索では空です。
 * @param[out] infClassGuid 両GUID出力が非nullの候補検索でだけ更新します。失敗値を権限へ使用しません。
 * @param[out] nativeClassGuid infClassGuidと対で指定する返却候補GUIDです。null可、外へ保持しません。
 * @return 列挙完了時は0、入力またはSetupAPI失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectMatchingDriverRank(
	const std::wstring_view instanceId, const std::optional<std::wstring_view> singleInfPath,
	const std::wstring_view expectedInf, const std::wstring_view expectedProvider,
	const std::uint64_t expectedVersion, const std::optional<std::wstring_view> expectedDate,
	std::optional<std::uint32_t> &rank, const std::wstring_view expectedClass = {},
	std::wstring *infClassGuid = nullptr, std::wstring *nativeClassGuid = nullptr)
{
	rank.reset() ;
	// device・期待INF・publisherが揃わない要求ではrankを照合しない。
	if( instanceId.empty() || expectedInf.empty() || expectedProvider.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	DeviceInfoSet devices(
		// 一device用set。
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合の作成失敗をOSの診断値で返す。
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const std::wstring nativeInstanceId( instanceId) ;	// API用のnull終端instance ID。
	SP_DEVINFO_DATA	   device{} ;						// Rank取得対象device metadata。
	device.cbSize = sizeof( device) ;
	// 指定deviceを開けなければ別deviceへ照合を広げず失敗とする。
	if( driver_store_inf_detail::transport().open( devices.get(), nativeInstanceId.c_str(), nullptr,
												 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	GUID candidateClass{} ;	// 同じ保護INFだけのClassです。元deviceを上書きしません。
	// 候補のClassを公開recordやdevice名から推測せず実INFへ結びます。
	if( singleInfPath) {
		const NativeError classError =
			readCandidateInfClass( *singleInfPath, expectedClass,
								  candidateClass) ;	// 同backendの元INF読取です。
		// Class未確認の候補をWindows適合として公開しません。
		if( classError != 0U) {
			return classError ;
		}
	}

	// 単一INFの指定がある場合はそのINFだけを検索対象へ固定する。
	if( singleInfPath.has_value()) {
		const NativeError configureError =	// 単一candidate INFの検索条件設定結果。
			configureSingleInfDriverSearch( devices.get(), device, singleInfPath.value()) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( configureError != 0) {
			return configureError ;
		}
	}
	// 互換driverの検索条件を設定できなければ既定条件で検索しない。
	else if( !configureCompatibleDriverSearch( devices.get(), device)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// Compatible listのRAII guard。
	// 互換listの構築に失敗した場合はrankを推測せず診断を返す。
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	// 一覧構築で返却されたClassを同INFのClassへ完全一致させます。
	if( singleInfPath && !IsEqualGUID( device.ClassGuid, candidateClass)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 原device Classではなく候補Classの独立証拠だけを出力します。
	if( singleInfPath && infClassGuid && nativeClassGuid) {
		*infClassGuid	 = formatClassGuid( candidateClass) ;
		*nativeClassGuid = formatClassGuid( device.ClassGuid) ;
	}

	bool enumerationComplete{} ;	// ERROR_NO_MORE_ITEMSまで列挙できた場合はtrue。
	// indexはnode位置を表し、有限上限内の同一packageから最良rankを選ぶ。
	for( DWORD index = 0; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 現在照合中のcompatible driver node。
		driver.cbSize = sizeof( driver) ;
		// 列挙APIの終了通知を正常終端と失敗へ分けて処理する。
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			const DWORD error = GetLastError() ;	// 列挙完了またはSetupAPI失敗code。
			// 正常終端以外の列挙失敗を途中までのrank結果で隠さない。
			if( error != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( error) ;
			}

			enumerationComplete = true ;
			break ;
		}

		DriverDetail detail ;	// Driver nodeのINFとsection metadata。
		// driver詳細を取得できなければ照合の完全性を保証できないため中断する。
		if( !readDriverDetail( devices.get(), device, driver, detail)) {
			const DWORD error = GetLastError() ;	// Detail API失敗または不正metadata診断値。
			return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
		}

		const bool matches =	// 現在版または候補版の固定metadataとの完全一致結果。
			normalizedFileName( detail.infFileName) == normalizedFileName( expectedInf) &&
			normalizeIdentifier( driver.ProviderName) == normalizeIdentifier( expectedProvider) &&
			driver.DriverVersion == expectedVersion &&
			(!expectedDate.has_value() ||
			 formatDriverDate( driver.DriverDate) == expectedDate.value()) ;
		// 期待INF・publisher・versionに一致しないnodeをrank比較から除く。
		if( !matches) {
			continue ;
		}

		std::uint32_t	  currentRank{} ;	// 現在一致したdriver nodeのfull Windows rank。
		const NativeError rankError =
			// Rank取得結果。
			readDriverRank( devices.get(), device, driver, currentRank) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( rankError != 0) {
			return rankError ;
		}

		// 一致nodeのうちWindowsが算出した最小rankだけを最良値として保持する。
		if( !rank.has_value() || currentRank < rank.value()) {
			rank = currentRank ;
		}
	}

	// 列挙上限で打ち切った場合は、未確認nodeを無視せず監査失敗にする。
	return enumerationComplete ? 0 : nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 単一外部INFの完全tuple内で唯一最小full-rankのWindows nodeを固定する。
 *
 * 全nodeを有限上限内で正常終端まで列挙し、元INF完全path、Provider、版、日付を満たす
 * nodeの実Windows full rankを比較する。同最良rank複数と読取不足はfail-closedで拒否する。
 *
 * @param[in] instanceId Worker内の秘密device instance ID。
 * @param[in] infPath 保護workspace内の単一INF絶対path。
 * @param[in] expectedClass 同じ実INFの内容検査で確認したClass名です。元device Classではありません。
 * @param[in] expectedProvider 監査済みINFのProvider表示名。
 * @param[in] expectedVersion 監査済みINFのpacked version。
 * @param[in] expectedDate 監査済みINFのYYYY/MM/DD日付。
 * @param[out] snapshot 一意に固定したWindows node metadata。
 * @return 一意なnode取得時は0、不一致、重複またはSetupAPI失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectUniqueCandidateDriverNode( const std::wstring_view instanceId,
														   const std::wstring_view infPath,
														   const std::wstring_view expectedClass,
														   const std::wstring_view expectedProvider,
														   const std::uint64_t	   expectedVersion,
														   const std::wstring_view expectedDate,
														   CandidateDriverNodeSnapshot &snapshot)
{
	snapshot = {} ;
	// device・INF・publisher・日付が欠落した要求ではnodeを固定しない。
	if( instanceId.empty() || infPath.empty() || expectedProvider.empty() || expectedDate.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	DeviceInfoSet devices(
		// 一device用set。
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合の作成失敗時はOSの診断を返す。
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const std::wstring nativeInstanceId( instanceId) ;	// API用のnull終端instance ID。
	SP_DEVINFO_DATA	   device{} ;						// Candidate node取得対象device metadata。
	device.cbSize = sizeof( device) ;
	// 指定deviceを開けない場合はnode固定処理を中止する。
	if( driver_store_inf_detail::transport().open( devices.get(), nativeInstanceId.c_str(), nullptr,
												 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	GUID			  infClass{} ;	// 同検査済み実INFのClassです。元端末Classを変更しません。
	const NativeError classError =
		// 独立した元INF確認です。
		readCandidateInfClass( infPath, expectedClass, infClass) ;
	// Class読取不能をWindows node適合へ補完しません。
	if( classError != 0U) {
		return classError ;
	}

	const NativeError configureError =	// 単一INFだけへ列挙範囲を限定した結果。
		configureSingleInfDriverSearch( devices.get(), device, infPath) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( configureError != 0) {
		return configureError ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// Compatible listのRAII guard。
	// 単一INFの互換listを構築できなければnodeを固定しない。
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	// 未確定deviceでも候補ClassはWindows互換一覧と同INF GUIDの一致で確認します。
	if( !IsEqualGUID( device.ClassGuid, infClass)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	snapshot.infClassGuid = formatClassGuid( infClass) ;
	snapshot.classGuid	  = formatClassGuid( device.ClassGuid) ;
	bool found{} ;					// 完全tupleに一致する最小rankのnodeを保持した場合はtrue。
	bool bestRankTied{} ;			// 現在の最小rankを持つnodeが複数の場合はtrue。
	bool enumerationComplete{} ;	// ERROR_NO_MORE_ITEMSまで確認できた場合はtrue。
	// 全一致nodeの実rankを読み、最後まで確認してから唯一最良を確定する。
	for( DWORD index = 0U; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 現在照合中のcandidate Windows node。
		driver.cbSize = sizeof( driver) ;
		// 列挙APIの終了を正常終端と障害に区別して一意性を確認する。
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			const DWORD error = GetLastError() ;	// 列挙完了またはSetupAPI失敗code。
			// 正常終端以外の列挙障害を部分一致で成功扱いにしない。
			if( error != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( error) ;
			}

			enumerationComplete = true ;
			break ;
		}

		DriverDetail detail ;	// INF file名とDDInstall sectionの秘密metadata。
		// node詳細を取得できなければ一意性確認を中止して診断を返す。
		if( !readDriverDetail( devices.get(), device, driver, detail)) {
			const DWORD error = GetLastError() ;	// Detail取得失敗の診断値。
			return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
		}

		const std::wstring nodeDate = formatDriverDate( driver.DriverDate) ;	// Nodeの暦日。
		const bool		   matches	=											// 監査済みglobal INF metadataとの完全一致結果。
			normalizeIdentifier( detail.infFileName) == normalizeIdentifier( infPath) &&
			normalizeIdentifier( driver.ProviderName) == normalizeIdentifier( expectedProvider) &&
			driver.DriverVersion == expectedVersion && nodeDate == expectedDate ;
		// 期待するINF・publisher・版・日付と一致しないnodeを除外する。
		if( !matches) {
			continue ;
		}

		std::uint32_t	  rank{} ;	// Windowsが現在nodeへ算出したfull rank。
		// 対応driverのrank読取り結果。Rank未確認を適用成功にしないため保持する。
		const NativeError rankError = readDriverRank( devices.get(), device, driver, rank) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( rankError != 0) {
			return rankError ;
		}

		// 同最良の重複は記録し、後続のより低rankで解消できるため列挙を継続する。
		if( found && rank == snapshot.rank) {
			bestRankTied = true ;
			continue ;
		}

		// より悪いrankのnodeは唯一最良のsnapshotを変更しない。
		if( found && rank > snapshot.rank) {
			continue ;
		}

		snapshot.sectionName   = std::move( detail.sectionName) ;
		snapshot.provider	   = driver.ProviderName ;
		snapshot.version	   = formatDriverVersion( driver.DriverVersion) ;
		snapshot.date		   = nodeDate ;
		snapshot.packedVersion = driver.DriverVersion ;
		snapshot.dateTicks	   = fileTimeTicks( driver.DriverDate) ;
		snapshot.rank		   = rank ;
		found				   = true ;
		bestRankTied		   = false ;
	}

	// 列挙上限までに正常終端へ達しなければ一意性を未確定として拒否する。
	if( !enumerationComplete) {
		snapshot = {} ;
		return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
	}

	// 一致nodeまたはそのsectionがない場合は固定snapshotを返さない。
	if( !found || snapshot.sectionName.empty()) {
		snapshot = {} ;
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// 正常終端後にも最小rankが同点なら、先頭のnodeを推測採用しない。
	if( bestRankTied) {
		snapshot = {} ;
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意の既診断へ原errorと最初の拒否だけを保持します。
 * @param[in,out] diagnostic 呼出し元が所有する任意診断です。
 * @param[in] error 元HRESULTです。
 * @param[in] stage 固定拒否位置です。
 * @param[in] observed 元enumまたは件数です。
 * @return 未変更の元HRESULTです。
 */
//------------------------------------------------------------------------------
NativeError bindingFailure( RequiredInfBindingDiagnostic *diagnostic, const NativeError error,
						   const InfBindingReject stage, const std::uint32_t observed = 0U) noexcept
{
	return diagnostic ? diagnostic->reject( error, stage, observed) : error ;
}
//------------------------------------------------------------------------------
/**
 * @brief 公式INF binding用の現在状態とcandidate nodeを同時に固定する。
 * Rank取得の前後で現在INF、版、日付を含む全snapshotを比較し、異なる時点の根拠を一bindingへ混在させない。
 * @param[in] instanceId Worker内の秘密device instance ID。
 * @param[in] infPath 保護workspace内の単一INF絶対path。
 * @param[in] package 内容監査済みINF package metadata。
 * @param[in] candidateVersion INF global版のpacked値。
 * @param[in] candidateDate INF global日付のYYYY/MM/DD表記。
 * @param[out] deviceSnapshot 監査前後で一致した現在device状態。
 * @param[out] candidateSnapshot 一意に固定したWindows node。
 * @param[out] rankAudit 現在状態に対する具体性とrank監査結果。
 * @param[out] diagnostic null可の同期中だけ借用する拒否段階記録先です。記録する失敗branchだけで更新し、それ以外は元値を保持します。
 * @return 状態固定完了時は0、変更、曖昧性またはSetupAPI失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectOfficialInfBindingState(
	const std::wstring_view instanceId, const std::wstring_view infPath,
	const OfficialInfPackage &package, const std::uint64_t candidateVersion,
	const std::wstring_view candidateDate, DeviceRankSnapshot &deviceSnapshot,
	CandidateDriverNodeSnapshot &candidateSnapshot, OfficialDriverRankAudit &rankAudit,
	RequiredInfBindingDiagnostic *diagnostic = nullptr)
{
	deviceSnapshot	  = {} ;
	candidateSnapshot = {} ;
	rankAudit		  = {} ;
	DeviceRankSnapshot before ;														// Rank取得前に固定する現在deviceとdriver状態。
	NativeError		   nativeError = readDeviceRankSnapshot( instanceId, before) ;	// 取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return bindingFailure( diagnostic, nativeError, InfBindingReject::CURRENT_BEFORE) ;
	}

	// 現在driverの日付が未確定なら導入bindingを構築しない。
	if( !before.noDriver && before.currentDriver.date.empty()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::optional<std::uint32_t> currentRank ;	// 現在driver nodeの最良Windows rank。
	// Native未導入では架空current rankを作らず、既知現在driverだけを比較に使用します。
	if( !before.noDriver) {
		nativeError = collectMatchingDriverRank(
			instanceId, std::nullopt, before.currentDriver.infFileName,
			before.currentDriver.provider, before.currentDriver.packedVersion.value(),
			std::wstring_view( before.currentDriver.date), currentRank) ;
	}

	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return bindingFailure( diagnostic, nativeError, InfBindingReject::CURRENT_RANK) ;
	}

	nativeError = collectUniqueCandidateDriverNode( instanceId, infPath, package.className,
												   package.providerName, candidateVersion,
												   candidateDate, candidateSnapshot) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return bindingFailure( diagnostic, nativeError, InfBindingReject::CANDIDATE_NODE) ;
	}

	DeviceRankSnapshot after ;	// Rank取得後に再取得する現在deviceとdriver状態。
	nativeError = readDeviceRankSnapshot( instanceId, after) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return bindingFailure( diagnostic, nativeError, InfBindingReject::CURRENT_AFTER) ;
	}

	// 監査前後でdevice状態が変化した場合は再scanを要求する。
	if( !deviceRankSnapshotsEqual( before, after)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 既知ClassのGUIDが候補INFと異なる場合は名前一致だけで適合としません。
	if( before.classState == OfficialDriverRankDeviceClassState::KNOWN_CLASS &&
	   before.nativeClassGuid != candidateSnapshot.classGuid) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const OfficialDriverRankEvidence evidence{
		// Pure evaluatorへ渡す秘密PnP根拠。
		.deviceClass			  = before.deviceClass,
		.candidateClass			  = package.className,
		.deviceHardwareIds		  = before.hardwareIds,
		.deviceCompatibleIds	  = before.compatibleIds,
		.candidateIds			  = package.hardwareIds,
		.currentMatchingDeviceId  = before.matchingDeviceId,
		.currentRank			  = currentRank,
		.candidateRank			  = candidateSnapshot.rank,
		.currentState			  = before.noDriver ? OfficialDriverRankCurrentState::NO_DRIVER
													: OfficialDriverRankCurrentState::KNOWN_DRIVER,
		.deviceClassState		  = before.classState,
		.candidateInfClassGuid	  = candidateSnapshot.infClassGuid,
		.candidateNativeClassGuid = candidateSnapshot.classGuid,
	} ;
	// 取得した証拠からrank判断を成立させられなければbindingを作らない。
	if( !evaluateOfficialDriverRank( evidence, rankAudit)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	deviceSnapshot = std::move( before) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief driver candidate が現在使用中の package かを判定する。
 *
 * @param[in] current installed driver metadata。
 * @param[in] detail candidate INF metadata。
 * @param[in] driver candidate driver node。
 * @return INF file と version が一致する場合は `true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isCurrentDriver( const CurrentDriverMetadata &current, const DriverDetail &detail,
								   const SP_DRVINFO_DATA_W &driver)
{
	return !current.infFileName.empty() &&
		   normalizedFileName( current.infFileName) == normalizedFileName( detail.infFileName) &&
		   (!current.packedVersion.has_value() ||
			current.packedVersion.value() == driver.DriverVersion) ;
}

//------------------------------------------------------------------------------
/**
 * @brief current version に対する候補操作を表示用に分類する。
 *
 * current version に対する候補操作を表示用に分類する。 注記:この比較は操作の説明だけに使い、compatibilityまたは推奨順位を決定しない。
 *
 * @param[in] current installed driver metadata。
 * @param[in] candidateVersion candidate の packed version。
 * @return update、reinstall、downgrade の分類。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const CurrentDriverMetadata &current,
										  const std::uint64_t		   candidateVersion) noexcept
{
	// 現在版を数値比較できない場合は通常更新と断定せず再導入に分類する。
	if( !current.packedVersion.has_value()) {
		return DriverAction::REINSTALL ;
	}

	// 候補版が現在版より大きい場合だけ表示上の更新に分類する。
	if( candidateVersion > current.packedVersion.value()) {
		return DriverAction::UPDATE ;
	}

	// 候補版が現在版より小さい場合だけ表示上の旧版に分類する。
	if( candidateVersion < current.packedVersion.value()) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 索引の有限ASCII PnP文法を端末内の照合keyに限定します。
 * @param[in] value 公開入力または大文字化した秘密ID。
 * @return 一bus区切り、512文字以下、許可ASCIIだけの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validIndexPnpId( const std::wstring_view value) noexcept
{
	const auto slash = value.find( L'\\') ;	// Bus区切りの位置。
	return value.size() <= 512U && slash != std::wstring_view::npos && slash > 0U &&
		   slash + 1U < value.size() && value.find( L'\\', slash + 1U) == std::wstring_view::npos &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   // UTF-16非ASCIIと制御文字を照合keyへ補正しません。
			   return (character >= L'A' && character <= L'Z') ||
					  (character >= L'a' && character <= L'z') ||
					  (character >= L'0' && character <= L'9') || character == L'\\' ||
					  character == L'&' || character == L'_' || character == L'-' ||
					  character == L'.' || character == L'*' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Native IDの安全な有限ASCIIだけを確認し、公表文法へ制限しません。
 * @param[in] value 元propertyの一ID。
 * @return 1～512文字の非空・非制御ASCIIの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validIndexNativeId( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 512U &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   // Nativeのbuslessやasterisk表記もRAMで保持し、非ASCII・制御文字を拒否します。
			   return character >= L'!' && character <= L'~' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原propertyの型・実size・明示空listまたは二重終端と全IDを検証します。
 * @param[in] set 同scanで所有する集合。
 * @param[in,out] device 同じ集合の現在node。
 * @param[in] key 固定したHardwareまたはCompatible property。
 * @param[in] transport 完全な同backend API表。
 * @param[out] ids 成功した大文字IDだけ。失敗時は空です。
 * @return 全property成功時0、欠損や不正時は元診断に対応するHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readIndexIds( const HDEVINFO set, SP_DEVINFO_DATA &device,
									   const DEVPROPKEY					   &key,
									   const DriverStoreInventoryTransport &transport,
									   std::vector<std::wstring>		   &ids)
{
	ids.clear() ;
	std::vector<std::byte> bytes ;	// 型と実sizeを確認した原byte。
	const auto status = readObservedProperty( set, device, key, DEVPROP_TYPE_STRING_LIST, bytes,
											 transport) ;	// 元propertyの独立した診断。
	// 欠損やAPI失敗を正常な空ID集合へ変換しません。
	if( status.state != DevicePropertyReadState::VALUE) {
		return nativeErrorFromWin32( status.diagnostic.code) ;
	}

	// 空シーケンスの実一文字だけを検査し、確保領域の初期NULで終端を補いません。
	if( bytes.size() == sizeof( wchar_t)) {
		wchar_t emptyMarker{} ;	// Alignmentを持つ実一文字のcopy先です。
		std::memcpy( &emptyMarker, bytes.data(), sizeof( emptyMarker)) ;
		return emptyMarker == L'\0' ? 0U : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// Readerの変更に依存せず、copy先のUTF-16容量と二重終端の最小量を独立確認します。
	if( bytes.size() < sizeof( wchar_t) * 2U || bytes.size() % sizeof( wchar_t) != 0U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring text( bytes.size() / sizeof( wchar_t), L'\0') ;	// Alignmentを持つ受信copy。
	std::memcpy( text.data(), bytes.data(), bytes.size()) ;
	// 実size外の初期値で二重NULを補完しません。
	if( text.size() < 2U || text[text.size() - 1U] != L'\0' || text[text.size() - 2U] != L'\0') {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t offset{} ;	// 実size内の未処理先頭。
	// 最後の二重NULまで有限に進み、全要素成功後だけ出力します。
	while( offset + 1U < text.size() && text[offset] != L'\0') {
		const auto end	 = text.find( L'\0', offset) ;								// 実size内の要素終端。
		const auto rawId = std::wstring_view{text}.substr( offset, end - offset) ;	// 元の秘密ID。
		// 公開schemaのsubsetをNative listの正常性条件へ転用しません。
		if( !validIndexNativeId( rawId)) {
			ids.clear() ;
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto id = normalizeIdentifier( rawId) ;	// 検証済みASCIIだけの秘密key。
		// 不正IDまたは同種別の重複を、部分的な一致へ残しません。
		if( std::find( ids.begin(), ids.end(), id) != ids.end()) {
			ids.clear() ;
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		ids.push_back( id) ;
		offset = end + 1U ;
	}

	// 空list以外の途中二重NULや余剰byteを成功へ丸めません。
	if( offset != text.size() - 1U && !(offset == 0U && text.size() == 2U)) {
		ids.clear() ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0U ;
}

} // namespace

/** @brief 同information setから作り、発行後不変な索引用秘密stateです。 */
struct DriverStoreProvider::IndexInventoryState {
	/** @brief 同scanの一present nodeに属する必要属性だけの秘密観測です。 */
	struct Node {
		/// 同scanのopaque nodeです。
		std::wstring			  identity ;
		/// 既知classの大文字GUID。未知は空です。
		std::wstring			  classGuid ;
		/// 同scanで確認した元Class観測です。公開recordで上書きしません。
		DeviceRankSnapshot		  classObservation ;
		/// Class欠損と失敗を混同しない元HRESULTです。
		NativeError				  classError{} ;
		/// 完全native未導入証拠を持つClass未確定deviceだけtrueです。
		bool					  initialClassUnknown{} ;
		/// 成功した当該種別の秘密IDだけを保持します。
		std::vector<std::wstring> hardware ;
		/// Hardwareへ読み替えない秘密Compatible IDです。
		std::vector<std::wstring> compatible ;
		/// Hardware propertyの元HRESULTです。
		NativeError				  hardwareError{} ;
		/// Compatible propertyの元HRESULTです。
		NativeError				  compatibleError{} ;
	} ;
	/// 発行元のscan sessionです。Install sessionとは独立です。
	ScanSessionId													session{} ;
	/// 単調増加するinventory世代です。
	std::uint64_t													generation{} ;
	/// 実際にscanした所有threadです。
	std::uint32_t													ownerThread{} ;
	/// 元未処理ownerが残る間だけ保持するleaseです。同workerだけが変更します。
	mutable bool													resolutionOpen{true} ;
	/// 原lookup以外の再列挙を不可逆に拒否します。
	mutable bool													lookupFrozen{} ;
	/// 全列挙と二巡目の必要属性captureが完了した場合trueです。
	bool															enumerationComplete{} ;
	/// 部分列挙の元HRESULTです。
	NativeError														enumerationError{} ;
	/// Captureした全present opaque集合です。Raw IDを含みません。
	std::vector<std::wstring>										present ;
	/// 全presentの種別を保持した秘密属性です。任意DTOから受け取りません。
	std::vector<Node>												nodes ;
	/// 秘密IDの元文字列viewから元node ordinalへ引く同state内だけの有限表です。
	std::unordered_map<std::wstring_view, std::vector<std::size_t>> idNodes ;
	/// 両属性のどちらかが失敗したnodeを元class別に全件保持します。空keyは未知classです。
	std::unordered_map<std::wstring_view, std::vector<std::size_t>> failedIdNodes ;
	/// 有限秘密mapに登録した全ID件数です。
	std::size_t														retainedIds{} ;
} ;

/** @brief Providerだけが強所有する秘密stateへの失効可能なcallbackです。 */
class DriverStoreProvider::IndexInventoryResolver final : public IndexPublicIdResolver {
public:
	/**
	 * @brief 秘密stateの所有を増やさずcontextを固定します。
	 * @param[in] state Providerの不変stateへのweak所有。
	 * @param[in] context 本callbackの発行context。
	 * @param[in] lease 同factoryが元stateへ結ぶread-openのweak寿命証拠です。
	 */
	IndexInventoryResolver( std::weak_ptr<const IndexInventoryState>		 state,
						   IndexLookupContext							 context,
						   std::shared_ptr<const NativeIndexLookupLease> lease)
		: state_( std::move( state)), context_( context), lease_( std::move( lease))
	{
	}
	/**
	 * @brief Nativeだけが元inventoryの私有leaseを共有します。
	 * @return 元factory発行の不変証拠の共有所有です。generic callbackでは空です。証拠objectは共有しても元inventory/contextの有効性や権限を
	 *         延長しません。
	 * @note このresolverが既に保持するlease_のshared_ptrを返します。この関数からinventory列挙やleaseの新発行は行いません。
	 */
	[[nodiscard]] std::shared_ptr<const NativeIndexLookupLease> leaseProof() const noexcept override
	{
		return lease_ ;
	}
	/**
	 * @brief 元公開ID役割を保持し、native両集合とClassGUIDを照合します。
	 * @param[in] kind メーカー公表INF側identifierの元役割。native property指定ではありません。
	 * @param[in] publishedId 元公開ASCII ID。端末actual IDではありません。
	 * @param[in] classGuid 元申告ClassGUID。
	 * @param[in] context 現在のworker context。
	 * @param[in] present 現在の有限opaque集合。本呼出し中だけ借用します。
	 * @return 完了区分・元HRESULTとopaque候補集合。全inventory列挙と照合の全完了だけがcompleted trueです。部分集合・列挙失敗・全presentか不明
	 *         な入力ではcompleted falseを返します。DriverStoreの私有証拠がある既知positiveだけを全体不足と分離でき、適合やrankは示しません。
	 * @note 例外は共通入口で診断へ変換されます。同workerから呼び、再入しません。
	 * @note 元scanの弱参照state・所有thread・完全present集合を検査し、保存済みの両ID集合とClassGUIDを照合します。この関数から新しいinventoryを取
	 *       得しません。
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		const IndexPnpIdKind kind, const std::string_view publishedId,
		const std::string_view classGuid, const IndexLookupContext context,
		const std::span<const std::wstring> present) const override
	{
		IndexPublicIdResolution result{context_, false, 0U, {}} ;	// 成功を推測しない初期状態。
		const auto				state = state_.lock() ;				// 呼出し中だけの秘密state所有。
		// 新scan・install・破棄とcontext違いを現在stateへ結び直しません。
		if( !state || !state->resolutionOpen || state->lookupFrozen || context != context_ ||
		   state->ownerThread != GetCurrentThreadId()) {
			result.error = nativeErrorFromWin32( ERROR_INVALID_STATE) ;
			return result ;
		}

		// 全present集合の一部や重複・余剰を照合完了へ変換しません。
		if( present.size() != state->present.size() ||
		   !std::is_permutation( present.begin(), present.end(), state->present.begin())) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}

		const std::wstring originalId( publishedId.begin(),
									  // 公開ASCII入力だけの一時copy。
									  publishedId.end()) ;
		const std::wstring guid( classGuid.begin(), classGuid.end()) ;	// 原申告classの一時copy。
		// 型不明、非ASCII ID、無効GUIDを正常な一致なしへ分類しません。
		if( (kind != IndexPnpIdKind::HARDWARE && kind != IndexPnpIdKind::COMPATIBLE) ||
		   !validIndexPnpId( originalId) || guid.size() != 38U || guid.front() != L'{' ||
		   guid.back() != L'}') {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}

		bool nonzero{} ;	// 未知classの全0表記を拒否します。
		// 固定GUIDの全hexと区切りをRAM内だけで確認します。
		for( std::size_t index = 1U; index < 37U; ++index) {
			const wchar_t value = guid[index] ;	// 原申告の一文字。
			const bool	  separator =
				// 固定区切り。
				index == 9U || index == 14U || index == 19U || index == 24U ;
			// 不正hex・UTF-8 byte・異なる区切りを暗黙補正しません。
			if( separator ? value != L'-'
						 : !((value >= L'0' && value <= L'9') || (value >= L'A' && value <= L'F') ||
							 (value >= L'a' && value <= L'f'))) {
				result.error = static_cast<NativeError>( E_INVALIDARG) ;
				return result ;
			}

			nonzero = nonzero || (!separator && value != L'0') ;
		}

		// 公開全0を既知classへ補完しません。
		if( !nonzero) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}

		result.error = state->enumerationError ;
		// 全present列挙と詳細captureが未完了なら、部分一致で成功にしません。
		if( !state->enumerationComplete) {
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
			std::printf( "INDEX_RESOLVER_DIAGNOSTIC kind=%u enumerationComplete=0 "
						"enumerationError=0x%08lx\n",
						static_cast<unsigned>( kind), static_cast<unsigned long>( result.error)) ;
#endif
			return result ;
		}

		const auto normalizedClass = normalizeIdentifier( guid) ;	// 公開GUIDのcase非依存key。
		const auto id =
			// 原公開IDを変更しない同じnative照合keyです。
			normalizeIdentifier( originalId) ;
		result.completed = true ;
		bool allPositiveClassesKnown{true} ;	// 部分positive証拠へ未知Classを含めません。
		std::vector<bool>
			individualObservations ;	// 各一致nodeの完全個別観測を元cohortと同順に保持します。
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
		std::size_t knownClassIdFailures{} ;			// 同classの必要ID失敗node数です。
		std::size_t unknownClassIdFailures{} ;			// 未知classの必要ID失敗node数です。
		std::size_t missingPropertyFailures{} ;			// 元ERROR_NOT_FOUNDの必要ID失敗数です。
		std::size_t matchingKnownClassNodes{} ;			// 既知classと当種別IDが一致した数です。
		std::size_t matchingUnknownClassNodes{} ;		// 当種別IDだけ一致した未知class数です。
		std::size_t classRejectedNodes{} ;				// ID一致後に元Class観測が拒否された数です。
		std::size_t otherKindKnownClassMatches{} ;		// 別native種別にexact一致した既知Class数です。
		std::size_t otherKindUnknownClassMatches{} ;	// 別native種別にexact一致した未知Class数です。
		std::size_t otherKindReadFailures{} ;			// Queryに影響し得る別native種別の読取拒否数です。
		NativeError firstIdError{} ;					// 最初の必要ID失敗の元HRESULTです。
#endif
		std::vector<std::size_t> relevantNodes ;	// 全cohortと失敗を原node順で処理する有限unionです。
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
		// 詳細診断の別種別非一致件数は元の全node分母を維持します。
		relevantNodes.resize( state->nodes.size()) ;
		// live診断は非一致nodeも原分母へ残すため、全ordinalを順に用意します。
		for( std::size_t ordinal = 0U; ordinal < relevantNodes.size(); ++ordinal) {
			relevantNodes[ordinal] = ordinal ;
		}
#else
		// IDが両native集合のどちらにあっても、元nodeを一度だけ候補へ残します。
		if( const auto found = state->idNodes.find( id) ; found != state->idNodes.end()) {
			relevantNodes = found->second ;
		}

		// 同class/未知classの必要ID失敗は、IDが逆引きに無くても必ず未判定へ残します。
		for( const auto failureClass : {std::wstring_view{normalizedClass}, std::wstring_view{}}) {
			// 同class又は未知classの属性失敗を、逆引き非該当でも未判定へ残します。
			if( const auto found = state->failedIdNodes.find( failureClass) ;
			   found != state->failedIdNodes.end()) {
				relevantNodes.insert( relevantNodes.end(), found->second.begin(),
									 found->second.end()) ;
			}
		}

		std::sort( relevantNodes.begin(), relevantNodes.end()) ;
		relevantNodes.erase( std::unique( relevantNodes.begin(), relevantNodes.end()),
							relevantNodes.end()) ;
#endif
		// 元ordinal順なので、最初のHRESULTとcohort/proofの全順序を変更しません。
		for( const auto ordinal : relevantNodes) {
			const auto &node = state->nodes[ordinal] ;	// 不変captureの元nodeだけを借用します。
			// 既知異classなら、無関係なID欠損を本queryへ持ち込みません。
			if( !node.classGuid.empty() && node.classGuid != normalizedClass) {
				continue ;
			}

#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
			const auto	otherError = kind == IndexPnpIdKind::HARDWARE
										 ? node.compatibleError
										 : node.hardwareError ;	// 判定へ混ぜない別種別の元診断です。
			const auto &otherIds   = kind == IndexPnpIdKind::HARDWARE
										 ? node.compatible
										 : node.hardware ;	// 同scan秘密captureの別種別だけです。
			otherKindReadFailures += otherError != 0U ? 1U : 0U ;
			// 元属性の成功とexact一致だけを匿名件数にし、公開種別を補正しません。
			if( otherError == 0U &&
			   std::find( otherIds.begin(), otherIds.end(), id) != otherIds.end()) {
				otherKindKnownClassMatches += node.classGuid.empty() ? 0U : 1U ;
				otherKindUnknownClassMatches += node.classGuid.empty() ? 1U : 0U ;
			}
#endif
			const NativeError error =
				node.hardwareError != 0U ? node.hardwareError
										 : node.compatibleError ;	// 必要な両native集合の元診断です。
			// 必要IDを読めない同classまたは未知classは不一致と断定しません。
			if( error != 0U) {
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
				knownClassIdFailures += node.classGuid.empty() ? 0U : 1U ;
				unknownClassIdFailures += node.classGuid.empty() ? 1U : 0U ;
				missingPropertyFailures += error == nativeErrorFromWin32( ERROR_NOT_FOUND) ? 1U : 0U ;
				firstIdError = firstIdError != 0U ? firstIdError : error ;
#endif
				result.completed = false ;
				result.error	 = result.error != 0U ? result.error : error ;
				continue ;
			}

			// 公表INF側の役割をnative property指定へ転用せず、両集合のexact不一致を確認します。
			if( std::find( node.hardware.begin(), node.hardware.end(), id) == node.hardware.end() &&
			   std::find( node.compatible.begin(), node.compatible.end(), id) ==
				   node.compatible.end()) {
				continue ;
			}

#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
			matchingKnownClassNodes += node.classGuid.empty() ? 0U : 1U ;
			matchingUnknownClassNodes += node.classGuid.empty() ? 1U : 0U ;
#endif
			// ID一致でも未知classをWindows適合や正常不一致へ分類しません。
			if( node.classError != 0U || (node.classGuid.empty() && !node.initialClassUnknown)) {
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
				++classRejectedNodes ;
#endif
				result.completed = false ;
				result.error	 = result.error != 0U ? result.error : node.classError ;
				continue ;
			}

			result.devices.push_back( node.identity) ;
			allPositiveClassesKnown = allPositiveClassesKnown && !node.classGuid.empty() ;
			individualObservations.push_back(
				!node.classGuid.empty() ||
				(node.initialClassUnknown &&
				 std::ranges::find( node.hardware, id) != node.hardware.end())) ;
		}

		// 全列挙を終えた同scanの既知Class positiveだけに、公開DTOから作れない根拠を付けます。
		if( !result.completed && state->enumerationError == 0U && !result.devices.empty() &&
		   allPositiveClassesKnown) {
			result.positiveProof = std::make_shared<const NativeIndexPositiveProof>(
				NativeIndexPositiveProof::MintKey{}, context_, kind, publishedId, classGuid,
				state->ownerThread, std::weak_ptr<const void>{state}, result.devices, result.error) ;
		}

		// 元列挙と全一致cohortを保ち、最大32deviceだけの完全個別観測へ別の証拠を発行します。
		if( state->enumerationError == 0U && !result.devices.empty() &&
		   result.devices.size() <= 32U &&
		   (result.devices.size() > 1U || (!result.completed && !allPositiveClassesKnown)) &&
		   std::ranges::any_of( individualObservations, []( const bool value) { return value ; })) {
			result.deviceProofs.resize( result.devices.size()) ;
			// 全一致nodeを一度ずつ確認し、未認証の未知Class slotを成功へ変えません。
			for( std::size_t index = 0U; index < result.devices.size(); ++index) {
				// 未知Classは完全初回証拠に加え当該Hardware exact一致を必要とします。
				if( !individualObservations[index]) {
					continue ;
				}

				result.deviceProofs[index] = std::make_shared<const NativeIndexDeviceProof>(
					NativeIndexDeviceProof::MintKey{}, context_, kind, publishedId, classGuid,
					state->ownerThread, std::weak_ptr<const void>{state}, result.devices,
					result.error, result.completed, result.devices[index]) ;
			}
		}

#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
		std::printf(
			"INDEX_RESOLVER_DIAGNOSTIC kind=%u enumerationComplete=1 "
			"enumerationError=0x%08lx knownClassIdFailures=%zu unknownClassIdFailures=%zu "
			"missingPropertyFailures=%zu firstIdError=0x%08lx matchingKnownClassNodes=%zu "
			"matchingUnknownClassNodes=%zu classRejectedNodes=%zu "
			"otherKindKnownClassMatches=%zu otherKindUnknownClassMatches=%zu "
			"otherKindReadFailures=%zu completed=%u error=0x%08lx\n",
			static_cast<unsigned>( kind), static_cast<unsigned long>( state->enumerationError),
			knownClassIdFailures, unknownClassIdFailures, missingPropertyFailures,
			static_cast<unsigned long>( firstIdError), matchingKnownClassNodes,
			matchingUnknownClassNodes, classRejectedNodes, otherKindKnownClassMatches,
			otherKindUnknownClassMatches, otherKindReadFailures,
			static_cast<unsigned>( result.completed), static_cast<unsigned long>( result.error)) ;
#endif
		return result ;
	}

private:
	/// Providerが失効させる秘密stateです。強所有を持ちません。
	std::weak_ptr<const IndexInventoryState>	  state_ ;
	/// 発行時に固定したoperation・scan・inventoryです。
	IndexLookupContext							  context_ ;
	/// 同factoryだけが発行したread-openのweak寿命証拠です。
	std::shared_ptr<const NativeIndexLookupLease> lease_ ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同workerの検証済みProviderと元世代だけを借用します。
 * @param[in] owner 借用Provider。nullは開始拒否で、終了時に何も変更しません。
 * @param[in] generation ownerが保持した正の元inventory世代。null ownerでは0です。
 * @param[in] operation 当該予約済みの新操作です。
 */
//------------------------------------------------------------------------------
DriverStoreProvider::IndexInstallProofScope::IndexInstallProofScope(
	DriverStoreProvider *owner, const std::uint64_t generation,
	const OperationId operation) noexcept
	: owner_( owner), generation_( generation), operation_( operation)
{
}
//------------------------------------------------------------------------------
/**
 * @brief 当該Sの借用だけを終了し、未処理Uの元proofを保持します。
 */
//------------------------------------------------------------------------------
DriverStoreProvider::IndexInstallProofScope::~IndexInstallProofScope()
{
	// 古いscopeから新operation/新世代の所有を変更しません。
	if( owner_ && owner_->installProofInventory_ && owner_->activeInstallOperation_ == operation_ &&
	   owner_->installProofInventory_->generation == generation_) {
		owner_->activeIndexDevices_.clear() ;
		owner_->installProofInventory_.reset() ;
		// 最後の未処理scope終了または明示失効だけで閉じます。
		if( owner_->pendingIndexDevices_.empty() && owner_->indexInventory_) {
			owner_->indexInventory_->resolutionOpen = false ;
		}
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 元同worker/scanのscope開始が成立したか確認します。
 * @return 開始した元scopeだけtrueです。
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::IndexInstallProofScope::active() const noexcept
{
	return owner_ != nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原lookup完了後の再factory/全体再列挙を不可逆に閉じます。
 * @param[in] origin 元完全contextです。
 * @return 同じ原ownerへ適用した場合trueです。
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::sealIndexLookup( const IndexLookupContext origin) noexcept
{
	// 原lookupだけを一度閉じ、失効後のreadOpenを再開しません。
	if( !indexInventory_ || origin != issuedIndexContext_ || !indexInventory_->resolutionOpen ||
	   indexInventory_->lookupFrozen || GetCurrentThreadId() != indexInventory_->ownerThread ||
	   origin.inventoryGeneration != indexInventory_->generation) {
		return false ;
	}

	indexInventory_->lookupFrozen = true ;
	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 未処理または当該実行中subsetへの結合を検証します。
 * @param[in] origin 元contextです。
 * @param[in] operation 明示操作です。
 * @param[in] devices 元一意subsetです。
 * @param[in] executing trueは当該scopeのS、falseは未処理Uです。
 * @return 完全一致だけtrueです。新しい権限を作りません。
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::validateRetainedIndexSelection(
	const IndexLookupContext origin, const OperationId operation,
	const std::span<const std::wstring> devices, const bool executing) const noexcept
{
	// 生存leaseだけで新device/旧操作へ許可しません。
	if( !indexInventory_ || origin != issuedIndexContext_ || !indexInventory_->resolutionOpen ||
	   !indexInventory_->lookupFrozen || origin.scanSessionId != scanSessionId_ ||
	   origin.inventoryGeneration != indexInventory_->generation ||
	   GetCurrentThreadId() != ownerThreadId_ || operation == 0U || devices.empty() ||
	   devices.size() > 4096U ||
	   (operation != activeInstallOperation_ && operation <= lastAcceptedInstallOperation_)) {
		return false ;
	}

	// 全対象を不変の元device集合と現在のU/Sへ照合します。
	for( std::size_t index{}; index < devices.size(); ++index) {
		const auto &device = devices[index] ;	// 元opaqueです。
		// 重複/原対応喪失/別scopeを拒否します。
		if( !deviceInstances_.contains( device) ||
		   std::find( devices.begin(), devices.begin() + static_cast<std::ptrdiff_t>( index),
					 device) != devices.begin() + static_cast<std::ptrdiff_t>( index) ||
		   (executing
				? operation != activeInstallOperation_ ||
					  std::ranges::find( activeIndexDevices_, device) == activeIndexDevices_.end()
				: !pendingIndexDevices_.contains( device))) {
			return false ;
		}
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 全選択事前検証後だけ新resolverを閉じ、元proofの解放を一batch終端へ延期します。
 * @param[in] origin 元factoryの原contextです。
 * @param[in] operation 当該予約済み新操作です。
 * @param[in] devices 元Uの一意な選択subsetです。
 * @return 同worker/scanの一回scope。不一致/閉鎖済みはinactiveです。
 * @note 新取得・proof・導入許可を発行せず、各deviceの直前再検証は別に必須です。
 */
//------------------------------------------------------------------------------
DriverStoreProvider::IndexInstallProofScope DriverStoreProvider::beginIndexInstallProofScope(
	const IndexLookupContext origin, const OperationId operation,
	const std::span<const std::wstring> devices) noexcept
{
	// 原owner/Uの検証が終わる前に一部だけ消費しません。
	if( installProofInventory_ || operation != activeInstallOperation_ ||
	   !validateRetainedIndexSelection( origin, operation, devices, false)) {
		return {nullptr, 0U, 0U} ;
	}

	try {
		std::vector<std::wstring> selected{devices.begin(),
										   // 確保失敗時はUを変更しません。
										   devices.end()} ;
		activeIndexDevices_.swap( selected) ;
		installProofInventory_ = indexInventory_ ;
		// 検証と全確保後だけUからSへ移します。
		for( const auto &device : devices) {
			pendingIndexDevices_.erase( device) ;
		}

		return {this, indexInventory_->generation, operation} ;
	} catch( ...) {
		// noexceptの確保例外をabortさせずinactiveへ返します。状態変更は確保後だけです。
		return {nullptr, 0U, 0U} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現在属性の非通信内部試験用API表を所有copyする。
 * @param[in] transport 完全なSetupAPI代替表。欠損をnative呼出しで補完しない。
 * @note このinstanceはscanCurrentInventory専用。通常scanと導入sessionを発行しない。
 */
//------------------------------------------------------------------------------
DriverStoreProvider::DriverStoreProvider( DriverStoreInventoryTransport transport) noexcept
	: testInventoryTransport_( std::move( transport))
{
}

//------------------------------------------------------------------------------
/**
 * @brief 現在の PnP device と compatible Driver Store 履歴を列挙する。現在の PnP device と compatible Driver Store履
 *        歴を列挙する。 注記: network 通信、download、およびsystem state の変更は行わない。
 * @param[in] scanSessionId 呼出し側が割り当てた 0 ではない session ID。 呼出し側が割り当てた 0 ではないsession ID。
 * @param[in] options Aggregate Provider以外では既定値を使用するscan設定。 複合Providerで検証済みのscan条件。
 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
 * @return 現在版と切替可能な local driver 候補を含む scan 結果。
 * @note network 通信、download、および system state の変更は行わない。
 */
//------------------------------------------------------------------------------
ScanResult DriverStoreProvider::scan( const ScanSessionId scanSessionId, const ScanOptions &options,
									 const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( options) ;
	return scanInventory( scanSessionId, progressCallback, nullptr, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 履歴・native照合map・install targetを生成せず現在属性だけを列挙する。
 * @param[in] scanSessionId 専用contextと一致するworker session。
 * @param[in,out] execution 同期呼出し中だけ借用する取消し・期限context。
 * @param[in] progressCallback 確定した列挙件数の通知先。
 * @return 表示専用の現在行。途中停止では検証済み行と不完全な計測を保持。
 */
//------------------------------------------------------------------------------
ScanResult DriverStoreProvider::scanCurrentInventory(
	const ScanSessionId scanSessionId, MetadataSearchExecutionContext &execution,
	const ProviderProgressCallback &progressCallback)
{
	return scanInventory( scanSessionId, progressCallback, &execution) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在属性scanへ索引専用の秘密ID captureだけを追加します。
 * @param[in] scanSessionId 専用contextと一致する正のsession。
 * @param[in,out] execution 同期呼出し中だけ借用する停止context。
 * @param[in] progressCallback 確定進捗の通知先。
 * @return 表示専用の現在行と独立した秘密resolver state。
 * @note 完全transport内だけで実行し、履歴・install session・native fallbackを発行しません。
 */
//------------------------------------------------------------------------------
ScanResult DriverStoreProvider::scanCurrentIndexInventory(
	const ScanSessionId scanSessionId, MetadataSearchExecutionContext &execution,
	const ProviderProgressCallback &progressCallback)
{
	return scanInventory( scanSessionId, progressCallback, &execution, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanの秘密snapshotをweak所有するread-only resolverを発行します。
 * @param[in] operationId 結合する正のworker operation。
 * @param[out] context 発行時だけsessionと単調inventory世代を返します。拒否時は空です。
 * @param[out] present 全観測opaque集合。拒否時は空です。生IDは含みません。
 * @return 所有threadの有効snapshotだけがcallbackを持ちます。拒否時はnullptrです。
 * @note Workerで同期呼出しし再入しません。新scan・install・Provider破棄で旧callbackは失効します。不完全snapshotのcallbackも発行できますが、
 *       resolveのcompletedはfalseです。
 */
//------------------------------------------------------------------------------
std::unique_ptr<IndexPublicIdResolver> DriverStoreProvider::makeIndexPublicIdResolver(
	const std::uint64_t operationId, IndexLookupContext &context,
	std::vector<std::wstring> &present) const
{
	context = {} ;
	present.clear() ;
	// 未発行、別thread、0 operationへ秘密stateの能力を渡しません。
	if( !indexInventory_ || !indexInventory_->resolutionOpen || indexInventory_->lookupFrozen ||
	   issuedIndexContext_.operationId != 0U || operationId == 0U ||
	   indexInventory_->ownerThread != GetCurrentThreadId()) {
		return nullptr ;
	}

	const IndexLookupContext issued{operationId, indexInventory_->session,
									indexInventory_->generation} ;	// このcallbackだけの結合tuple。
	issuedIndexContext_ = issued ;
	auto lease			= std::make_shared<const NativeIndexLookupLease>(
		 NativeIndexLookupLease::MintKey{}, issued, indexInventory_->ownerThread,
		 std::weak_ptr<const void>{indexInventory_},
		 &indexInventory_->resolutionOpen) ;	// 秘密stateを強所有しません。
	auto resolver = std::make_unique<IndexInventoryResolver>( indexInventory_, issued,
															 // Weak所有。
															 std::move( lease)) ;
	present		  = indexInventory_->present ;
	context		  = issued ;
	return resolver ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常scanと現在属性専用scanが共有する有界present列挙。
 * @param[in] scanSessionId 呼出側が発行した非ゼロsession。
 * @param[in] progressCallback 同期の進捗通知先。
 * @param[in,out] execution Nullは通常履歴検索、非nullは表示専用。
 * @param[in] captureIndexIds 同scanの索引照合用秘密属性を保持する場合true。
 * @return 列挙結果。専用modeではinstall sessionを発行しない。
 */
//------------------------------------------------------------------------------
ScanResult DriverStoreProvider::scanInventory( const ScanSessionId			  scanSessionId,
											  const ProviderProgressCallback &progressCallback,
											  MetadataSearchExecutionContext *execution,
											  const bool					  captureIndexIds)
{
	invalidateScanSession() ;
	progressCallback( {.stage = ProviderStage::SCANNING_DEVICES}) ;
	ScanResult result{} ;	// 全present deviceとcompatible driverを格納するscan結果。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.purpose = execution != nullptr ? ScanPurpose::METADATA_ONLY : ScanPurpose::STANDARD ;
	const auto &transport =
		// Instance固定I/O。
		testInventoryTransport_.value_or( driver_store_inf_detail::transport().inventory) ;
	// Fixture依存を通常scanへ使わず、不完全tableをnative APIで補完しない。
	if( (testInventoryTransport_ && execution == nullptr) || !transport.open ||
	   !transport.enumerate || !transport.property || !transport.instanceId || !transport.close ||
	   !transport.nodeStatus) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	// 未発行sessionへdeviceと導入targetを登録しない。
	if( scanSessionId == 0 ||
	   (execution != nullptr && execution->scanSessionId() != scanSessionId)) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	ownerThreadId_ = GetCurrentThreadId() ;
	// 世代overflow後は旧値の再利用や0世代の発行を行いません。
	if( indexInventoryGeneration_ == std::numeric_limits<std::uint64_t>::max()) {
		result.error = nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		return result ;
	}

	++indexInventoryGeneration_ ;
	std::shared_ptr<IndexInventoryState> indexState ;	// 同scanだけが作る可変capture。
	// 通常scanと明示索引用現在属性scanだけに秘密stateを作ります。
	if( captureIndexIds) {
		indexState				= std::make_shared<IndexInventoryState>() ;
		indexState->session		= scanSessionId ;
		indexState->generation	= indexInventoryGeneration_ ;
		indexState->ownerThread = ownerThreadId_ ;
	}

	// Queue内での取消しや期限切れはWindows列挙を開始しない。
	if( execution != nullptr && execution->checkpoint() != 0) {
		result.error   = execution->checkpoint() ;
		result.outcome = execution->sessionStopReason() == MetadataSearchReason::CANCELLED
							 ? OutcomeCode::ABORTED
							 : OutcomeCode::FAILURE ;
		inventoryMeasurement_.enumeratedDeviceCount = {std::nullopt,
													   MeasurementExtent::UNAVAILABLE} ;
		return result ;
	}

	DeviceInfoSet devices(	// 本scan中の全present deviceを所有するinformation set。
		transport.open( nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT), transport) ;
	// present device集合を作成できなければsessionを失効してscanを失敗とする。
	if( !devices.valid()) {
		result.error = nativeErrorFromWin32( GetLastError()) ;
		invalidateScanSession() ;
		inventoryMeasurement_.enumeratedDeviceCount	   = {std::nullopt,
														  MeasurementExtent::UNAVAILABLE} ;
		inventoryMeasurement_.unrepresentedDeviceCount = {std::nullopt,
														  MeasurementExtent::UNAVAILABLE} ;
		inventoryMeasurement_.reasons.push_back(
			{MeasurementReason::INCOMPLETE, MeasurementUnit::QUERY, 1U}) ;
		inventoryMeasurement_.error = result.error ;
		return result ;
	}

	bool		  partialFailure{} ;			// trueの場合は列挙欠損を警告付き成功として返す。
	DWORD		  deviceCount{} ;				// 本scanで保持して詳細確認するpresent device数。
	std::uint64_t observedDeviceCount{} ;		// 上限probeを含め、存在を確認できたnode数。
	std::uint64_t assessedDeviceCount{} ;		// Compatible listを最後まで判定できたdevice数。
	std::uint64_t limitAffectedDeviceCount{} ;	// 列挙上限で詳細を完了できなかったnode数。
	bool deviceEnumerationComplete{} ;			// ERROR_NO_MORE_ITEMSで全device終端を確認した場合true。
	bool candidateLimitReached{} ;				// 全候補上限により後続deviceを処理できない場合true。
	BoundedEnumerationStop deviceStop{
		BoundedEnumerationStop::LIMIT} ;	// 上限まで列挙した場合の本体停止理由。
	BoundedEnumerationProbe deviceProbe{
		BoundedEnumerationProbe::NOT_RUN} ;	// 上限到達時だけ設定する一回probe結果。
	NativeError deviceEnumerationError{} ;	// 本体またはprobeで最初に得た列挙診断値。
	// 同一workerでだけ呼び、同期API境界の停止を最初のinventory診断へ保持する。
	const auto	checkInventoryStop = [&]() {
		 // 通常scanには新しい取消し契約を暗黙追加しない。
		 if( execution == nullptr) {
			 return false ;
		 }

		 const NativeError error = execution->checkpoint() ;	// 最新の主停止理由。
		 // 停止していなければ列挙を継続する。
		 if( error == 0) {
			 return false ;
		 }

		 partialFailure = true ;
		 // 後続停止で先行API errorを上書きしない。
		 if( inventoryMeasurement_.error == 0) {
			 inventoryMeasurement_.error = error ;
		 }

		 return true ;
	 } ;
	// 詳細処理前に同一information setを一巡し、進捗表示の正確な分母を確定する。
	for( DWORD deviceIndex = 0; deviceIndex < MAXIMUM_DEVICES; ++deviceIndex) {
		// 個数確認の途中停止を正常終端へ読み替えない。
		if( checkInventoryStop()) {
			deviceStop			   = BoundedEnumerationStop::API_FAILURE ;
			deviceEnumerationError = inventoryMeasurement_.error ;
			break ;
		}

		SP_DEVINFO_DATA device{} ;	// 件数確認中のpresent device metadata。
		device.cbSize = sizeof( device) ;
		// 件数確認の列挙終了を検出し、正常終端か障害かを判定する。
		if( transport.enumerate( devices.get(), deviceIndex, &device) == FALSE) {
			const DWORD error = GetLastError() ;	// 件数列挙の正常終端または失敗code。
			// 本体loopの停止理由を保持し、上限到達とは別に後で純粋分類する。
			if( error == ERROR_NO_MORE_ITEMS) {
				deviceStop = BoundedEnumerationStop::NORMAL_END ;
			} else {
				deviceStop			   = BoundedEnumerationStop::API_FAILURE ;
				deviceEnumerationError = nativeErrorFromWin32( error) ;
			}

			break ;
		}

		++deviceCount ;
	}

	// 上限ちょうどで終端したか、少なくとも一件超過したかを一回だけ追加確認する。
	if( deviceStop == BoundedEnumerationStop::LIMIT) {
		// 上限probeの直前も停止を確認し、追加APIを呼ばない。
		if( checkInventoryStop()) {
			deviceProbe			   = BoundedEnumerationProbe::API_FAILURE ;
			deviceEnumerationError = inventoryMeasurement_.error ;
		} else {
			SP_DEVINFO_DATA probe{} ;	// 保持しない4097件目の存在確認用metadata。
			probe.cbSize = sizeof( probe) ;
			// Probe結果は保持せず、正常終端・超過・API失敗だけを計測する。
			if( transport.enumerate( devices.get(), MAXIMUM_DEVICES, &probe) == FALSE) {
				const DWORD error = GetLastError() ;	// 上限probeの正常終端または失敗code。
				// ERROR_NO_MORE_ITEMSの場合だけ4096件を正確な全件数として扱う。
				if( error == ERROR_NO_MORE_ITEMS) {
					deviceProbe = BoundedEnumerationProbe::NORMAL_END ;
				} else {
					deviceProbe			   = BoundedEnumerationProbe::API_FAILURE ;
					deviceEnumerationError = nativeErrorFromWin32( error) ;
				}
			} else {
				// 追加nodeを候補化せず、純粋分類へ実要素の存在だけを渡す。
				deviceProbe = BoundedEnumerationProbe::ELEMENT_FOUND ;
			}
		}
	}

	const auto deviceBoundary = classifyBoundedEnumeration(
		static_cast<std::uint64_t>( deviceCount), static_cast<std::uint64_t>( MAXIMUM_DEVICES),
		deviceStop, deviceProbe, deviceEnumerationError) ;	// 本体と一回probeの整合済み分類。
	// 内部列挙状態の矛盾を部分成功へ隠さず、scan全体をfail-closedで終了する。
	if( !deviceBoundary || !deviceBoundary->observedItemCount.value.has_value()) {
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		invalidateScanSession() ;
		return result ;
	}

	observedDeviceCount							= deviceBoundary->observedItemCount.value.value() ;
	deviceEnumerationComplete					= deviceBoundary->enumerationComplete ;
	inventoryMeasurement_.enumeratedDeviceCount = deviceBoundary->observedItemCount ;
	// API失敗では最初の診断値を保持し、超過確認では上限影響nodeを一件記録する。
	if( deviceBoundary->error != 0) {
		partialFailure				= true ;
		inventoryMeasurement_.error = deviceBoundary->error ;
	}

	// 上限外のpresent deviceを確認した場合だけ、未処理nodeを一件以上として記録する。
	if( deviceBoundary->limitExceeded) {
		++limitAffectedDeviceCount ;
		partialFailure = true ;
	}

	progressCallback(
		{.stage = ProviderStage::SCANNING_DEVICES, .completedItems = 0, .totalItems = deviceCount}) ;
	result.coverage.eligibleDeviceCount = deviceCount ;

	// Present deviceを上限付きで列挙し、各deviceの現在版とcompatible履歴を収集する。
	for( DWORD deviceIndex = 0; deviceIndex < deviceCount; ++deviceIndex) {
		// 詳細列挙で未処理のnodeは表示済み母数へ含めない。
		if( checkInventoryStop()) {
			break ;
		}

		SP_DEVINFO_DATA device{} ;	// 現在列挙中のpresent device metadata。
		device.cbSize = sizeof( device) ;
		// 事前列挙で存在したnodeを再取得できなければ同一集合の詳細処理を完了にしない。
		if( transport.enumerate( devices.get(), deviceIndex, &device) == FALSE) {
			const DWORD error = GetLastError() ;	// 二巡目の列挙失敗code。
			partialFailure	  = true ;
			// 事前列挙と矛盾する正常終端はERROR_INVALID_DATAとして保持する。
			if( inventoryMeasurement_.error == 0) {
				inventoryMeasurement_.error =
					nativeErrorFromWin32( error == ERROR_NO_MORE_ITEMS ? ERROR_INVALID_DATA : error) ;
			}

			break ;
		}

		// UIへ渡せるscan session内のopaque device ID。
		const std::wstring deviceIdentity =
			L"device:" + std::to_wstring( scanSessionId) + L":" + std::to_wstring( deviceIndex) ;
		DeviceObservation observation ;	// 生属性を含まない一deviceの観測。
		observation.scanSessionId  = scanSessionId ;
		observation.deviceIdentity = deviceIdentity ;
		std::wstring instanceId ;	// 有効時だけ秘密mapへ登録するworker内ID。
		observation.instanceIdentity =
			readObservedInstanceId( devices.get(), device, instanceId, transport) ;
		// Worker内instance IDを分類後に破棄し、候補へは有限busだけを渡す。
		const OfficialDiscoveryDeviceBus discoveryBus =
			classifyOfficialDiscoveryDeviceBus( instanceId) ;
		observation.node = readObservedNode( device, transport) ;
		std::wstring deviceName ;	// FriendlyNameまたはDeviceDescから得る表示名。
		observation.friendlyName = readObservedDeviceString(
			devices.get(), device, DEVPKEY_Device_FriendlyName, deviceName, transport) ;
		// 名前の空・欠損・失敗時は標準説明を試し、元の失敗も観測へ残す。
		if( observation.friendlyName.state != DevicePropertyReadState::VALUE) {
			observation.deviceDescription = readObservedDeviceString(
				devices.get(), device, DEVPKEY_Device_DeviceDesc, deviceName, transport) ;
		}

		std::wstring	   manufacturer ;	// Device propertyが返す製造元表示名。
		std::wstring	   deviceClass ;	// Device propertyが返すsetup class表示名。
		// UIのWindows標準class icon選択に使用するcanonical GUID。
		const std::wstring deviceClassGuid = formatClassGuid( device.ClassGuid) ;
		observation.manufacturer		   = readObservedDeviceString(
			  devices.get(), device, DEVPKEY_Device_Manufacturer, manufacturer, transport) ;
		observation.deviceClass = readObservedDeviceString(
			devices.get(), device, DEVPKEY_Device_Class, deviceClass, transport) ;
		std::wstring driverKey ;	// 内容をUI・logへ転送しない一時key。
		observation.driverKey = readObservedDeviceString(
			devices.get(), device, DEVPKEY_Device_Driver, driverKey, transport) ;
		// Worker内の現在属性と、値を含まない読取り結果。
		const CurrentDriverMetadata current = readCurrentDriver( devices.get(), device, transport) ;
		observation.infName					= current.infRead ;
		observation.provider				= current.providerRead ;
		observation.version					= current.versionRead ;
		observation.date					= current.dateRead ;
		observation.driverPresence =
			classifyDeviceDriverPresence( observation.node, observation.driverKey) ;
		// 有効な実IDを持ち、後続で消失が見つからない場合だけnative照合へ進む。
		bool nativeIdentityAvailable =
			observation.instanceIdentity.state == DevicePropertyReadState::VALUE ;
		bool observationFailed =
			!nativeIdentityAvailable ;	// 失敗時も代表行を残すが完全観測としない。
		const std::array<const DevicePropertyReadStatus *, 11>
			reads{&observation.instanceIdentity,
				  &observation.node.read,
				  &observation.friendlyName,
				  &observation.deviceDescription,
				  &observation.manufacturer,
				  &observation.deviceClass,
				  &observation.driverKey,
				  &observation.infName,
				  &observation.provider,
				  &observation.version,
				  &observation.date} ;	// 全読取りから失敗と消失だけを確認する固定集合。
		// 属性失敗を件数に保持し、途中のdevice消失時はnative照合能力を発行しない。
		for( const auto *read : reads) {
			const bool failed = read->state == DevicePropertyReadState::FAILED ||
								read->state == DevicePropertyReadState::INVALID_DATA ||
								// 欠損とは別の実失敗。
								read->state == DevicePropertyReadState::LIMIT_REACHED ;
			observationFailed = observationFailed || failed ;
			// 一件目の失敗を全体診断へ保持し、元の領域付きcodeは観測から失わない。
			if( (failed || read == &observation.instanceIdentity) && read->diagnostic.code != 0U &&
			   inventoryMeasurement_.error == 0) {
				inventoryMeasurement_.error = nativeErrorFromWin32(
					read->diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR
						? read->diagnostic.code
						: ERROR_GEN_FAILURE) ;
			}

			// OSが消失を返したdeviceへ、前段で得たIDを再利用しない。
			if( (read->diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR &&
				read->diagnostic.code == ERROR_NO_SUCH_DEVINST) ||
			   (read->diagnostic.domain == DeviceDiagnosticDomain::CONFIGURATION_MANAGER &&
				read->diagnostic.code == CR_NO_SUCH_DEVNODE)) {
				nativeIdentityAvailable = false ;
				// 消失したnodeを全present確認済みへ残しません。
				if( indexState) {
					indexState->enumerationError = nativeErrorFromWin32( ERROR_NO_SUCH_DEVINST) ;
				}
			}
		}

		partialFailure = partialFailure || observationFailed ;
		// 同じ現在nodeの元IDとClassGUIDを、表示・現在driver属性とは独立にcaptureします。
		if( indexState) {
			indexState->present.push_back( deviceIdentity) ;
			IndexInventoryState::Node node ;	// 当該nodeだけの必要属性を所有します。
			node.identity = deviceIdentity ;
			// null/正式Unknown GUIDを公開recordのClassへ補完しません。
			if( !IsEqualGUID( device.ClassGuid, GUID_NULL) &&
			   !IsEqualGUID( device.ClassGuid, GUID_DEVCLASS_UNKNOWN)) {
				node.classGuid = normalizeIdentifier( deviceClassGuid) ;
			}

			// Inventory-only transportを互換driverのnative fallbackへ接続しません。
			if( !testInventoryTransport_) {
				node.classError = readDeviceClassSnapshot( devices.get(), device, transport,
														  node.classObservation) ;
				// 未確定Classだけを完全な初回証拠で仮照合対象へ進めます。
				if( node.classError == 0U && node.classGuid.empty() && nativeIdentityAvailable) {
					DeviceRankSnapshot proof ;	// 元opaqueの独立した全native初回証拠です。
					const NativeError  proofError =
						// 完全表のみです。
						readDeviceRankSnapshot( instanceId, proof) ;
					// Classと元node/六属性の同時観測が変わった証拠を流用しません。
					if( proofError == 0U && proof.noDriver &&
					   proof.classRead.state == observation.deviceClass.state &&
					   proof.classState == node.classObservation.classState &&
					   proof.nativeClassGuid == node.classObservation.nativeClassGuid &&
					   proof.observedClassGuid == node.classObservation.observedClassGuid &&
					   proof.deviceClass == deviceClass &&
					   proof.node.statusFlags == observation.node.statusFlags &&
					   proof.node.problemCode == observation.node.problemCode &&
					   observation.driverKey.state == DevicePropertyReadState::NOT_PRESENT &&
					   observation.infName.state == DevicePropertyReadState::NOT_PRESENT &&
					   observation.provider.state == DevicePropertyReadState::NOT_PRESENT &&
					   observation.version.state == DevicePropertyReadState::NOT_PRESENT &&
					   observation.date.state == DevicePropertyReadState::NOT_PRESENT) {
						node.classObservation	 = std::move( proof) ;
						node.initialClassUnknown = true ;
					} else {
						node.classError =
							proofError != 0U ? proofError : nativeErrorFromWin32( ERROR_RETRY) ;
					}
				}
			}

			node.hardwareError	 = readIndexIds( devices.get(), device, DEVPKEY_Device_HardwareIds,
												transport, node.hardware) ;
			node.compatibleError = readIndexIds( devices.get(), device, DEVPKEY_Device_CompatibleIds,
												transport, node.compatible) ;
			// 初回証拠のID順序/種別と同snapshotの公開ID照合素材を一致させます。
			if( node.initialClassUnknown) {
				const auto sameIds = []( const std::wstring &left, const std::wstring &right) {
					return left == normalizeIdentifier( right) ;
				} ; // 同期中だけ両秘密値を借用し、正規化した全IDを比較します。
				// 二観測の変化を初回候補へ結び直しません。
				if( node.hardwareError != 0U || node.compatibleError != 0U ||
				   !std::equal( node.hardware.begin(), node.hardware.end(),
							   node.classObservation.hardwareIds.begin(),
							   node.classObservation.hardwareIds.end(), sameIds) ||
				   !std::equal( node.compatible.begin(), node.compatible.end(),
							   node.classObservation.compatibleIds.begin(),
							   node.classObservation.compatibleIds.end(), sameIds)) {
					node.initialClassUnknown = false ;
					node.classError			 = nativeErrorFromWin32( ERROR_RETRY) ;
				}
			}

			// 有限RAM枠超過は部分一致で成功にせず、両種別を未完了へ残します。
			if( node.hardware.size() + node.compatible.size() >
			   index_capacity::NATIVE_INVENTORY_IDS - indexState->retainedIds) {
				indexState->enumerationError = indexState->enumerationError == 0U
												   ? nativeErrorFromWin32( ERROR_MORE_DATA)
												   : indexState->enumerationError ;
			} else {
				indexState->retainedIds += node.hardware.size() + node.compatible.size() ;
				indexState->nodes.push_back( std::move( node)) ;
			}
		}

		// 専用modeとidentity未確認時はnative照合mapを構築しない。
		if( execution == nullptr && nativeIdentityAvailable) {
			// WUA candidate を同じ device node へ統合するため全 Hardware/Compatible ID を内部 map
			// に持つ。
			// WUA候補との内部照合に使用するHardware ID群。
			std::vector<std::wstring> hardwareIds =
				readDeviceStringList( devices.get(), device, DEVPKEY_Device_HardwareIds) ;
			// 同じ照合へ追加するCompatible ID群。
			std::vector<std::wstring> compatibleIds =
				readDeviceStringList( devices.get(), device, DEVPKEY_Device_CompatibleIds) ;
			hardwareIds.insert( hardwareIds.end(), compatibleIds.begin(), compatibleIds.end()) ;
			// WUA候補との照合用に、Hardware IDとCompatible IDを同じ正規化表へ登録する。
			for( const std::wstring &hardwareId : hardwareIds) {
				const std::wstring normalized = normalizeIdentifier( hardwareId) ;	// 大文字照合key。
				// Hardware ID mapへの追加位置と新規追加flag。
				const auto [iterator, inserted] =
					hardwareToDevice_.emplace( normalized, deviceIdentity) ;
				// 一つの照合IDが複数deviceを指す場合は誤統合を避けて解決不能にする。
				if( !inserted && iterator->second != deviceIdentity) {
					// 一つの ID が複数 device に一致する場合は誤統合を避けて解決不能とする。
					iterator->second.clear() ;
				}
			}
		}

		std::vector<UpdateCandidate> deviceCandidates ;	// このdeviceの表示候補群。
		std::vector<InstallTarget> deviceTargets ;		// Candidate indexと対応する秘密install metadata。
		bool foundCurrent{} ;							// trueの場合はcompatible list内で現在packageを特定済み。
		bool deviceAssessed{!observationFailed} ;		// 観測とcompatible listがerrorなしの場合true。
		bool deviceLimitAffected{} ;					// このdeviceでdriverまたは候補上限に達した場合true。

		// 専用modeとidentity未確認時はcompatible list・rank・install targetを生成しない。
		if( execution == nullptr && nativeIdentityAvailable) {
			// 互換driverの検索条件を設定できたdeviceだけを履歴列挙へ進める。
			if( configureCompatibleDriverSearch( devices.get(), device)) {
				DriverInfoList driverList( devices.get(), device) ;	// Compatible listのRAII guard。
				// 互換listの構築成功後にだけRAII解放対象として登録し、nodeを列挙する。
				if( driver_store_inf_detail::transport().build( devices.get(), &device,
															  SPDIT_COMPATDRIVER) != FALSE) {
					driverList.markBuilt() ;
					std::unordered_set<std::wstring> deduplicationKeys ;	// INF/version重複検出key。
					DWORD enumeratedDriverCount{} ;							// SetupAPIから存在を確認したcompatible node数。
					BoundedEnumerationStop driverStop{
						BoundedEnumerationStop::LIMIT} ;	// 上限まで列挙した場合の本体停止理由。
					BoundedEnumerationProbe driverProbe{
						BoundedEnumerationProbe::NOT_RUN} ;	// 上限時だけ設定する一回probe結果。
					NativeError driverEnumerationError{} ;	// 本体またはprobeの最初の列挙診断値。

					// Windows が rank 順に構築した compatible list を並べ替えずに列挙する。
					for( DWORD driverIndex = 0; driverIndex < MAXIMUM_DRIVERS_PER_DEVICE;
						++driverIndex) {
						SP_DRVINFO_DATA_W driver{} ;	// 現在列挙中のcompatible driver node。
						driver.cbSize = sizeof( driver) ;
						// driver nodeの列挙が終了した時点で正常終端と障害を区別する。
						if( driver_store_inf_detail::transport().enumerate(
							   devices.get(), &device, SPDIT_COMPATDRIVER, driverIndex, &driver) ==
						   FALSE) {
							const DWORD error =
								// Driver列挙の正常終端または失敗code。
								GetLastError() ;
							// 本体loopの停止理由を保持し、上限到達とは別に後で純粋分類する。
							if( error == ERROR_NO_MORE_ITEMS) {
								driverStop = BoundedEnumerationStop::NORMAL_END ;
							} else {
								driverStop			   = BoundedEnumerationStop::API_FAILURE ;
								driverEnumerationError = nativeErrorFromWin32( error) ;
							}

							break ;
						}

						++enumeratedDriverCount ;

						DriverDetail detail ;	// UIへ渡さないINFとsection metadata。
						// 詳細を取得できないdriver nodeを飛ばし、そのdeviceの監査不完全を記録する。
						if( !readDriverDetail( devices.get(), device, driver, detail)) {
							const DWORD error =
								// Detail取得失敗または不正metadata code。
								GetLastError() ;
							partialFailure = true ;
							deviceAssessed = false ;
							// APIが診断を設定しない不正値はERROR_INVALID_DATAとして保持する。
							if( inventoryMeasurement_.error == 0) {
								inventoryMeasurement_.error = nativeErrorFromWin32(
									error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
							}

							continue ;
						}

						// 同一 package/version の別 model section
						// は履歴上の別版ではないため一件にまとめる。
						// 同一package/versionをまとめるkey。
						const std::wstring deduplicationKey =
							normalizedFileName( detail.infFileName) + L"|" +
							std::to_wstring( driver.DriverVersion) ;
						// 同じINF・versionのdriver nodeを重複した候補として追加しない。
						if( !deduplicationKeys.insert( deduplicationKey).second) {
							continue ;
						}

						// 現在使用中packageと完全一致する最初のnode。
						const bool currentCandidate =
							!foundCurrent && isCurrentDriver( current, detail, driver) ;
						foundCurrent = foundCurrent || currentCandidate ;
						UpdateCandidate candidate ;	// UIへ渡す現在compatible driver候補。
						candidate.deviceIdentity = deviceIdentity ;
						candidate.title =
							driver.Description[0] == L'\0' ? deviceName : driver.Description ;
						candidate.manufacturer	  = manufacturer ;
						candidate.model			  = deviceName ;
						candidate.driverClass	  = deviceClass ;
						candidate.deviceClassGuid = deviceClassGuid ;
						candidate.discoveryBus	  = discoveryBus ;
						candidate.provider		  = driver.ProviderName ;
						candidate.version		  = formatDriverVersion( driver.DriverVersion) ;
						candidate.driverDate	  = formatDriverDate( driver.DriverDate) ;
						candidate.sourceName	  = L"Windows Driver Store" ;
						candidate.sourceLocation  = L"ローカル（Windows が検証・格納）" ;
						candidate.discoveryBasis  = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
						candidate.action		  = currentCandidate
														? DriverAction::NONE
														: classifyAction( current, driver.DriverVersion) ;
						candidate.current		  = currentCandidate ;
						// 現在版と利用者が選ぶ旧版候補は自動選択の対象にしない。
						candidate.recommended = false ;
						candidate.installable = !currentCandidate ;
						candidate.audit		  = makeWindowsManagedCandidateAudit( currentCandidate) ;

						InstallTarget target ;	// 実行直前の再照合に使用する秘密metadata。
						target.deviceInstanceId = instanceId ;
						target.infFileName		= detail.infFileName ;
						target.sectionName		= detail.sectionName ;
						target.providerName		= driver.ProviderName ;
						target.driverVersion	= driver.DriverVersion ;
						target.driverDateTicks	= fileTimeTicks( driver.DriverDate) ;
						deviceCandidates.push_back( std::move( candidate)) ;
						deviceTargets.push_back( std::move( target)) ;
					}

					// 512件ちょうどで終端したか、513件目が存在するかを一回だけ確認する。
					if( driverStop == BoundedEnumerationStop::LIMIT) {
						SP_DRVINFO_DATA_W probe{} ;	// 保持しない513件目のdriver node metadata。
						probe.cbSize = sizeof( probe) ;
						// Probeは候補やinstall targetを追加せず、終端状態だけを取得する。
						if( driver_store_inf_detail::transport().enumerate(
							   devices.get(), &device, SPDIT_COMPATDRIVER,
							   MAXIMUM_DRIVERS_PER_DEVICE, &probe) == FALSE) {
							const DWORD error =
								// Driver上限probeの終端または失敗code。
								GetLastError() ;
							// ERROR_NO_MORE_ITEMSなら512件を完全なcompatible listとして扱う。
							if( error == ERROR_NO_MORE_ITEMS) {
								driverProbe = BoundedEnumerationProbe::NORMAL_END ;
							} else {
								driverProbe			   = BoundedEnumerationProbe::API_FAILURE ;
								driverEnumerationError = nativeErrorFromWin32( error) ;
							}
						} else {
							// 513件目を保持せず、純粋分類へ実要素の存在だけを渡す。
							driverProbe = BoundedEnumerationProbe::ELEMENT_FOUND ;
						}
					}

					const auto driverBoundary = classifyBoundedEnumeration(
						static_cast<std::uint64_t>( enumeratedDriverCount),
						static_cast<std::uint64_t>( MAXIMUM_DRIVERS_PER_DEVICE), driverStop,
						driverProbe,
						driverEnumerationError) ;	// Compatible list本体と一回probeの整合済み分類。
					// 内部状態の矛盾または列挙不完全を、このdeviceの判定済み状態へ含めない。
					if( !driverBoundary) {
						partialFailure = true ;
						deviceAssessed = false ;
						// 分類不能には既存の先行診断を上書きしない共通codeを使う。
						if( inventoryMeasurement_.error == 0) {
							inventoryMeasurement_.error = static_cast<NativeError>( E_UNEXPECTED) ;
						}
					} else {
						// 列挙APIまたはprobeの失敗を最初のinventory診断として保持する。
						if( driverBoundary->error != 0) {
							partialFailure = true ;
							deviceAssessed = false ;
							// 先に取得した診断値を維持し、最初のdriver列挙失敗だけを公開する。
							if( inventoryMeasurement_.error == 0) {
								inventoryMeasurement_.error = driverBoundary->error ;
							}
						}

						// 上限外の実nodeを確認した場合だけ、当該deviceを上限影響へ数える。
						if( driverBoundary->limitExceeded) {
							partialFailure		= true ;
							deviceAssessed		= false ;
							deviceLimitAffected = true ;
						}
					}
				} else {
					const DWORD error = GetLastError() ;	// Compatible list構築失敗code。
					partialFailure	  = true ;
					deviceAssessed	  = false ;
					// 最初のcompatible list構築失敗だけをinventory診断へ保持する。
					if( inventoryMeasurement_.error == 0) {
						inventoryMeasurement_.error = nativeErrorFromWin32( error) ;
					}
				}
			} else {
				const DWORD error = GetLastError() ;	// Compatible search設定失敗code。
				partialFailure	  = true ;
				deviceAssessed	  = false ;
				// 最初のcompatible search設定失敗だけをinventory診断へ保持する。
				if( inventoryMeasurement_.error == 0) {
					inventoryMeasurement_.error = nativeErrorFromWin32( error) ;
				}
			}
		}

		// 属性読取り待機中の取消し後には未commitのdeviceを公開しない。
		if( checkInventoryStop()) {
			break ;
		}

		// 互換list内で現在driverを特定できない場合も現在propertyの表示専用行を残す。
		if( !foundCurrent) {
			UpdateCandidate installed ;	// Compatible listで特定不能だった現在版の表示候補。
			installed.deviceIdentity  = deviceIdentity ;
			installed.title			  = deviceName ;
			installed.manufacturer	  = manufacturer ;
			installed.model			  = deviceName ;
			installed.driverClass	  = deviceClass ;
			installed.deviceClassGuid = deviceClassGuid ;
			installed.discoveryBus	  = discoveryBus ;
			installed.provider		  = current.provider ;
			installed.version		  = current.version ;
			installed.driverDate	  = current.date ;
			installed.sourceName	  = L"現在のデバイス構成" ;
			installed.sourceLocation  = L"ローカル" ;
			installed.discoveryBasis  = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
			installed.action		  = DriverAction::NONE ;
			installed.audit			  = makeWindowsManagedCandidateAudit( true) ;
			installed.current		  = true ;
			installed.recommended	  = false ;
			deviceCandidates.insert( deviceCandidates.begin(), std::move( installed)) ;
			// 通常履歴だけにcandidateと対応するtarget領域を持たせる。
			if( execution == nullptr) {
				deviceTargets.insert( deviceTargets.begin(), InstallTarget{}) ;
			}
		} else {
			// 現在使用中候補のvector内位置。
			const auto currentIterator =
				std::find_if( deviceCandidates.begin(), deviceCandidates.end(),
							 []( const UpdateCandidate &candidate) { return candidate.current ; }) ;
			// 現在行が先頭でない場合は候補と導入targetを同時に移動して対応を保つ。
			if( currentIterator != deviceCandidates.end() &&
			   currentIterator != deviceCandidates.begin()) {
				// Candidateとtargetを同時に回転するindex。
				const std::size_t currentIndex = static_cast<std::size_t>(
					std::distance( deviceCandidates.begin(), currentIterator)) ;
				std::rotate( deviceCandidates.begin(), currentIterator, currentIterator + 1) ;
				std::rotate( deviceTargets.begin(), deviceTargets.begin() + currentIndex,
							deviceTargets.begin() + currentIndex + 1) ;
			}
		}

		bool		currentRepresented{} ;		// 現在版行を候補集合へ追加できた場合true。
		std::size_t appendedCandidateCount{} ;	// このdeviceで全体結果へ追加できた候補数。
		// UI に渡す identity は session 内の連番とし、秘密性のある native identifier を含めない。
		for( std::size_t index = 0; index < deviceCandidates.size(); ++index) {
			// 現在版補完行を含む各追加の直前に全体上限を検査する。
			if( result.candidates.size() >= MAXIMUM_TOTAL_CANDIDATES) {
				partialFailure		  = true ;
				deviceAssessed		  = false ;
				deviceLimitAffected	  = true ;
				candidateLimitReached = true ;
				break ;
			}

			UpdateCandidate &candidate = deviceCandidates[index] ;	// Identityを付与する表示候補。
			candidate.identity		   = L"store:" + std::to_wstring( scanSessionId) + L":" +
								 std::to_wstring( deviceIndex) + L":" + std::to_wstring( index) ;
			candidate.providerId = std::wstring( DRIVER_STORE_PROVIDER_ID) ;
			// 現在構成の代表行だけへ観測を結合し、更新候補へ複製しない。
			if( candidate.current) {
				candidate.deviceObservation = observation ;
			}

			// 専用modeで取得対象を示すidentityを発行しない。
			if( execution == nullptr) {
				candidate.packageIdentity = L"driver-store-node:" + candidate.identity ;
			}

			// install可能な候補だけを現在sessionの指定導入routingへ登録する。
			if( candidate.installable) {
				installTargets_.emplace( candidate.identity, std::move( deviceTargets[index])) ;
			}

			currentRepresented = currentRepresented || candidate.current ;
			result.candidates.push_back( std::move( candidate)) ;
			++appendedCandidateCount ;
		}

		// 代表行があり実identityも確認できたdeviceだけを秘密mapへ登録する。
		if( currentRepresented && execution == nullptr && nativeIdentityAvailable) {
			deviceInstances_.emplace( deviceIdentity, std::move( instanceId)) ;
		}

		// 上限到達後に未追加候補または後続deviceがある場合だけ打切りとして扱う。
		if( result.candidates.size() >= MAXIMUM_TOTAL_CANDIDATES &&
		   (appendedCandidateCount < deviceCandidates.size() || deviceIndex + 1U < deviceCount)) {
			partialFailure		  = true ;
			deviceAssessed		  = false ;
			deviceLimitAffected	  = true ;
			candidateLimitReached = true ;
		}

		assessedDeviceCount += deviceAssessed ? 1U : 0U ;
		// Driver上限だけに達したdeviceは一件として有限な理由集計へ加える。
		if( deviceLimitAffected) {
			++limitAffectedDeviceCount ;
		}

		const std::uint64_t completed =	// 現在deviceまでの詳細処理完了件数。
			static_cast<std::uint64_t>( deviceIndex) + 1 ;
		progressCallback(
			{.stage			  = ProviderStage::SCANNING_DEVICES,
			 .percentComplete = static_cast<std::uint32_t>( completed * 100 / deviceCount),
			 .completedItems  = completed,
			 .totalItems	  = deviceCount}) ;

		// 全候補上限後は未収録deviceを候補化せず、既知の残数を理由件数へ加える。
		if( candidateLimitReached) {
			limitAffectedDeviceCount += static_cast<std::uint64_t>( deviceCount - deviceIndex - 1U) ;
			break ;
		}
	}

	// present deviceがない場合も列挙完了を進捗へ反映する。
	if( deviceCount == 0 && !checkInventoryStop()) {
		progressCallback( {.stage = ProviderStage::SCANNING_DEVICES, .percentComplete = 100}) ;
	}

	std::uint64_t representedDeviceCount{} ;		// 公開できた一意な現在版行数。
	std::uint64_t missingManufacturerCount{} ;		// 現在版行のmanufacturer欠損数。
	std::uint64_t missingClassCount{} ;				// 現在版行のsetup class欠損数。
	std::uint64_t missingVersionCount{} ;			// 現在版行のdriver version欠損数。
	std::uint64_t missingAttributeDeviceCount{} ;	// 一つ以上の表示属性が欠けた現在node数。
	// 最終候補の現在版だけを一巡し、表示済み母数と属性欠損を確定する。
	for( const UpdateCandidate &candidate : result.candidates) {
		// 非現在版はinventory母数と属性欠損へ加えない。
		if( !candidate.current) {
			continue ;
		}

		++representedDeviceCount ;
		missingManufacturerCount += candidate.manufacturer.empty() ? 1U : 0U ;
		missingClassCount += candidate.driverClass.empty() ? 1U : 0U ;
		missingVersionCount += candidate.version.empty() ? 1U : 0U ;
		missingAttributeDeviceCount += candidate.manufacturer.empty() ||
											   candidate.driverClass.empty() ||
											   candidate.version.empty()
										   ? 1U
										   : 0U ;
	}

	inventoryMeasurement_.representedDeviceCount   = {representedDeviceCount,
													  MeasurementExtent::EXACT} ;
	inventoryMeasurement_.missingManufacturerCount = {missingManufacturerCount,
													  MeasurementExtent::EXACT} ;
	inventoryMeasurement_.missingClassCount		   = {missingClassCount, MeasurementExtent::EXACT} ;
	inventoryMeasurement_.missingCurrentVersionCount = {missingVersionCount,
														MeasurementExtent::EXACT} ;
	// 同じ列挙集合の観測下限から実際に表現できた現在版を引き、確定度は昇格させない。
	if( observedDeviceCount >= representedDeviceCount) {
		inventoryMeasurement_.unrepresentedDeviceCount = {
			observedDeviceCount - representedDeviceCount,
			deviceEnumerationComplete ? MeasurementExtent::EXACT : MeasurementExtent::LOWER_BOUND} ;
	} else {
		// 同一information set内で母数が逆転した場合は計測を信用可能な値として公開しない。
		inventoryMeasurement_.unrepresentedDeviceCount = {std::nullopt,
														  MeasurementExtent::UNAVAILABLE} ;
		partialFailure								   = true ;
	}

	inventoryMeasurement_.detailedEnumerationComplete =
		deviceEnumerationComplete && !partialFailure && assessedDeviceCount == deviceCount &&
		representedDeviceCount == deviceCount ;
	// 同一deviceの複数属性欠損を一件として理由内訳へ残す。
	if( missingAttributeDeviceCount != 0) {
		inventoryMeasurement_.reasons.push_back( {MeasurementReason::MISSING_ATTRIBUTE,
												 MeasurementUnit::DEVICE,
												 missingAttributeDeviceCount}) ;
	}

	// 上限に影響されたことが確定したnodeだけをdevice単位で記録する。
	if( limitAffectedDeviceCount != 0) {
		inventoryMeasurement_.reasons.push_back(
			{MeasurementReason::LIMIT_REACHED, MeasurementUnit::DEVICE, limitAffectedDeviceCount}) ;
	}

	// 詳細判定できなかった既知nodeは、列挙数との差を下限として保持する。
	if( observedDeviceCount > assessedDeviceCount) {
		inventoryMeasurement_.reasons.push_back( {MeasurementReason::INCOMPLETE,
												 MeasurementUnit::DEVICE,
												 observedDeviceCount - assessedDeviceCount}) ;
	}

	// 必要属性以外の欠損・履歴失敗をID照合の完了軸へ混ぜません。
	if( indexState) {
		indexState->enumerationComplete =
			deviceEnumerationComplete && indexState->present.size() == deviceCount &&
			!checkInventoryStop() && indexState->enumerationError == 0U ;
		// Capture前の消失診断を正常終端で上書きしません。
		if( indexState->enumerationError == 0U) {
			indexState->enumerationError = deviceEnumerationError ;
		}

		// 二巡目消失や停止だけは元inventory診断を保持します。
		if( !indexState->enumerationComplete && indexState->enumerationError == 0U) {
			indexState->enumerationError = inventoryMeasurement_.error ;
		}

		// 全nodeの移動が終わってからviewを作り、vector再確保で秘密keyを失効させません。
		for( std::size_t ordinal = 0U; ordinal < indexState->nodes.size(); ++ordinal) {
			const auto &node = indexState->nodes[ordinal] ;	// 発行後不変の秘密captureです。
			// HardwareとCompatibleの両集合を同じ原nodeへ結びます。
			for( const auto &ids : {std::cref( node.hardware), std::cref( node.compatible)}) {
				// 捕捉した全秘密IDのviewだけを原ordinalへ登録します。
				for( const auto &id : ids.get()) {
					indexState->idNodes[id].push_back( ordinal) ;
				}
			}

			// 一方の属性だけ成功したnodeも、元union全体の失敗診断を保持します。
			if( node.hardwareError != 0U || node.compatibleError != 0U) {
				indexState->failedIdNodes[node.classGuid].push_back( ordinal) ;
			}
		}

		indexInventory_ = std::move( indexState) ;
	}

	scanSessionId_ = execution == nullptr ? scanSessionId : 0U ;
	// 未処理集合は元scanで一度だけ作り、導入後に追加しません。
	for( const auto &entry : deviceInstances_) {
		pendingIndexDevices_.insert( entry.first) ;
	}

	result.succeeded = true ;
	result.outcome	 = partialFailure ? OutcomeCode::SUCCEEDED_WITH_ERRORS : OutcomeCode::SUCCESS ;
	// 現在属性だけの列挙を従来のcompatible driver判定数へ数えない。
	result.coverage.assessedDeviceCount = execution == nullptr ? assessedDeviceCount : 0U ;
	// Cancel・全体期限停止では、現在行を保持しても正常scan成功を返さない。
	if( execution != nullptr && execution->checkpoint() != 0) {
		result.succeeded = false ;
		indexInventory_.reset() ;
		result.error   = execution->checkpoint() ;
		result.outcome = execution->sessionStopReason() == MetadataSearchReason::CANCELLED
							 ? OutcomeCode::ABORTED
							 : OutcomeCode::FAILURE ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 直前のscanで実際に観測したlocal inventory計測を取得する。
 * @return Providerが所有する計測値への参照。次のscan、installまたは失効まで有効である。
 * @note 生のdevice識別子を含まず、呼出し元はworker thread内でだけ参照する。
 */
//------------------------------------------------------------------------------
const DeviceInventoryMeasurement &DriverStoreProvider::inventoryMeasurement() const noexcept
{
	return inventoryMeasurement_ ;
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 原deviceの未処理Uまたは当該実行Sへの所属を照合します。
 * @param[in] device 元opaque deviceです。
 * @return 未消費または当該scopeへ予約済みだけtrueです。
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::ownsInstallDevice( const std::wstring_view device) const noexcept
{
	return std::ranges::any_of( pendingIndexDevices_,
							   [&]( const auto &entry) { return entry == device ; }) ||
		   (activeInstallOperation_ != 0U &&
			std::ranges::find( activeIndexDevices_, device) != activeIndexDevices_.end()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元同scanの選択scopeと未処理所有を当該操作へ結びます。
 * @param[in] operationId 当該新操作です。
 * @param[in] session 未失効の元scanです。
 * @param[in] identities 元表示の選択candidate subsetです。
 * @return 元scopeの全件照合成功0、それ以外は拒否HRESULTです。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::beginInstallOperation(
	const OperationId operationId, const ScanSessionId session,
	const std::span<const std::wstring> identities)
{
	std::vector<std::wstring> devices ;	// 元mapからだけ選択deviceを求めます。
	// 別候補やnative値を外から補完しません。
	for( const auto &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// 元発行候補です。
		// 存在しない候補から予約を作りません。
		if( target == installTargets_.end()) {
			return E_INVALIDARG ;
		}

		const auto device = std::ranges::find(
			deviceInstances_, target->second.deviceInstanceId,
			[]( const auto &entry) { return entry.second ; }) ;	// 同nativeの元opaqueです。
		// 元native対応を失った候補を使いません。
		if( device == deviceInstances_.end()) {
			return E_INVALIDARG ;
		}

		devices.push_back( device->first) ;
	}

	return bindInstallDevices( operationId, session, devices) ;
}
//------------------------------------------------------------------------------
/**
 * @brief Compositeで検証した元device subsetを当該操作へ拘束します。
 * @param[in] operationId 新しいInstall操作です。
 * @param[in] session 未失効の元scanです。
 * @param[in] devices 元発行の一意なdevice subsetです。
 * @param[in] allowEmpty WUAだけの操作にnative実行scopeを作らず元ownerを保持する内部指定です。
 * @return 成功0、stale/不明/重複は失敗です。native変更は行いません。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::bindInstallDevices( const OperationId					operationId,
													const ScanSessionId					session,
													const std::span<const std::wstring> devices,
													const bool							allowEmpty)
{
	// 別scan/thread、旧操作、二重操作を予約前に拒否します。
	if( session == 0U || session != scanSessionId_ || ownerThreadId_ != GetCurrentThreadId() ||
	   operationId == 0U || operationId <= lastAcceptedInstallOperation_ ||
	   activeInstallOperation_ != 0U || (!allowEmpty && devices.empty()) ||
	   devices.size() > 4096U) {
		return E_INVALIDARG ;
	}

	std::unordered_set<std::wstring> unique ;	// 全件検証後だけcommitします。
	std::vector<std::wstring>		 pending ;	// 確保失敗時に元集合を変えません。
	// 同scanの未処理deviceだけを一度ずつ予約します。
	for( const auto &device : devices) {
		// 新device/消費済みdevice/重複を権限へ追加しません。
		if( !deviceInstances_.contains( device) || !pendingIndexDevices_.contains( device) ||
		   !unique.insert( device).second) {
			return E_INVALIDARG ;
		}

		pending.push_back( device) ;
	}

	activeInstallDevices_.swap( pending) ;
	activeInstallOperation_		  = operationId ;
	lastAcceptedInstallOperation_ = operationId ;
	installEntered_				  = false ;
	return 0 ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実Provider入口を通った当該操作だけを消費対象へ記録します。
 */
//------------------------------------------------------------------------------
void DriverStoreProvider::markInstallEntered() noexcept
{
	installEntered_ = activeInstallOperation_ != 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元同scanの選択scopeと未処理所有を当該操作へ結びます。
 * @param[in] operationId 当該新操作です。
 * @param[in] session 未失効の元scanです。
 * @return 当該操作の原未消費subsetです。不明な操作は空です。
 */
//------------------------------------------------------------------------------
std::optional<InstallRetentionSummary> DriverStoreProvider::finishInstallOperation(
	const OperationId operationId, const ScanSessionId session)
{
	// 他操作の終端から残存所有を公開しません。
	if( operationId == 0U || operationId != activeInstallOperation_ || session != scanSessionId_) {
		return std::nullopt ;
	}

	InstallRetentionSummary retained{
		operationId, session, installEntered_, {}, {}} ;	// 元subsetです。
	// 実行入口を通ったdeviceの候補だけを消費します。
	if( installEntered_) {
		// 元集合の各要素を同じscopeへ一度ずつ照合します。
		for( const auto &device : activeInstallDevices_) {
			const auto native = deviceInstances_.find( device) ;	// 元所有の対応です。
			pendingIndexDevices_.erase( device) ;
			// 他deviceの候補や元native対応は破棄しません。
			if( native != deviceInstances_.end()) {
				std::erase_if( installTargets_, [&]( const auto &entry) {
					return entry.second.deviceInstanceId == native->second ;
				}) ;
			}
		}
	}

	// 同selected deviceの未使用tokenも一括終了し、old eventから再検査許可を作りません。
	if( installEntered_) {
		std::erase_if( officialInfInstallBindings_, [&]( const auto &entry) {
			return std::ranges::find( activeInstallDevices_, entry.second.deviceIdentity) !=
				   activeInstallDevices_.end() ;
		}) ;
		std::erase_if( officialInstallerBindings_, [&]( const auto &entry) {
			return std::ranges::find( activeInstallDevices_, entry.second.identity) !=
				   activeInstallDevices_.end() ;
		}) ;
	}

	// 未消費の実targetだけを同scanの元opaqueへ結びます。
	for( const auto &entry : installTargets_) {
		const auto device =
			std::ranges::find( deviceInstances_, entry.second.deviceInstanceId,
							  []( const auto &item) { return item.second ; }) ;	// 同nativeです。
		// 原対応を失った候補を継続しません。
		if( device != deviceInstances_.end() && pendingIndexDevices_.contains( device->first)) {
			retained.candidates.push_back( {entry.first, device->first}) ;
		}
	}

	activeInstallDevices_.clear() ;
	activeInstallOperation_ = 0U ;
	installEntered_			= false ;
	return retained ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択された local driver node を再照合して device へ導入する。選択された local driver node を再照合して deviceへ導入する。 注記
 *        : scan 時の INF path を直接信用せず、実行直前に全 metadata を再照合する。
 * @param[in] scanSessionId 選択元の Driver Store scan session ID。
 * @param[in] identities UI に提示済みの opaque identity 群。
 * @param[in] parentWindowNative device installer の親 HWND を整数表現で渡す値。 device installer の親 HWNDを整数表現で渡
 *                   す値。
 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
 * @return 選択候補ごとの導入結果。
 * @note scan 時の INF path を直接信用せず、実行直前に全 metadata を再照合する。
 */
//------------------------------------------------------------------------------
InstallResult DriverStoreProvider::install( const ScanSessionId				   scanSessionId,
										   const std::span<const std::wstring> identities,
										   const std::uintptr_t				   parentWindowNative,
										   const ProviderProgressCallback	  &progressCallback)
{
	InstallResult result{} ;	// 選択identity順で個別結果を保持するinstall結果。
	result.updates.reserve( identities.size()) ;
	// 後続検証の成否にかかわらず、全選択identityへ個別結果を返す領域を用意する。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity = identity}) ;
	}

	// stale session、別 thread、空または不明 selection は system state を変える前に拒否する。
	std::unordered_set<std::wstring> uniqueIdentities ;	// 重複検証済みidentity集合。
	std::unordered_set<std::wstring> uniqueDevices ;	// 一device一候補を検証するnative ID集合。
	// 空の選択、失効session、所有thread外からの導入要求は全体失敗にしてsessionを破棄する。
	if( identities.empty() || scanSessionId == 0 || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	// Identityの重複、scan session内の存在、および一device一候補を事前検証する。
	for( const std::wstring &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// Scan時に保持した秘密target検索結果。
		// 未知候補、候補の重複、一deviceへの複数指定は導入前に全件拒否する。
		if( !uniqueIdentities.insert( identity).second || target == installTargets_.end() ||
		   !uniqueDevices.insert( target->second.deviceInstanceId).second) {
			result.downloadOutcome = OutcomeCode::FAILURE ;
			result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
			result.installOutcome  = OutcomeCode::FAILURE ;
			result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}
	}

	result.downloadOutcome = OutcomeCode::SUCCESS ;
	markInstallEntered() ;
	// Local Driver Store候補は追加downloadを必要としないため全件を成功扱いにする。
	for( UpdateExecutionResult &update : result.updates) {
		update.downloadOutcome = OutcomeCode::SUCCESS ;
	}

	progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
					  .percentComplete = 20,
					  .completedItems  = identities.size(),
					  .totalItems	   = identities.size()}) ;
	progressCallback( {.stage		   = ProviderStage::INSTALLING,
					  .percentComplete = 20,
					  .completedItems  = 0,
					  .totalItems	   = identities.size()}) ;

	std::size_t successCount{} ;	// Installに成功したselection数。
	NativeError lastError{} ;		// 最後に発生したinstall error。全成功時は0。
	// 元の選択順を維持し、各候補を再照合して個別結果へ反映する。
	for( std::size_t index = 0; index < identities.size(); ++index) {
		bool rebootRequired{} ;	// 現在targetが再起動を要求した場合はtrue。
		lastError = installTarget( installTargets_.at( identities[index]), parentWindowNative,
								  rebootRequired) ;
		UpdateExecutionResult &update = result.updates[index] ;	// 現在targetの個別結果。
		update.rebootRequired		  = rebootRequired ;
		result.rebootRequired		  = result.rebootRequired || rebootRequired ;
		// 指定nodeの導入が成功した候補だけを成功件数へ含める。
		if( lastError == 0) {
			update.installOutcome = OutcomeCode::SUCCESS ;
			++successCount ;
		} else {
			update.installOutcome = OutcomeCode::FAILURE ;
			update.installError	  = lastError ;
		}

		const std::uint64_t completed = index + 1 ;	// 現在までに導入を試行した候補数。
		progressCallback(
			{.stage			  = ProviderStage::INSTALLING,
			 .percentComplete = static_cast<std::uint32_t>( 20 + completed * 80 / identities.size()),
			 .completedItems  = completed,
			 .totalItems	  = identities.size()}) ;
	}

	result.succeeded = successCount == identities.size() ;
	result.installOutcome =
		successCount == identities.size()
			? OutcomeCode::SUCCESS
			: (successCount == 0 ? OutcomeCode::FAILURE : OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	result.installError = result.succeeded ? 0 : lastError ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief WUA の Hardware ID と一致する local device の opaque identity を取得する。
 * @param[in] hardwareId WUA が返した Hardware ID。外部へ公開しない。
 * @return 現在の scan で一致する device identity。曖昧または未検出なら `std::nullopt`。
 */
//------------------------------------------------------------------------------
std::optional<std::wstring> DriverStoreProvider::deviceIdentityForHardwareId(
	const std::wstring_view hardwareId) const
{
	// 空のHardware IDからdeviceを推測しない。
	if( hardwareId.empty()) {
		return std::nullopt ;
	}

	// 正規化Hardware IDに対応するlocal device検索結果。
	const auto iterator = hardwareToDevice_.find( normalizeIdentifier( hardwareId)) ;
	// 端末内で一意な照合先が得られないHardware IDは候補へ結び付けない。
	if( iterator == hardwareToDevice_.end() || iterator->second.empty() ||
	   !deviceInstances_.contains( iterator->second)) {
		return std::nullopt ;
	}

	return iterator->second ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式catalog snapshotへ端末内限定binding fingerprintを付与する。公式catalog snapshotへ端末内bindingを付与する。Opaque
 *        identityをworker内mapでnative IDへ解決し、全件成功した場合だけfingerprintを反映する。生IDは返さない。
 * @param[in] secret 管理者保護stateから読み取った端末固有HMAC key。 管理者保護stateの端末固有HMAC key。
 * @param[in,out] devices 現在scanのopaque identityを持つ非機密snapshot。 現在scanの公式catalog用snapshot。
 * @return 全deviceへ付与できた場合は0、session、identity、CNG失敗時はHRESULT。 全deviceへ付与できた場合は0、入力またはCNG失敗時はHRESULT。
 * @note Native device instance IDは本関数から返さず、network、UI、logへ渡さない。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::attachLocalOfficialBindingFingerprints(
	const LocalOfficialBindingSecret &secret, const std::span<OfficialCatalogDevice> devices) const
{
	constexpr std::size_t MAXIMUM_BINDING_DEVICES = 4'096U ;	// 一scanの付与件数上限。
	// 有効な所有threadのscanと上限内のsnapshotだけにbindingを付与する。
	if( scanSessionId_ == 0U || GetCurrentThreadId() != ownerThreadId_ ||
	   devices.size() > MAXIMUM_BINDING_DEVICES) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::unordered_set<std::wstring> identities ;	// Opaque identity重複検出集合。
	std::vector<std::wstring>		 fingerprints ;	// 全件成功まで保持するHMAC結果。
	identities.reserve( devices.size()) ;
	fingerprints.reserve( devices.size()) ;
	// 現在scanのopaque identityを一件ずつnative IDへ解決して不可逆化する。
	for( const OfficialCatalogDevice &device : devices) {
		const auto instance =	// Worker内だけで参照するnative instance ID検索結果。
			deviceInstances_.find( device.deviceIdentity) ;
		// 空、重複、現在scanに存在しないdevice identityはbinding対象にしない。
		if( device.deviceIdentity.empty() || !identities.insert( device.deviceIdentity).second ||
		   instance == deviceInstances_.end()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::wstring	  fingerprint ;	// 現在deviceの端末内HMAC表記。
		const NativeError error = makeLocalOfficialDeviceBindingFingerprint(
			secret, instance->second, fingerprint) ;	// Native ID不可逆化結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		fingerprints.push_back( std::move( fingerprint)) ;
	}

	// 全件の生成成功後だけcallerのsnapshotを更新する。
	for( std::size_t index = 0U; index < devices.size(); ++index) {
		devices[index].localBindingFingerprint = std::move( fingerprints[index]) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief G11-Cで分離した一つのINFを現在deviceのrankとread-onlyで比較する。G11-Cで分離した一INFのPnP具体性とrankを監査する。現在driverと単一候
 *        補INFのWindows rankをread-onlyで取得し、ID具体性とrankが退行しない場合だけApplicableとする。
 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID。
 * @param[in] deviceIdentity UIへ提示済みのopaque device identity。
 * @param[in] workspace Candidate driver閉包を所有する保護workspace。 Candidate閉包を所有する保護workspace。
 * @param[in] package G11-Cで構造を検証した一つのINF package。 G11-Cで構造検証した一INF package。
 * @param[out] audit PnP ID文字列を含まない具体性とrankの監査結果。 PnP ID文字列を含まない監査結果。
 * @return 拒否を含む監査判定の生成時は0、入力またはSetupAPI失敗時はHRESULT。 拒否を含む監査判定の生成時は0、処理失敗時はHRESULT。
 * @note 戻り値0だけでinstallを許可せず、auditのApplicableを別途確認する。
 * @note Driver Storeへのstage、driver選択、installまたはdevice state変更を行わない。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::auditOfficialInfRank( const ScanSessionId	  scanSessionId,
													  const std::wstring_view deviceIdentity,
													  const OfficialDownloadWorkspace &workspace,
													  const OfficialInfPackage		  &package,
													  OfficialDriverRankAudit		  &audit) const
{
	audit				= {} ;
	const auto instance =	// Opaque identityからworker内のnative IDを得る検索結果。
		deviceInstances_.find( std::wstring( deviceIdentity)) ;
	const std::optional<std::uint64_t> candidateVersion =
		// Candidateのpacked version。
		parseDriverVersion( package.driverVersion) ;
	// session、device、INF metadata、数値版の前提が揃わないrank監査要求を拒否する。
	if( scanSessionId == 0 || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() ||
	   instance == deviceInstances_.end() || package.infRelativePath.empty() ||
	   package.className.empty() || package.providerName.empty() || package.hardwareIds.empty() ||
	   !candidateVersion.has_value()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	SYSTEM_INFO nativeSystem{} ;	// Native OS architectureの取得先。
	driver_store_inf_detail::transport().architecture( &nativeSystem) ;
	// x64以外の実OSではこのINF監査経路を使用しない。
	if( nativeSystem.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const std::wstring candidateInfPath =	// SetupAPIへ渡すworkspace内INF絶対path。
		workspace.path( package.infRelativePath) ;
	// 展開先から候補INFを解決できなければ監査を開始しない。
	if( candidateInfPath.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const DWORD attributes = GetFileAttributesW( candidateInfPath.c_str()) ;	// INFのfile属性。
	// 候補INFの属性取得失敗は元のWindows診断値で返す。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// ディレクトリや再解析点を候補INFとして監査しない。
	if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	// Rank取得前に固定するdeviceと現在driver metadata。
	DeviceRankSnapshot before ;
	NativeError		   nativeError = readDeviceRankSnapshot( instance->second, before) ;	// 取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return nativeError ;
	}

	std::optional<std::uint32_t> currentRank ;	// 現在driverのWindows full rank。
	// Native未導入に現在rankを仮定せず、既知driverだけを非退行比較します。
	if( !before.noDriver) {
		nativeError = collectMatchingDriverRank(
			instance->second, std::nullopt, before.currentDriver.infFileName,
			before.currentDriver.provider, before.currentDriver.packedVersion.value(), std::nullopt,
			currentRank) ;
	}

	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return nativeError ;
	}

	std::optional<std::uint32_t> candidateRank ;			// 単一candidate INFのWindows full rank。
	std::wstring				 candidateInfClassGuid ;	// 同検査済み実INFのClassです。
	std::wstring				 candidateNativeClassGuid ;	// Windows互換一覧のClassです。
	nativeError = collectMatchingDriverRank(
		instance->second, std::wstring_view( candidateInfPath), candidateInfPath,
		package.providerName, candidateVersion.value(), std::nullopt, candidateRank,
		package.className, &candidateInfClassGuid, &candidateNativeClassGuid) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return nativeError ;
	}

	DeviceRankSnapshot after ;	// Rank取得後に再取得するdeviceと現在driver metadata。
	nativeError = readDeviceRankSnapshot( instance->second, after) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return nativeError ;
	}

	// 監査中にdevice状態が変化した場合は結果を採用せず再確認を要求する。
	if( !deviceRankSnapshotsEqual( before, after)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 既知device GUIDと候補GUIDの違いをClass名一致だけで通しません。
	if( before.classState == OfficialDriverRankDeviceClassState::KNOWN_CLASS &&
	   before.nativeClassGuid != candidateNativeClassGuid) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const OfficialDriverRankEvidence evidence{
		// Pure evaluatorへ渡すworker内限定根拠。
		.deviceClass			  = before.deviceClass,
		.candidateClass			  = package.className,
		.deviceHardwareIds		  = before.hardwareIds,
		.deviceCompatibleIds	  = before.compatibleIds,
		.candidateIds			  = package.hardwareIds,
		.currentMatchingDeviceId  = before.matchingDeviceId,
		.currentRank			  = currentRank,
		.candidateRank			  = candidateRank,
		.currentState			  = before.noDriver ? OfficialDriverRankCurrentState::NO_DRIVER
													: OfficialDriverRankCurrentState::KNOWN_DRIVER,
		.deviceClassState		  = before.classState,
		.candidateInfClassGuid	  = candidateInfClassGuid,
		.candidateNativeClassGuid = candidateNativeClassGuid,
	} ;
	// rank判定に必要な証拠が整合しなければ監査成功としない。
	if( !evaluateOfficialDriverRank( evidence, audit)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在版を要求せず単一INFのWindows compatible nodeを観測する。
 * @param[in] scanSessionId 現在inventoryのsession。
 * @param[in] deviceIdentity 当該sessionのopaque device identity。
 * @param[in] workspace 検証済みINF閉包の所有領域。
 * @param[in] package 内容と署名を検証したINF。
 * @param[out] candidateRank 一致nodeの最小Windows rank。非適用・失敗時は空。
 * @return 全列挙完了時0、入力・SetupAPI・有限上限違反時はHRESULT。
 * @note 空結果とAPI失敗を区別する。現在driverとの順位比較や導入許可は発行しない。Workerから呼び、staging、driver選択、installを行わない。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::observeInfCandidateRank(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::optional<std::uint32_t> &candidateRank) const
{
	candidateRank.reset() ;
	// Session、所有thread、有限なopaque IDを先に確認する。
	if( scanSessionId == 0 || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() ||
	   deviceIdentity.size() > 256U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto instance =
			// 秘密native ID。
			deviceInstances_.find( std::wstring( deviceIdentity)) ;
		const auto version		= parseDriverVersion( package.driverVersion) ;	// 候補だけの明示版。
		const std::wstring path = workspace.path( package.infRelativePath) ;	// 保護された単一INF。
		// 現在版や表示名を要求せず、候補の固定metadataと対象identityを確認する。
		if( instance == deviceInstances_.end() || !version || path.empty() ||
		   package.providerName.empty() || package.hardwareIds.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const DWORD attributes = GetFileAttributesW( path.c_str()) ;	// INFの現在属性。
		// Fileを読めない失敗をPnP非適用へ変換しない。
		if( attributes == INVALID_FILE_ATTRIBUTES) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 通常file以外をSetupAPIへ渡さない。
		if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		const NativeError error = collectMatchingDriverRank(
			instance->second, std::wstring_view( path), path, package.providerName, *version,
			std::nullopt, candidateRank, package.className) ;	// Windowsの適合観測。
		// 部分列挙に成功したnodeがあっても、全列挙失敗なら結果を公開しない。
		if( error != 0) {
			candidateRank.reset() ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		candidateRank.reset() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 監査済み公式INFを現在device状態と一意なWindows nodeへ拘束する。監査済み公式INFを現在状態と一意なWindows nodeへ拘束する。現在状態と候補nodeを
 *        再取得し、全照合成功後だけ単調増加tokenへ秘密metadataをcommitする。OS状態は変更しない。
 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID。
 * @param[in] deviceIdentity UIへ提示済みのopaque device identity。
 * @param[in] workspace Candidate driver閉包を所有する保護workspace。 Candidate閉包を所有する保護workspace。
 * @param[in] package G11-Cで構造を検証した一つのINF package。 内容監査済みの一INF package。
 * @param[in] expectedCurrentProvider Scan結果に固定した現在Provider表示名。 Scan時の現在Provider名。
 * @param[in] expectedCurrentVersion Scan結果に固定した現在version。 Scan時の現在version。
 * @param[in] expectedCurrentDate Scan結果に固定した現在のYYYY/MM/DD日付。 Scan時の現在日付。
 * @param[in] expectedRankAudit 発行前に合格したPnP具体性とrank監査結果。 直前に合格したrank監査結果。
 * @param[out] binding 成功時の一scan限定opaque binding。失敗時は空値。 成功時の非機密opaque binding。
 * @param[out] diagnostic 任意の元拒否位置です。実行判定に使用しません。
 * @return 発行成功時は0、入力、状態変更、一意性またはSetupAPI失敗時はHRESULT。 Binding発行時は0、状態変更、曖昧性またはSetupAPI失敗時はHRESULT。
 * @note 生のinstance ID、PnP ID、INF path、sectionはDriver Store内だけに保持する。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createOfficialInfInstallBinding(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::wstring_view expectedCurrentProvider, const std::wstring_view expectedCurrentVersion,
	const std::wstring_view expectedCurrentDate, const OfficialDriverRankAudit &expectedRankAudit,
	OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnostic)
{
	// 公開入口でだけ診断を初期化し、下位から戻った拒否を保持します。
	if( diagnostic) {
		*diagnostic		 = {} ;
		diagnostic->path = 1U ;
	}

	// 基礎node適合だけで未確認の明示依存を実行可能な標準INFへ補完しません。
	if( package.hasExternalDependencies) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
							  InfBindingReject::SINGLE_DEPENDENCY) ;
	}

	const auto error = createOfficialInfInstallBindingImpl(
		scanSessionId, deviceIdentity, workspace, package, expectedCurrentProvider,
		expectedCurrentVersion, expectedCurrentDate, expectedRankAudit, binding,
		diagnostic) ;	// 具体的拒否位置は下位の最初の値を維持します。
	return bindingFailure( diagnostic, error, InfBindingReject::BINDING_STATE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 標準入口または私有計画入口で確認したbase nodeを発行します。
 * @param[in] scanSessionId 元scanです。
 * @param[in] deviceIdentity 元opaqueです。
 * @param[in] workspace 検証済み閉包です。
 * @param[in] package 検証済み一INFです。
 * @param[in] expectedCurrentProvider 元現在providerです。
 * @param[in] expectedCurrentVersion 元現在versionです。
 * @param[in] expectedCurrentDate 元現在日付です。
 * @param[in] expectedRankAudit 元Windows rankです。
 * @param[out] binding 同状態の一意nodeだけです。
 * @param[out] diagnostic 任意の元拒否位置です。実行判定に使用しません。
 * @return 一意性/全状態一致0、それ以外はHRESULTです。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createOfficialInfInstallBindingImpl(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::wstring_view expectedCurrentProvider, const std::wstring_view expectedCurrentVersion,
	const std::wstring_view expectedCurrentDate, const OfficialDriverRankAudit &expectedRankAudit,
	OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnostic)
{

	binding				= {} ;
	const auto instance =	// Opaque identityからworker内のnative IDを得る検索結果。
		deviceInstances_.find( std::wstring( deviceIdentity)) ;
	const std::optional<std::uint64_t> candidateVersion =
		// Candidate INFのpacked version。
		parseDriverVersion( package.driverVersion) ;
	const std::optional<std::uint64_t> currentVersion =
		// Scan時現在版のpacked値。
		parseDriverVersion( expectedCurrentVersion) ;
	const std::optional<std::wstring> candidateDate =
		// Candidate INFの正規化日付。
		normalizeInfDriverDate( package.driverDate) ;
	const bool initialInstall = expectedRankAudit.currentState ==
								OfficialDriverRankCurrentState::NO_DRIVER ;	// 実rank監査方式。
	// 現在版、候補版、日付、適用可能rankを含むbindingの全前提を確認する。
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() ||
	   instance == deviceInstances_.end() || !ownsInstallDevice( deviceIdentity) ||
	   package.infRelativePath.empty() || package.className.empty() ||
	   package.providerName.empty() || package.hardwareIds.empty() ||
	   (initialInstall
			? !expectedCurrentProvider.empty() || !expectedCurrentVersion.empty() ||
				  !expectedCurrentDate.empty()
			: expectedCurrentProvider.empty() || expectedCurrentVersion.empty() ||
				  expectedCurrentDate.empty() || !currentVersion || *currentVersion == 0U) ||
	   !candidateVersion.has_value() || candidateVersion.value() == 0U ||
	   !candidateDate.has_value() ||
	   expectedRankAudit.decision != OfficialDriverRankDecision::APPLICABLE) {
		return bindingFailure( diagnostic, static_cast<NativeError>( E_INVALIDARG),
							  InfBindingReject::INPUT) ;
	}

	// scan内のbinding保持数が上限に達した場合は追加を拒否する。
	if( officialInfInstallBindings_.size() >= MAXIMUM_OFFICIAL_INF_BINDINGS) {
		return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
	}

	// 無効値や周回するtokenを発行せず、bindingの一意性を維持する。
	if( nextOfficialBindingToken_ == 0U ||
	   nextOfficialBindingToken_ == std::numeric_limits<std::uint64_t>::max()) {
		return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
	}

	SYSTEM_INFO nativeSystem{} ;	// Native OS architectureの取得先。
	driver_store_inf_detail::transport().architecture( &nativeSystem) ;
	// x64以外の実OSには公式INF導入bindingを作成しない。
	if( nativeSystem.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
							  InfBindingReject::ARCHITECTURE, nativeSystem.wProcessorArchitecture) ;
	}

	const std::wstring candidateInfPath =	// SetupAPIへ渡すworkspace内INF絶対path。
		workspace.path( package.infRelativePath) ;
	// 空または埋込NULを含むINF pathをWindows APIへ渡さない。
	if( candidateInfPath.empty() || candidateInfPath.find( L'\0') != std::wstring::npos) {
		return bindingFailure( diagnostic, static_cast<NativeError>( E_INVALIDARG),
							  InfBindingReject::INPUT) ;
	}

	const DWORD attributes = GetFileAttributesW( candidateInfPath.c_str()) ;	// INFのfile属性。
	// binding対象INFの属性取得失敗をそのまま通知する。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return bindingFailure( diagnostic, nativeErrorFromWin32( GetLastError()),
							  InfBindingReject::INF_FILE) ;
	}

	// 通常file以外のINFをbindingへ登録しない。
	if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	DeviceRankSnapshot			deviceSnapshot ;	// 発行時に固定する現在device状態。
	CandidateDriverNodeSnapshot candidateSnapshot ;	// 発行時に固定するWindows node。
	OfficialDriverRankAudit		currentRankAudit ;	// 発行時に再生成するrank監査結果。
	const NativeError			collectError = collectOfficialInfBindingState(
		  instance->second, candidateInfPath, package, candidateVersion.value(),
		  candidateDate.value(), deviceSnapshot, candidateSnapshot, currentRankAudit,
		  diagnostic) ;	// 全状態のread-only固定結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( collectError != 0) {
		return bindingFailure( diagnostic, collectError, InfBindingReject::BINDING_STATE) ;
	}

	// 同inventory世代の元Classをbinding時の別観測で置き換えません。
	if( indexInventory_) {
		const auto origin =
			std::find_if( indexInventory_->nodes.begin(), indexInventory_->nodes.end(),
						 [deviceIdentity]( const IndexInventoryState::Node &node) {
							 return node.identity == deviceIdentity ;
						 }) ; // 同期中だけopaqueを借用します。
		// 元scanのClass読取失敗や状態変化を候補Classから補完しません。
		if( origin == indexInventory_->nodes.end() || origin->classError != 0U ||
		   deviceSnapshot.classState != origin->classObservation.classState ||
		   deviceSnapshot.classRead.state != origin->classObservation.classRead.state ||
		   deviceSnapshot.classGuidRead.state != origin->classObservation.classGuidRead.state ||
		   deviceSnapshot.deviceClass != origin->classObservation.deviceClass ||
		   deviceSnapshot.nativeClassGuid != origin->classObservation.nativeClassGuid ||
		   deviceSnapshot.observedClassGuid != origin->classObservation.observedClassGuid ||
		   (deviceSnapshot.classState != OfficialDriverRankDeviceClassState::KNOWN_CLASS &&
			!origin->initialClassUnknown)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// Scan表示値、現在実状態、直前監査のいずれかが変わった場合は再scanを要求する。
	if( deviceSnapshot.currentDriver.provider != expectedCurrentProvider ||
	   deviceSnapshot.currentDriver.version != expectedCurrentVersion ||
	   deviceSnapshot.currentDriver.date != expectedCurrentDate ||
	   deviceSnapshot.noDriver != initialInstall ||
	   (!initialInstall && deviceSnapshot.currentDriver.packedVersion != currentVersion) ||
	   currentRankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
	   !officialRankAuditsEqual( expectedRankAudit, currentRankAudit)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	OfficialInfInstallBindingRecord record ;	// Tokenへcommitする秘密binding記録。
	record.scanSessionId			   = scanSessionId ;
	record.deviceIdentity			   = deviceIdentity ;
	record.device.deviceInstanceId	   = instance->second ;
	record.device.deviceClass		   = std::move( deviceSnapshot.deviceClass) ;
	record.device.hardwareIds		   = std::move( deviceSnapshot.hardwareIds) ;
	record.device.compatibleIds		   = std::move( deviceSnapshot.compatibleIds) ;
	record.device.matchingDeviceId	   = std::move( deviceSnapshot.matchingDeviceId) ;
	record.device.currentInfFileName   = std::move( deviceSnapshot.currentDriver.infFileName) ;
	record.device.currentProvider	   = std::move( deviceSnapshot.currentDriver.provider) ;
	record.device.currentVersion	   = std::move( deviceSnapshot.currentDriver.version) ;
	record.device.currentDate		   = std::move( deviceSnapshot.currentDriver.date) ;
	record.device.currentPackedVersion = deviceSnapshot.currentDriver.packedVersion.value_or( 0U) ;
	record.device.noDriver			   = deviceSnapshot.noDriver ;
	record.device.classRead			   = deviceSnapshot.classRead ;
	record.device.classGuidRead		   = deviceSnapshot.classGuidRead ;
	record.device.observedClassGuid	   = std::move( deviceSnapshot.observedClassGuid) ;
	record.device.nativeClassGuid	   = std::move( deviceSnapshot.nativeClassGuid) ;
	record.device.classState		   = deviceSnapshot.classState ;
	record.device.node				   = deviceSnapshot.node ;
	record.device.driverKeyRead		   = deviceSnapshot.driverKeyRead ;
	record.device.matchingRead		   = deviceSnapshot.matchingRead ;
	record.device.driverKey			   = std::move( deviceSnapshot.driverKey) ;
	record.candidate.infPath		   = candidateInfPath ;
	record.candidate.sectionName	   = std::move( candidateSnapshot.sectionName) ;
	record.candidate.provider		   = std::move( candidateSnapshot.provider) ;
	record.candidate.version		   = std::move( candidateSnapshot.version) ;
	record.candidate.date			   = std::move( candidateSnapshot.date) ;
	record.candidate.packedVersion	   = candidateSnapshot.packedVersion ;
	record.candidate.dateTicks		   = candidateSnapshot.dateTicks ;
	record.candidate.rank			   = candidateSnapshot.rank ;
	record.candidate.infClassGuid	   = std::move( candidateSnapshot.infClassGuid) ;
	record.candidate.classGuid		   = std::move( candidateSnapshot.classGuid) ;
	record.rankAudit				   = currentRankAudit ;

	OfficialInfInstallBinding output ;	// Commit成功後だけcallerへ渡す非機密binding。
	output.token			 = nextOfficialBindingToken_ ;
	output.currentProvider	 = record.device.currentProvider ;
	output.currentVersion	 = record.device.currentVersion ;
	output.currentDate		 = record.device.currentDate ;
	output.candidateProvider = record.candidate.provider ;
	output.candidateVersion	 = record.candidate.version ;
	output.candidateDate	 = record.candidate.date ;
	output.rankAudit		 = record.rankAudit ;
	try {
		// 単調増加tokenをemplaceし、既存bindingを上書きしない。
		const auto insertResult =
			officialInfInstallBindings_.emplace( output.token, std::move( record)) ;
		// 既存tokenへの挿入失敗を成功扱いせず、一意なbindingだけを返す。
		if( !insertResult.second) {
			return nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
		}
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	++nextOfficialBindingToken_ ;
	binding = std::move( output) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同issuer元記録から全import内容とdevice別選択関係を再構築します。
 * @param[in] inspection 同保護元byteと全CAT/memberの検査所有者です。
 * @param[in] record 同session/device/元INFに固定した私有binding記録です。
 * @param[out] plan 成功時だけ同原順の不変内容計画です。失敗時は空です。
 * @param[out] diagnosticStage 任意の数値段階です。生ID・path・節名を含みません。
 * @return 元byteと選択節/role関係確認0、その他は元HRESULTです。
 * @note Worker内read-only処理です。単独の導入許可を発行しません。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::buildRequiredInfComponentPlan(
	const CommonInfInspection &inspection, const OfficialInfInstallBindingRecord &record,
	std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	RequiredInfBindingDiagnostic					   *diagnosticStage) const
{
	plan.reset() ;
	// 明示された端末内診断だけへ段階を返し、実行可否の入力には使いません。
	if( diagnosticStage) {
		diagnosticStage->stage = 3U ;
	}

	const auto error =
		// 非機能importも全byte/CATへ再照合します。
		reverifyCommonDriverInf( inspection) ;
	// 別元INF/session/private stateの節を同内容へ転用しません。
	if( error != 0 || record.scanSessionId != inspection.scanSessionId || !inspection.workspace ||
	   normalizeIdentifier( record.candidate.infPath) !=
		   normalizeIdentifier( inspection.workspace->path( inspection.infRelativePath))) {
		return error ? error : static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<OfficialInfPackage> selections{	// 元順の全import copyです。
												   inspection.closure.packages.front()} ;
		selections.insert( selections.end(), inspection.requiredInfPackages.begin(),
						  inspection.requiredInfPackages.end()) ;
		OfficialInfPackage selectedBase ;	// 元metadataと出力をaliasさせない選択copyです。
		// 元private節の関係解析と元内容再検査の拒否を区別します。
		if( diagnosticStage) {
			diagnosticStage->stage = 4U ;
		}

		const auto selectedError = inspectSelectedOfficialInfRelations(
			*inspection.workspace, inspection.closure.entries, selections.front(),
			record.candidate.sectionName,
			selectedBase) ;	// 同private nodeの基本名だけから解析します。
		// 任意節や非実在fallbackを必要役割の選択成功へ変換しません。
		if( selectedError != 0) {
			return bindingFailure( diagnosticStage, selectedError,
								  InfBindingReject::SELECTED_RELATIONS) ;
		}

		selectedBase.selectedNativeRank = record.candidate.rank ;
		selections.front()				= std::move( selectedBase) ;
		std::vector<bool> visited(
			// 八package以内で各active roleを一度だけ解析します。
			selections.size()) ;
		std::vector<std::size_t> queue{0U} ;	// private選択baseからの有限機能queueです。
		visited[0] = true ;
		// 選択節のCopyINFだけを解析します。非選択importは全内容検査のまま保持します。
		for( std::size_t position = 0U; position < queue.size(); ++position) {
			const auto index = queue[position] ;	// 同原順の選択packageです。
			// 現deviceで必要な元参照だけを同保護閉包へ結合します。
			for( const auto &path : selections[index].activeRequiredInfPaths) {
				const auto found = std::ranges::find_if( selections, [&]( const auto &value) {
					return normalizeIdentifier( value.infRelativePath) == normalizeIdentifier( path) ;
				}) ; // 元内容copyだけを同期借用します。
				// 原importの欠損を基本INFだけの成功へ変換しません。
				if( found == selections.end()) {
					// 同じHRESULTになる二つの拒否を数値だけで区別します。
					if( diagnosticStage) {
						diagnosticStage->stage = found == selections.end() ? 5U : 6U ;
					}

					return bindingFailure( diagnosticStage,
										  nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
										  InfBindingReject::COPY_INF_MISSING) ;
				}

				// 元CopyINFの独立基本INFはstage用内容です。別deviceのnative nodeやinstallを作りません。
				if( found->role == DriverPlanRole::BASE_DRIVER) {
					continue ;
				}

				const auto ordinal =
					// 八件内ordinalです。
					static_cast<std::size_t>( found - selections.begin()) ;
				// 共有参照は一度だけ解決し、循環は全import graphで別に拒否します。
				if( visited[ordinal]) {
					continue ;
				}

				visited[ordinal] = true ;
				// Extensionだけは同じ親の役割ClassとWindows compatible nodeで選択節を固定します。
				if( found->role == DriverPlanRole::EXTENSION) {
					// 追加役割のnative nodeと関係解析を別段階に保持します。
					if( diagnosticStage) {
						diagnosticStage->stage = 7U ;
					}

					CandidateDriverNodeSnapshot node ;	// 同親/同元INFだけの私有互換nodeです。
					const auto					nodeError = collectUniqueCandidateDriverNode(
						 record.device.deviceInstanceId,
						 inspection.workspace->path( found->infRelativePath), found->className,
						 found->providerName, parseDriverVersion( found->driverVersion).value_or( 0U),
						 normalizeInfDriverDate( found->driverDate).value_or( L""),
						 node) ;	// base Class/rankを流用しません。
					// 同Extensionのnative適合失敗を名称やbase成功から補完しません。
					if( nodeError != 0) {
						return bindingFailure( diagnosticStage, nodeError,
											  InfBindingReject::CANDIDATE_NODE, 7U) ;
					}

					OfficialInfPackage selected ;	// 同役割nodeからの機能関係だけです。
					// 実役割node選択後の元INF解析段階です。
					if( diagnosticStage) {
						diagnosticStage->stage = 8U ;
					}

					const auto relationError = inspectSelectedOfficialInfRelations(
						*inspection.workspace, inspection.closure.entries, *found, node.sectionName,
						selected) ;	// 同元INFを借用します。
					// 元役割選択の解析失敗を一baseの成功へ代替しません。
					if( relationError != 0) {
						return bindingFailure( diagnosticStage, relationError,
											  InfBindingReject::SELECTED_RELATIONS, 8U) ;
					}

					selected.selectedNativeRank = node.rank ;
					*found						= std::move( selected) ;
				}

				queue.push_back( ordinal) ;
			}
		}

		// 共通内容計画の拒否を上位private選択の拒否と区別します。
		if( diagnosticStage) {
			diagnosticStage->stage = 9U ;
		}

		return makeRequiredDriverComponentPlan( inspection, selections, plan, diagnosticStage) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済み役割計画を単一親の私有bindingへ固定します。
 * @param[in] session 元scan sessionです。
 * @param[in] identity 元選択親のopaque identityです。
 * @param[in] inspection 同byte/CAT検証済み閉包です。
 * @param[out] plan 同deviceの私有node選択から生成した不変関係です。失敗時は空です。
 * @param[in] provider 元現在行のproviderです。
 * @param[in] version 元現在行のversionです。
 * @param[in] date 元現在行の日付です。
 * @param[in] audit 元baseのWindows rank監査です。
 * @param[out] binding 全照合成功時だけ発行する元親bindingです。
 * @param[out] diagnosticStage 任意の非所有数値診断先です。nullなら採取せず権限判定へ使いません。
 * @return 成功0、関係/適用性/元状態の拒否はHRESULTです。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createRequiredInfInstallBinding(
	const ScanSessionId session, const std::wstring_view identity,
	const CommonInfInspection &inspection, std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	const std::wstring_view provider, const std::wstring_view version, const std::wstring_view date,
	const OfficialDriverRankAudit &audit, OfficialInfInstallBinding &binding,
	RequiredInfBindingDiagnostic *diagnosticStage)
{
	binding = {} ;
	plan.reset() ;
	// 空入力と実検査以降を別の数値として保持します。
	if( diagnosticStage) {
		*diagnosticStage	  = {} ;
		diagnosticStage->path = 2U ;
	}

	// 公開件数や別sessionから元閉包の導入権限を発行しません。
	if( !inspection.workspace || inspection.scanSessionId != session) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 元全role/CAT/memberの再検証開始を採取します。
	if( diagnosticStage) {
		diagnosticStage->stage = 1U ;
	}

	auto error = reverifyCommonDriverInf( inspection) ;	// 全role/CAT/memberを再確認します。
	// 再検証失敗はbindingへ進めません。
	if( error != 0U) {
		return bindingFailure( diagnosticStage, error, InfBindingReject::CONTENT_REVERIFY) ;
	}

	// 元親の完全native状態の固定段階です。
	if( diagnosticStage) {
		diagnosticStage->stage = 2U ;
	}

	error = createOfficialInfInstallBindingImpl( session, identity, *inspection.workspace,
												inspection.closure.packages.front(), provider,
												version, date, audit, binding, diagnosticStage) ;
	// 元親の完全状態と一意nodeを先に固定します。
	if( error != 0U) {
		return error ;
	}

	auto &record =
		// 同issuerで今固定した元nodeです。
		officialInfInstallBindings_.at( binding.token) ;
	error = buildRequiredInfComponentPlan( inspection, record, plan, diagnosticStage) ;
	// 私有node解析が成立した計画だけを元tokenへ固定します。
	if( error == 0) {
		record.requiredPlan = plan ;
		// 同issuer記録との直前再照合を別段階として採取します。
		if( diagnosticStage) {
			diagnosticStage->stage = 10U ;
		}

		error = revalidateRequiredInfInstallBinding( session, identity, inspection, plan, binding,
													diagnosticStage) ;
		// 下位が採取した最初の拒否を維持し、元binding再照合失敗の欠測も防ぎます。
		error = bindingFailure( diagnosticStage, error, InfBindingReject::BINDING_STATE, 10U) ;
	}

	// 関係/適用性拒否では未公開tokenを残しません。
	if( error != 0U) {
		static_cast<void>( discardOfficialInfInstallBinding( session, binding.token)) ;
		binding = {} ;
		plan.reset() ;
	}

	// 全成功だけを最終段階へ進め、失敗した段階は変更しません。
	if( error == 0U && diagnosticStage) {
		diagnosticStage->stage = 11U ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元親と全必要役割を変更前にread-onlyで再検証します。
 * @param[in] session 元scanです。
 * @param[in] identity 元親opaqueです。
 * @param[in] inspection 元保護閉包です。
 * @param[in] plan 元私有関係です。
 * @param[in] binding 元親bindingです。
 * @param[in,out] diagnosticStage null可の最初の固定拒否段階です。
 * @return 全byte/関係/元状態一致0、失効/未確認はHRESULTです。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::revalidateRequiredInfInstallBinding(
	const ScanSessionId session, const std::wstring_view identity,
	const CommonInfInspection								 &inspection,
	const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	const OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnosticStage) const
{
	const auto stored = officialInfInstallBindings_.find( binding.token) ;	// 元issuer記録です。
	// 別byte/別session/公開DTOから転用した計画は拒否します。
	if( !plan || !inspection.workspace || stored == officialInfInstallBindings_.end() ||
	   stored->second.requiredPlan != plan || plan->session_ != session ||
	   plan->basePath_ != inspection.infRelativePath) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	auto error = revalidateOfficialInfInstallBinding(
		session, identity, *inspection.workspace, inspection.closure.packages.front(),
		binding) ;	// 同元node/現在stateを先に再照合します。
	// 元選択変化を旧節名の再解析で隠しません。
	if( error != 0) {
		return error ;
	}

	std::shared_ptr<const RequiredDriverComponentPlan>
		fresh ;	// 現在の同原byte/役割nodeから再構築します。
	error = buildRequiredInfComponentPlan( inspection, stored->second, fresh, diagnosticStage) ;
	// 元必要関係の全memberを現在byteへ再照合します。
	if( error != 0U || !fresh || fresh->members_.size() != plan->members_.size() ||
	   fresh->verifiedNeedsEdgeCount_ != plan->verifiedNeedsEdgeCount_) {
		return error ? error : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 件数一致だけで異なるWindows選択節/role rankを受理しません。
	if( fresh->selectedPackages_.size() != plan->selectedPackages_.size()) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// 非機能importの原順と機能選択の全関係を維持します。
	for( std::size_t index = 0U; index < plan->selectedPackages_.size(); ++index) {
		const auto &before = plan->selectedPackages_[index] ;	// 同private planの元選択です。
		const auto &after  = fresh->selectedPackages_[index] ;	// 現在の同元INF選択です。
		// 別node節/装飾/Windows rank/参照/必要子を同計画へ補正しません。
		if( before.selectedBasicSection != after.selectedBasicSection ||
		   before.selectedInstallSection != after.selectedInstallSection ||
		   before.selectedNativeRank != after.selectedNativeRank ||
		   before.activeRequiredInfPaths != after.activeRequiredInfPaths ||
		   before.requiredComponents != after.requiredComponents) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 検証されたsource順と関係を保持し、件数だけで一致しません。
	for( std::size_t i = 0; i < plan->members_.size(); ++i) {
		const auto &a = plan->members_[i] ;		// 元関係です。
		const auto &b = fresh->members_[i] ;	// 現在byteの関係です。
		// 親/ID/Class役割の差は復旧前に拒否します。
		if( a.packageOrdinal != b.packageOrdinal || a.role != b.role ||
		   a.parentPackageOrdinal != b.parentPackageOrdinal ||
		   a.componentHardwareIds != b.componentHardwareIds ||
		   a.packageOrdinal >= inspection.requiredInfPackages.size()) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}

		const auto &package = inspection.requiredInfPackages[a.packageOrdinal] ;	// 元roleです。
		GUID		nativeClass{} ;													// 実INFの独立Classです。
		error = readCandidateInfClass( inspection.workspace->path( package.infRelativePath),
									  package.className, nativeClass) ;
		// Class文字列だけでroleを確定しません。
		if( error != 0U || normalizeIdentifier( formatClassGuid( nativeClass)) !=
							  normalizeIdentifier( package.classGuid)) {
			return error ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// Extensionは同じ元親のPnP一致が必要で、base Class一致は要求しません。
		if( a.role == DriverPlanRole::EXTENSION) {
			const auto &device = stored->second.device ;	// 元親の秘密IDだけです。
			const bool	match  = std::ranges::any_of( package.hardwareIds, [&]( const auto &id) {
				  return std::ranges::any_of( device.hardwareIds,
											 [&]( const auto &local) {
												 return normalizeIdentifier( id) ==
														normalizeIdentifier( local) ;
											 }) ||
						 std::ranges::any_of( device.compatibleIds, [&]( const auto &local) {
							 return normalizeIdentifier( id) == normalizeIdentifier( local) ;
						 }) ;
			  }) ; // Modelsの表記同一ではなく実PnP一致です。
			// 別device extensionを一計画へ追加しません。
			if( !match) {
				return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
			}
		}
	}

	return revalidateOfficialInfInstallBinding( session, identity, *inspection.workspace,
											   inspection.closure.packages.front(), binding) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 必要役割をstageし指定親と一意な必要SWC子だけを導入します。
 * @param[in] session 元scanです。
 * @param[in] identity 元選択親です。
 * @param[in] inspection 元検証済み閉包です。
 * @param[in] plan 元私有関係です。
 * @param[in] binding 元親bindingです。
 * @param[in] parentWindowNative 明示操作の親windowです。
 * @param[out] roles 実際のstage/指定導入/Windows反映待ちを役割別に保持します。
 * @param[out] rebootRequired 実APIが返した再起動要否です。
 * @return 全指定API完了0、反映待ちS_FALSE、部分失敗はHRESULTです。
 * @note 必要roleの元/登録INF/rootを変更非共有で計画終端まで保持します。Extension反映をbase API成功から推測しません。全device導入APIを呼びません。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installBoundRequiredInfPlan(
	const ScanSessionId session, const std::wstring_view identity,
	const CommonInfInspection								 &inspection,
	const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	const OfficialInfInstallBinding &binding, const std::uintptr_t parentWindowNative,
	std::vector<DriverPlanRoleExecutionResult> &roles, bool &rebootRequired)
{
	roles.clear() ;
	rebootRequired = false ;
	auto error	   = revalidateRequiredInfInstallBinding( session, identity, inspection, plan,
														 binding) ;	// 変更直前の同issuer診断です。
	// 全選択preflightとは別に変更直前も全関係を確認します。
	if( error != 0U) {
		return error ;
	}

	roles.resize( plan->members_.size() + 1U) ;
	roles.front().role	  = DriverPlanRole::BASE_DRIVER ;
	roles.front().ordinal = 1U ;
	std::vector<std::unique_ptr<RegisteredInfGuard>> registrations(
		// 計画終端まで全登録INFをpinします。
		roles.size()) ;
	// 各必要memberの未実行も結果分母へ保持します。
	for( std::size_t i = 0; i < plan->members_.size(); ++i) {
		roles[i + 1U].role	  = plan->members_[i].role ;
		roles[i + 1U].ordinal = static_cast<std::uint32_t>( i + 2U) ;
	}

	// Windows CopyINFの再帰import前に全必要INFを同境界でstageします。
	for( std::size_t order = 0; order < roles.size(); ++order) {
		const auto	i = (order + 1U) % roles.size() ;	// 必要role先行、baseは最後です。
		const auto &package =
			i ? inspection.requiredInfPackages[plan->members_[i - 1U].packageOrdinal]
			  : inspection.closure.packages.front() ;	// 実閉包memberです。
		std::wstring staged ;							// 検証済み登録先です。
		registrations[i] =
			std::make_unique<RegisteredInfGuard>() ;	// 各roleの元/root/登録を単独所有します。
		error = registrations[i]->initialize( inspection.workspace->path( package.infRelativePath)) ;
		// 元/rootを保持できない役割は登録や後続device作用へ進めません。
		if( error == 0U) {
			error = stageOfficialInfPackage( *inspection.workspace, package, staged) ;
		}

		// 関数内stage guardの終了後も同じ全byteを保持し、後続base作用中の変更を防ぎます。
		if( error == 0U) {
			error = registrations[i]->verify( staged) ;
		}

		roles[i].stageError	  = error ;
		roles[i].stageOutcome = error ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
		roles[i].reflection =
			error ? DriverPlanReflectionState::FAILED : DriverPlanReflectionState::STAGED ;
		// 部分stageを全成功にせず、後続未実行を残します。
		if( error != 0U) {
			return error ;
		}
	}

	error = installBoundOfficialInfImpl(
		session, identity, *inspection.workspace, inspection.closure.packages.front(), binding,
		parentWindowNative, rebootRequired, &roles.front().installDiagnosticMissing) ;
	roles.front().installError	 = error ;
	roles.front().installOutcome = error ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
	roles.front().reflection	 = error ? DriverPlanReflectionState::FAILED
										 : DriverPlanReflectionState::INSTALL_API_COMPLETED ;
	// Base API失敗では必要子/extension完了を推測しません。
	if( error != 0U) {
		return error ;
	}

	bool	   pending{} ;														// Extensionまたは非同期SWC列挙は未確認です。
	const auto parentInstance = deviceInstances_.at( std::wstring( identity)) ;	// 元選択親です。
	// 各必要roleを同じ親だけへ限定します。
	for( std::size_t i = 0; i < plan->members_.size(); ++i) {
		const auto &member = plan->members_[i] ;	// 元AddComponent/CopyINF関係です。
		auto	   &role   = roles[i + 1U] ;		// 候補別に保持する実結果です。
		// ExtensionのWindows適用順位と反映を独自に置換しません。
		if( member.role == DriverPlanRole::EXTENSION) {
			role.reflection = DriverPlanReflectionState::WINDOWS_PENDING ;
			pending			= true ;
			continue ;
		}

		DeviceRankSnapshot parent ;	// 実base反映とstartedをread-only確認します。
		error			 = readDeviceRankSnapshot( parentInstance, parent) ;
		const auto &base = inspection.closure.packages.front() ;	// 元検証baseです。
		// Base API成功だけで子の親startedや反映を補完しません。
		if( error != 0U || parent.node.read.state != DevicePropertyReadState::VALUE ||
		   (parent.node.statusFlags.value_or( 0U) & DN_STARTED) == 0U || parent.noDriver ||
		   normalizeIdentifier( parent.currentDriver.provider) !=
			   normalizeIdentifier( base.providerName) ||
		   parent.currentDriver.version != base.driverVersion ||
		   parent.currentDriver.date != normalizeInfDriverDate( base.driverDate).value_or( L"")) {
			role.reflection	  = DriverPlanReflectionState::WINDOWS_PENDING ;
			role.installError = error ;
			pending			  = true ;
			continue ;
		}

		DeviceInfoSet devices( driver_store_inf_detail::transport().inventory.open(
			nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT)) ;	// Present子だけです。
		std::wstring  childInstance ;										// 一意に結合した秘密SWC子です。
		// 集合生成失敗を子不存在へ変換しません。
		if( !devices.valid()) {
			error = nativeErrorFromWin32( GetLastError()) ;
		} else {
			// 元親とSWC IDが一致する一意なpresent子を有限列挙します。
			for( DWORD n = 0; n <= 4096U; ++n) {
				SP_DEVINFO_DATA child{} ;	// 同集合の候補子です。
				child.cbSize = sizeof( child) ;
				// 正式終端以外の失敗を部分一致成功にしません。
				if( !driver_store_inf_detail::transport().inventory.enumerate( devices.get(), n,
																			 &child)) {
					const auto native = GetLastError() ;	// 元列挙診断です。
					error = native == ERROR_NO_MORE_ITEMS ? 0 : nativeErrorFromWin32( native) ;
					break ;
				}

				// 有限上限を超える集合では実行しません。
				if( n == 4096U) {
					error = nativeErrorFromWin32( ERROR_MORE_DATA) ;
					break ;
				}

				std::wstring relation ;	// 親の正式read-only propertyです。
				// 未読取や異なる親を必要子としません。
				if( !readDeviceString( devices.get(), child, DEVPKEY_Device_Parent, relation) ||
				   normalizeIdentifier( relation) != normalizeIdentifier( parentInstance)) {
					continue ;
				}

				// 同present子の元Hardware ID群です。worker内の照合だけに使います。
				const auto ids =
					readDeviceStringList( devices.get(), child, DEVPKEY_Device_HardwareIds) ;
				const bool matches = std::ranges::any_of( ids, [&]( const auto &id) {
					return std::ranges::any_of(
						member.componentHardwareIds, [&]( const auto &expected) {
							return normalizeIdentifier( id) == normalizeIdentifier( expected) ;
						}) ;
				}) ; // 元ComponentIDsにWindowsが付加するSWC IDだけです。
				// 無関係SWC/appを導入しません。
				if( !matches) {
					continue ;
				}

				std::wstring instance ;	// worker内限定childです。
				// 曖昧子とID読取失敗を一意な子へ変換しません。
				if( !childInstance.empty() ||
				   !readDeviceInstanceId( devices.get(), child, instance)) {
					error = nativeErrorFromWin32( ERROR_DUP_NAME) ;
					break ;
				}

				childInstance = std::move( instance) ;
			}
		}

		// 列挙失敗は部分失敗、正式不存在はWindows反映待ちです。
		if( error != 0U) {
			role.installError	= error ;
			role.installOutcome = OutcomeCode::FAILURE ;
			role.reflection		= DriverPlanReflectionState::FAILED ;
			return error ;
		}

		// 非同期にまだ生成されていない子を推測導入しません。
		if( childInstance.empty()) {
			role.reflection = DriverPlanReflectionState::WINDOWS_PENDING ;
			pending			= true ;
			continue ;
		}

		// 計画ordinalに結合した元検査済み子packageです。
		const auto				   &package = inspection.requiredInfPackages[member.packageOrdinal] ;
		DeviceRankSnapshot			child ;	// 子の全現在状態です。
		CandidateDriverNodeSnapshot node ;	// 子の一意な指定INF nodeです。
		OfficialDriverRankAudit		audit ;	// 子に対する実rankです。
		error = collectOfficialInfBindingState(
			childInstance, inspection.workspace->path( package.infRelativePath), package,
			parseDriverVersion( package.driverVersion).value_or( 0U),
			normalizeInfDriverDate( package.driverDate).value_or( L""), child, node, audit) ;
		const auto childIdentity = std::wstring( identity) + L"/required-component-" +
								   // UI非公開の同操作内opaqueです。
								   std::to_wstring( i + 1U) ;
		OfficialInfInstallBinding childBinding ;	// 同issuer child用です。
		// 子の同Class/全状態/一意node/非退行rankからのみ権限を発行します。
		if( error == 0U) {
			deviceInstances_.emplace( childIdentity, childInstance) ;
			error = createOfficialInfInstallBindingImpl(
				session, childIdentity, *inspection.workspace, package,
				child.currentDriver.provider, child.currentDriver.version, child.currentDriver.date,
				audit, childBinding) ;
			// 完全に固定した元親を子tokenの私有作用範囲へ結合します。
			if( error == 0U) {
				officialInfInstallBindings_.at( childBinding.token).requiredParentInstance =
					parentInstance ;
			}
		}

		DeviceRankSnapshot beforeChild ;	// 指定子の直前に親の完全状態を再確認します。
		// 別親/started変化では子を導入しません。
		if( error == 0U) {
			error = readDeviceRankSnapshot( parentInstance, beforeChild) ;
			// 子binding作成中の親変化を拒否します。
			if( error == 0U && !deviceRankSnapshotsEqual( parent, beforeChild)) {
				error = nativeErrorFromWin32( ERROR_RETRY) ;
			}
		}

		bool childReboot{} ;	// 子APIの実再起動値です。
		// flags0の非null一意nodeだけを一present子へ導入します。
		if( error == 0U) {
			error = installBoundOfficialInfImpl( session, childIdentity, *inspection.workspace,
												package, childBinding, parentWindowNative,
												childReboot, &role.installDiagnosticMissing) ;
		}

		static_cast<void>( discardOfficialInfInstallBinding( session, childBinding.token)) ;
		deviceInstances_.erase( childIdentity) ;
		rebootRequired		= rebootRequired || childReboot ;
		role.installError	= error ;
		role.installOutcome = error ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
		role.reflection		= error ? DriverPlanReflectionState::FAILED
									: DriverPlanReflectionState::INSTALL_API_COMPLETED ;
		// 変更済みbaseと未実行残memberを保持して部分失敗を返します。
		if( error != 0U) {
			return error ;
		}
	}

	return pending ? static_cast<NativeError>( S_FALSE) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式INF導入bindingと現在のdeviceおよびWindows nodeを再照合する。公式INF導入bindingと現在状態を再照合する。発行時の現在INF、版、日付、PnP
 *        状態と候補section、版、日付、rankを再取得値へ比較する。OS状態は変更しない。
 * @param[in] scanSessionId Bindingを発行した現在session ID。 Binding発行元のscan session ID。
 * @param[in] deviceIdentity Bindingに対応するopaque device identity。 Bindingに対応するopaque device ID。
 * @param[in] workspace 再検証済みcandidate閉包を所有する保護workspace。 再検証済みcandidateの保護workspace。
 * @param[in] package 再検証済みの一つのINF package。 再検証済みの一INF package。
 * @param[in] binding Provider workerが保持した非機密binding。 Provider workerが保持する非機密binding。
 * @return 全記録が一致する場合は0、失効、変更またはSetupAPI失敗時はHRESULT。 全記録一致時は0、失効、変更またはSetupAPI失敗時はHRESULT。
 * @note 本関数はDriver Storeへのstage、driver選択、installを行わない。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::revalidateOfficialInfInstallBinding(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const OfficialInfInstallBinding &binding) const
{
	const auto stored =	// Opaque tokenから秘密binding記録を得る検索結果。
		officialInfInstallBindings_.find( binding.token) ;
	const auto instance =	// Opaque identityが現在scanに存在するかの検索結果。
		deviceInstances_.find( std::wstring( deviceIdentity)) ;
	// token、session、所有thread、deviceの対応が保持記録と一致する場合だけ再検証する。
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || binding.token == 0U || deviceIdentity.empty() ||
	   stored == officialInfInstallBindings_.end() || instance == deviceInstances_.end() ||
	   !ownsInstallDevice( deviceIdentity) || stored->second.scanSessionId != scanSessionId ||
	   stored->second.deviceIdentity != deviceIdentity ||
	   stored->second.device.deviceInstanceId != instance->second) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const OfficialInfInstallBindingRecord &record = stored->second ;	// 発行時の秘密記録。
	// Callerが保持した非機密部分もtokenの記録と完全一致しなければ拒否する。
	if( binding.currentProvider != record.device.currentProvider ||
	   binding.currentVersion != record.device.currentVersion ||
	   binding.currentDate != record.device.currentDate ||
	   binding.candidateProvider != record.candidate.provider ||
	   binding.candidateVersion != record.candidate.version ||
	   binding.candidateDate != record.candidate.date ||
	   !officialRankAuditsEqual( binding.rankAudit, record.rankAudit)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::optional<std::uint64_t> candidateVersion =
		// 再検証INFのpacked version。
		parseDriverVersion( package.driverVersion) ;
	const std::optional<std::wstring> candidateDate =
		// 再検証INFの正規化日付。
		normalizeInfDriverDate( package.driverDate) ;
	// 再検証に必要なINF metadata、候補版、日付が欠けた要求を拒否する。
	if( package.infRelativePath.empty() || package.className.empty() ||
	   package.providerName.empty() || package.hardwareIds.empty() ||
	   !candidateVersion.has_value() || candidateVersion.value() == 0U ||
	   !candidateDate.has_value()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring candidateInfPath =	// 再検証済みworkspace内INF絶対path。
		workspace.path( package.infRelativePath) ;
	// 再検証するINF pathが空または埋込NUL付きなら拒否する。
	if( candidateInfPath.empty() || candidateInfPath.find( L'\0') != std::wstring::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 候補path、provider、版、日付がbinding作成時から変わった場合は再確認を要求する。
	if( candidateInfPath != record.candidate.infPath ||
	   normalizeIdentifier( package.providerName) !=
		   normalizeIdentifier( record.candidate.provider) ||
	   candidateVersion.value() != record.candidate.packedVersion ||
	   candidateDate.value() != record.candidate.date) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	const DWORD attributes = GetFileAttributesW( candidateInfPath.c_str()) ;	// INFのfile属性。
	// 再検証時にINF属性を取得できなければ導入へ進めない。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// binding作成後に通常file以外へ変わったINFを拒否する。
	if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	DeviceRankSnapshot			deviceSnapshot ;	// 導入前に再取得する現在device状態。
	CandidateDriverNodeSnapshot candidateSnapshot ;	// 導入前のcandidate Windows node。
	OfficialDriverRankAudit		currentRankAudit ;	// 導入前に再生成するrank監査結果。
	const NativeError			collectError = collectOfficialInfBindingState(
		  instance->second, candidateInfPath, package, candidateVersion.value(),
		  candidateDate.value(), deviceSnapshot, candidateSnapshot,
		  currentRankAudit) ;	// 全状態のread-only再検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( collectError != 0) {
		return collectError ;
	}

	const bool deviceMatches =	// 発行時に固定した秘密device状態との完全一致結果。
		deviceSnapshot.deviceClass == record.device.deviceClass &&
		deviceSnapshot.classState == record.device.classState &&
		deviceSnapshot.classRead.state == record.device.classRead.state &&
		deviceSnapshot.classGuidRead.state == record.device.classGuidRead.state &&
		deviceSnapshot.observedClassGuid == record.device.observedClassGuid &&
		deviceSnapshot.nativeClassGuid == record.device.nativeClassGuid &&
		deviceSnapshot.node.read.state == record.device.node.read.state &&
		deviceSnapshot.node.statusFlags == record.device.node.statusFlags &&
		deviceSnapshot.node.problemCode == record.device.node.problemCode &&
		deviceSnapshot.driverKeyRead.state == record.device.driverKeyRead.state &&
		deviceSnapshot.matchingRead.state == record.device.matchingRead.state &&
		deviceSnapshot.driverKey == record.device.driverKey &&
		deviceSnapshot.hardwareIds == record.device.hardwareIds &&
		deviceSnapshot.compatibleIds == record.device.compatibleIds &&
		deviceSnapshot.matchingDeviceId == record.device.matchingDeviceId &&
		deviceSnapshot.currentDriver.infFileName == record.device.currentInfFileName &&
		deviceSnapshot.currentDriver.provider == record.device.currentProvider &&
		deviceSnapshot.currentDriver.version == record.device.currentVersion &&
		deviceSnapshot.currentDriver.date == record.device.currentDate &&
		deviceSnapshot.noDriver == record.device.noDriver &&
		(record.device.noDriver ? !deviceSnapshot.currentDriver.packedVersion
								: deviceSnapshot.currentDriver.packedVersion &&
									  *deviceSnapshot.currentDriver.packedVersion ==
										  record.device.currentPackedVersion) ;
	CandidateDriverNodeSnapshot expectedCandidate ;	// 発行時nodeの比較用snapshot。
	expectedCandidate.infClassGuid	= record.candidate.infClassGuid ;
	expectedCandidate.classGuid		= record.candidate.classGuid ;
	expectedCandidate.sectionName	= record.candidate.sectionName ;
	expectedCandidate.provider		= record.candidate.provider ;
	expectedCandidate.version		= record.candidate.version ;
	expectedCandidate.date			= record.candidate.date ;
	expectedCandidate.packedVersion = record.candidate.packedVersion ;
	expectedCandidate.dateTicks		= record.candidate.dateTicks ;
	expectedCandidate.rank			= record.candidate.rank ;
	// device、候補node、rankの再照合結果が保持証拠と異なる場合は導入を拒否する。
	if( !deviceMatches || !candidateNodeSnapshotsEqual( expectedCandidate, candidateSnapshot) ||
	   currentRankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
	   !officialRankAuditsEqual( record.rankAudit, currentRankAudit)) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定scanに属する一つの公式INF導入bindingを明示的に破棄する。現在sessionと所有workerを照合し、他候補のbindingを維持したまま未発行候補の秘密記録だけ
 *        を破棄する。
 * @param[in] scanSessionId Bindingを発行したscan session ID。
 * @param[in] token Driver Storeが発行した0ではないopaque token。 Driver Storeが発行したopaque token。
 * @return 一件を破棄した場合true。別session、別workerまたは未登録ならfalse。 一件を破棄した場合true。不一致または未登録ならfalse。
 * @note 他Providerが同じscanで保持するbindingは変更しない。
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::discardOfficialInfInstallBinding( const ScanSessionId scanSessionId,
														   const std::uint64_t token) noexcept
{
	// 旧sessionまたは別workerから現在tokenを破棄させない。
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ || token == 0U ||
	   GetCurrentThreadId() != ownerThreadId_) {
		return false ;
	}

	return officialInfInstallBindings_.erase( token) == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定scanに属する全公式INF導入bindingを明示的に失効させる。指定scanの公式INF導入bindingを明示的に失効させる。現在sessionと所有workerが一致す
 *        る場合だけ全tokenを破棄する。旧sessionから現在bindingを失効させない。
 * @param[in] scanSessionId Bindingを発行したscan session ID。
 * @note 旧sessionまたは所有worker以外からの要求では現在bindingを変更しない。
 */
//------------------------------------------------------------------------------
void DriverStoreProvider::invalidateOfficialInfInstallBindings(
	const ScanSessionId scanSessionId) noexcept
{
	// 別sessionまたは所有thread外の要求では現在のbindingを失効させない。
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_) {
		return ;
	}

	officialInfInstallBindings_.clear() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同保護INFのbyteを再確認して一度だけstoreへimportします。
 * @param[in] workspace 元保護領域です。
 * @param[in] package 同byte検証済みINFです。
 * @param[out] stagedInfPath 検証済み登録root直下の秘密pathです。
 * @return stageと元/登録byte一致0、それ以外はHRESULTです。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::stageOfficialInfPackage( const OfficialDownloadWorkspace &workspace,
														 const OfficialInfPackage		 &package,
														 std::wstring &stagedInfPath) const
{
	stagedInfPath.clear() ;
	const auto sourceInfPath = workspace.path( package.infRelativePath) ;	// 元秘密pathです。
	// 登録APIのpath上限と完全な終端を確保します。
	if( sourceInfPath.empty() || sourceInfPath.find( L'\0') != std::wstring::npos ||
	   sourceInfPath.size() >= MAX_PATH) {
		return nativeErrorFromWin32( ERROR_FILENAME_EXCED_RANGE) ;
	}

	RegisteredInfGuard registration ;										// 同root/元byte/登録byteを保持します。
	auto			   error = registration.initialize( sourceInfPath) ;	// 登録前確認です。
	// 保護root/元byte未確認ではstageしません。
	if( error != 0U) {
		return error ;
	}

	const auto cached = stagedOfficialInfs_.find( sourceInfPath) ;	// 同元INF限定cacheです。
	// 同byte登録先だけを再利用します。
	if( cached != stagedOfficialInfs_.end()) {
		// 変化した元byteへ旧登録先を流用しません。
		if( cached->second.sourceSha256 != registration.sourceSha256()) {
			return nativeErrorFromWin32( ERROR_CRC) ;
		}

		stagedInfPath = cached->second.path ;
	} else {
		std::array<wchar_t, MAX_PATH> destination{} ;	// Windows返却の完全登録先です。
		DWORD						  required{} ;		// NUL込み要素数です。
		SetLastError( ERROR_SUCCESS) ;
		const auto copied = driver_store_inf_detail::transport().stage(
			sourceInfPath.c_str(), nullptr, SPOST_PATH, SP_COPY_NOOVERWRITE, destination.data(),
			// importのみです。
			static_cast<DWORD>( destination.size()), &required, nullptr) ;
		const auto copyError = copied ? ERROR_SUCCESS : GetLastError() ;	// 元診断です。
		// 既存登録以外のstage失敗を保持します。
		if( !copied && copyError != ERROR_FILE_EXISTS) {
			return nativeErrorFromWin32( copyError ? copyError : ERROR_INVALID_DATA) ;
		}

		// 切詰め、未終端、埋込NULのpathを許可しません。
		if( required <= 1U || required > destination.size() || destination.front() == L'\0' ||
		   destination[required - 1U] != L'\0') {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		stagedInfPath.assign( destination.data(), required - 1U) ;
		// 初期bufferの余りをpathへ含めません。
		if( stagedInfPath.find( L'\0') != std::wstring::npos) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	error = registration.verify( stagedInfPath) ;
	// 登録root直下と全元byte一致を確認します。
	if( error != 0U) {
		return error ;
	}

	// 初回確認済み登録だけをcacheします。
	if( cached == stagedOfficialInfs_.end()) {
		stagedOfficialInfs_.emplace( sourceInfPath,
									StagedOfficialInf{registration.sourceSha256(), stagedInfPath}) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Bindingで固定した監査済み公式INFをstagingして指定deviceへ導入する。Bindingを再検証後、SetupCopyOEMInfWが返した登録先INFから一意な
 *        nodeを再構築する。導入直前にも現在状態を確認し、DiInstallDeviceへ非nullのDriverInfoDataとFlags 0を渡す。
 * @param[in] scanSessionId Bindingを発行した現在scan session ID。 Bindingを発行した現在session。
 * @param[in] deviceIdentity Bindingに対応するopaque device identity。 対象のopaque device identity。
 * @param[in] workspace 再検証済みcandidate閉包を所有する保護workspace。 再検証済みINF閉包の保護workspace。
 * @param[in] package 再検証済みの一つのINF package。 再検証済みの一INF package。
 * @param[in] binding Provider workerが保持する一scan限定binding。 Providerが保持する一scan限定binding。
 * @param[in] parentWindowNative Windows導入dialogの親Window値。 Installer親HWNDの整数表現。
 * @param[out] rebootRequired 導入完了に再起動が必要な場合はtrue。
 * @return Stagingと指定device導入の成功時は0、それ以外はHRESULT。
 * @note Windowsが返した登録先INFだけを再照合し、登録済みpackageを自動削除しない。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installBoundOfficialInf( const ScanSessionId	 scanSessionId,
														 const std::wstring_view deviceIdentity,
														 const OfficialDownloadWorkspace &workspace,
														 const OfficialInfPackage		 &package,
														 const OfficialInfInstallBinding &binding,
														 const std::uintptr_t parentWindowNative,
														 bool				 &rebootRequired) const
{
	const auto stored = officialInfInstallBindings_.find( binding.token) ;	// 私有権限の境界です。
	// 公開single-INF入口から必要役割計画のtokenを部分導入しません。
	if( package.hasExternalDependencies ||
	   (stored != officialInfInstallBindings_.end() && stored->second.requiredPlan)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	return installBoundOfficialInfImpl( scanSessionId, deviceIdentity, workspace, package, binding,
									   parentWindowNative, rebootRequired) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 私有前提を満たした指定一deviceの元実装を実行します。
 * @param[in] scanSessionId 元scanです。
 * @param[in] deviceIdentity 元opaqueです。
 * @param[in] workspace 元保護閉包です。
 * @param[in] package 元検証済みINFです。
 * @param[in] binding 元一意nodeです。
 * @param[in] parentWindowNative 明示操作の親windowです。
 * @param[out] rebootRequired 実APIの再起動値です。
 * @param[out] diagnosticMissing 非nullは同期中だけ借用する出力です。FALSE/LastError0の観測だけtrueです。
 * @return stage/指定API完了0、それ以外はHRESULTです。
 * @note FALSE/LastError0では内部ERROR_INVALID_DATAを返し、実Windowsの同error観測と区別します。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installBoundOfficialInfImpl(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const OfficialInfInstallBinding &binding, const std::uintptr_t parentWindowNative,
	bool &rebootRequired, bool *diagnosticMissing) const
{
	// 未到達・他の拒否を指定APIの診断欠落へ読み替えません。
	if( diagnosticMissing) {
		*diagnosticMissing = false ;
	}

	rebootRequired			= false ;
	NativeError nativeError = revalidateOfficialInfInstallBinding(
		scanSessionId, deviceIdentity, workspace, package, binding) ;	// Staging前の固定状態確認。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return nativeError ;
	}

	const auto stored =	// 再検証済みtokenから秘密node記録を得る検索結果。
		officialInfInstallBindings_.find( binding.token) ;
	const auto instance =	// Opaque identityからnative device IDを得る検索結果。
		deviceInstances_.find( std::wstring( deviceIdentity)) ;
	// bindingと現在deviceの対応を失った場合はINF登録を開始しない。
	if( stored == officialInfInstallBindings_.end() || instance == deviceInstances_.end() ||
	   stored->second.device.deviceInstanceId != instance->second) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const OfficialInfInstallBindingRecord &record = stored->second ;	// 固定済み秘密binding記録。
	const std::wstring sourceInfPath =									// SetupCopyOEMInfWへ渡すnull終端の監査済みINF path。
		workspace.path( package.infRelativePath) ;
	// 空または埋込NUL付きのsource INF pathを登録APIへ渡さない。
	if( sourceInfPath.empty() || sourceInfPath.find( L'\0') != std::wstring::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 登録APIへ渡すpathが対応長を超える場合は切り詰めず拒否する。
	if( sourceInfPath.size() >= static_cast<std::size_t>( MAX_PATH)) {
		return nativeErrorFromWin32( ERROR_FILENAME_EXCED_RANGE) ;
	}

	RegisteredInfGuard registration ;	// Root/元INF/登録INFを指定導入の終端までpinします。
	nativeError = registration.initialize( sourceInfPath) ;
	// 登録rootや元実byteを確認できなければstageを呼びません。
	if( nativeError != 0U) {
		return nativeError ;
	}

	std::wstring stagedInfPath ;	// 共通stage境界が照合した登録先だけです。
	nativeError = stageOfficialInfPackage( workspace, package, stagedInfPath) ;
	// 共通境界の失敗を指定device導入へ進めません。
	if( nativeError != 0U) {
		return nativeError ;
	}

	nativeError = registration.verify( stagedInfPath) ;
	// 既知登録rootの直下と元INF全byteが一致する場合だけnode再構築へ進みます。
	if( nativeError != 0U) {
		return nativeError ;
	}

	const DWORD stagedAttributes = GetFileAttributesW( stagedInfPath.c_str()) ;	// 登録先属性。
	// 登録先INFの属性を取得できなければnodeの再構築へ進めない。
	if( stagedAttributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 登録先がディレクトリまたは再解析点なら導入を拒否する。
	if( (stagedAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	DeviceInfoSet devices(
		// 対象一件用set。
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合を取得できなければ登録済みnodeを検索しない。
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	SP_DEVINFO_DATA device{} ;	// Bindingで固定したinstanceを再openしたdevice metadata。
	device.cbSize = sizeof( device) ;
	// binding対象deviceを開けなければ別deviceへ代替せず中止する。
	if( driver_store_inf_detail::transport().open( devices.get(), instance->second.c_str(), nullptr,
												 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	GUID stagedClass{} ;	// 元byteと一致する登録INFの独立Class確認です。
	nativeError = readCandidateInfClass( stagedInfPath, package.className, stagedClass) ;
	// 同じ実INFのClassが発行時と異なれば指定nodeへ進みません。
	if( nativeError != 0U || formatClassGuid( stagedClass) != record.candidate.infClassGuid) {
		return nativeError != 0U ? nativeError : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	nativeError = configureSingleInfDriverSearch( devices.get(), device, stagedInfPath) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return nativeError ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// Staged INF compatible listのRAII guard。
	// Windowsの互換driver list構築に失敗した場合は独自候補を作らない。
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	SP_DRVINFO_DATA_W selectedDriver{} ;	// 元完全tuple内で唯一最小rankのstaged node。
	// 一覧構築の返却Classも元INFと発行時候補の両GUIDに結合します。
	if( !IsEqualGUID( device.ClassGuid, stagedClass) ||
	   formatClassGuid( device.ClassGuid) != record.candidate.classGuid) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	bool found{} ;			// 元完全tuple内の最小rank候補を保持した場合はtrue。
	bool bestRankTied{} ;	// 現在の最小full rankに複数nodeがある場合はtrue。
	bool
		selectedMatchesBinding{} ;			// 最小nodeの節、原日時ticksとrankも元bindingに一致する場合はtrue。
	std::uint32_t bestRank{} ;				// foundの場合だけ有効なWindows full rank。
	bool		  enumerationComplete{} ;	// trueの場合はcompatible nodeを上限内で最後まで確認済み。
	// Windowsがstaged INFから生成した全nodeを読み、元tuple内の唯一最良を再選択する。
	for( DWORD index = 0U; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 現在照合しているstaged INFのdriver node。
		driver.cbSize = sizeof( driver) ;
		// 列挙APIの終了を検出し、正常終端と途中失敗を区別する。
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			const DWORD enumerationError = GetLastError() ;	// 列挙終了または失敗診断値。
			// 候補列挙の正常終端以外は診断値を保持して中止する。
			if( enumerationError != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( enumerationError) ;
			}

			enumerationComplete = true ;
			break ;
		}

		DriverDetail detail ;	// Staged nodeが参照するINFとinstall section。
		// node詳細が取得不能または不正なら一意性を確認できないため中止する。
		if( !readDriverDetail( devices.get(), device, driver, detail)) {
			const DWORD detailError = GetLastError() ;	// Detail取得失敗または不正値。
			return nativeErrorFromWin32( detailError == ERROR_SUCCESS ? ERROR_INVALID_DATA
																	 : detailError) ;
		}

		std::uint32_t rank{} ;	// Windowsがstaged nodeへ算出したfull rank。
		nativeError = readDriverRank( devices.get(), device, driver, rank) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( nativeError != 0) {
			return nativeError ;
		}

		const bool matches =	// 元INF完全path、Provider、packed版、暦日の一致結果。
			normalizeIdentifier( detail.infFileName) == normalizeIdentifier( stagedInfPath) &&
			normalizeIdentifier( driver.ProviderName) ==
				normalizeIdentifier( record.candidate.provider) &&
			driver.DriverVersion == record.candidate.packedVersion &&
			formatDriverDate( driver.DriverDate) == record.candidate.date ;
		// 登録先INFと保持証拠に一致しないnodeは導入対象から除外する。
		if( !matches) {
			continue ;
		}

		// 同点を即時確定せず、後の低rankで旧同点を解消できるよう保持する。
		if( found && rank == bestRank) {
			bestRankTied = true ;
			continue ;
		}

		// 元winnerより悪いnodeがあるだけでは指定導入を曖昧にしない。
		if( found && rank > bestRank) {
			continue ;
		}

		selectedDriver		   = driver ;
		found				   = true ;
		bestRank			   = rank ;
		bestRankTied		   = false ;
		selectedMatchesBinding = normalizeIdentifier( detail.sectionName) ==
									 normalizeIdentifier( record.candidate.sectionName) &&
								 fileTimeTicks( driver.DriverDate) == record.candidate.dateTicks &&
								 rank == record.candidate.rank ;
	}

	// 列挙上限までに正常終端を確認できなければ一意性を保証しない。
	if( !enumerationComplete) {
		return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
	}

	// 登録先に一致するnodeが存在しなければ導入しない。
	if( !found) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// 最小rankの同点は登録済みnodeでも許可しない。
	if( bestRankTied) {
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	// 旧nodeが残っていても新しい唯一winnerへ差し替わった場合は再scanを要求する。
	if( !selectedMatchesBinding) {
		return nativeErrorFromWin32( ERROR_RETRY) ;
	}

	// Staging中の現在driver変更も検出し、成功済み登録を削除せずdevice導入だけを中止する。
	nativeError = revalidateOfficialInfInstallBinding( scanSessionId, deviceIdentity, workspace,
													  package, binding) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( nativeError != 0) {
		return nativeError ;
	}

	nativeError = registration.verify( stagedInfPath) ;
	// Node検索後にもpinした登録path/全byteを再確認し、元INF以外を指定しません。
	if( nativeError != 0U) {
		return nativeError ;
	}

	const HWND parentWindow =	// Caller所有のHWNDをWin32境界でだけ元の型へ戻す。
		reinterpret_cast<HWND>( parentWindowNative) ;
	BOOL nativeRebootRequired = FALSE ;	// DiInstallDeviceが返す再起動要求flag。
	// 指定nodeの導入失敗はWindows診断値として呼出側へ返す。
	// 必要SWCは指定node直前にも元親を正式propertyへ再照合します。
	if( !record.requiredParentInstance.empty()) {
		std::wstring currentParent ;	// 同present子の現在親です。
		// 親の変更/読取不成立を元選択の範囲へ補完しません。
		if( !readDeviceString( devices.get(), device, DEVPKEY_Device_Parent, currentParent) ||
		   normalizeIdentifier( currentParent) !=
			   normalizeIdentifier( record.requiredParentInstance)) {
			return nativeErrorFromWin32( ERROR_RETRY) ;
		}
	}

	// 同private sessionの再確認済みdevice/nodeだけをflags0で指定します。
	if( driver_store_inf_detail::transport().install( parentWindow, devices.get(), &device,
													&selectedDriver, 0,
													&nativeRebootRequired) == FALSE) {
		const DWORD installError =
			// FALSE直後の元診断です。欠落は成功ではありません。
			GetLastError() ;
		// 内部補完と実Windows診断を別観測へ保持します。所有権は移しません。
		if( diagnosticMissing) {
			*diagnosticMissing = installError == ERROR_SUCCESS ;
		}

		return nativeErrorFromWin32( installError == ERROR_SUCCESS ? ERROR_INVALID_DATA
																  : installError) ;
	}

	rebootRequired = nativeRebootRequired != FALSE ;
	rememberInstalledObservationTarget( instance->second, stagedInfPath, selectedDriver.ProviderName,
									   selectedDriver.DriverVersion) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済み外部INFを現在scanの一つのopaque deviceへ導入する。検証済み外部INFを現在scanの一deviceへ導入する。指定INF一件だけからcompatible
 *        listを構築し、Providerとversionが一意なnodeだけを対象deviceへ導入する。
 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID。
 * @param[in] deviceIdentity UIへ提示済みのopaque device identity。 対象のopaque device identity。
 * @param[in] infPath Providerが再検証した保護workspace内INF絶対path。 再検証済みINFの保護workspace絶対path。
 * @param[in] expectedProvider Scan時に検証したINF Provider表示名。 Scan時のINF Provider表示名。
 * @param[in] expectedVersion Scan時に検証した4要素numeric driver version。 Scan時の4要素numeric version。
 * @param[in] parentWindowNative Device installerの親HWNDを整数表現で渡す値。 Installer親HWNDの整数表現。
 * @param[out] rebootRequired 完了に再起動が必要な場合は`true`。
 * @return 導入成功時は0、session、再照合またはWindows API失敗時はHRESULT。 対象nodeの再照合と導入成功時は0、それ以外はHRESULT。
 * @pre 呼出し側はINF、CAT、全参照fileの署名とPnP適用性を直前に再検証する。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installVerifiedExternalInf(
	const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
	const std::wstring_view infPath, const std::wstring_view expectedProvider,
	const std::wstring_view expectedVersion, const std::uintptr_t parentWindowNative,
	bool &rebootRequired) const
{

	rebootRequired = false ;
	const std::optional<std::uint64_t> packedVersion =
		// Scan時versionの再照合値。
		parseDriverVersion( expectedVersion) ;
	const auto instance = deviceInstances_.find( std::wstring( deviceIdentity)) ;	// Native ID検索。
	// 有効なsession、所有thread、device、INF path、provider、数値版を導入前に確認する。
	if( scanSessionId == 0 || scanSessionId != scanSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || deviceIdentity.empty() || infPath.empty() ||
	   infPath.find( L'\0') != std::wstring_view::npos || expectedProvider.empty() ||
	   !packedVersion.has_value() || instance == deviceInstances_.end()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring externalInf( infPath) ;									// Windows APIへ渡すnull終端絶対path。
	const DWORD		   attributes = GetFileAttributesW( externalInf.c_str()) ;	// 通常file属性。
	// 外部INFの属性取得失敗は診断値を保持して中止する。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 外部INFが通常file以外の場合は導入対象にしない。
	if( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	DeviceInfoSet devices(
		// 対象一件用set。
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合を作成できなければ外部INFを適用しない。
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	SP_DEVINFO_DATA device{} ;	// Opaque identityから再openした対象device metadata。
	device.cbSize = sizeof( device) ;
	// 照合済みdeviceを開けない場合は他deviceへ適用先を広げない。
	if( driver_store_inf_detail::transport().open( devices.get(), instance->second.c_str(), nullptr,
												 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const NativeError configureError =	// 単一INF compatible listの条件設定結果。
		configureSingleInfDriverSearch( devices.get(), device, externalInf) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( configureError != 0) {
		return configureError ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// 外部INF compatible listのRAII guard。
	// 互換driver listの構築失敗を独自照合で補わない。
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	SP_DRVINFO_DATA_W selectedDriver{} ;	// 一意に再照合できた外部INF driver node。
	bool			  found{} ;				// trueの場合だけDiInstallDeviceを許可する。
	// 外部INFから構築された全nodeを確認し、曖昧な複数一致をfail-closedで拒否する。
	for( DWORD index = 0; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 現在再照合中の外部driver node。
		driver.cbSize = sizeof( driver) ;
		// 列挙終了時は正常終端かを確認して検索を終える。
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			// 正常終端以外の列挙失敗は呼出側へ返す。
			if( GetLastError() != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			break ;
		}

		DriverDetail detail ;	// Driver nodeが参照するINFとsection metadata。
		// INF詳細の取得失敗や不正metadataを導入前に拒否する。
		if( !readDriverDetail( devices.get(), device, driver, detail)) {
			const DWORD error = GetLastError() ;	// Detail API失敗または不正metadata診断値。
			return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
		}

		const bool matches =
			normalizedFileName( detail.infFileName) == normalizedFileName( externalInf) &&
			normalizeIdentifier( driver.ProviderName) == normalizeIdentifier( expectedProvider) &&
			// Scan時metadataとの完全一致結果。
			driver.DriverVersion == packedVersion.value() ;
		// 指定INF、provider、版に一致しないnodeを除外する。
		if( !matches) {
			continue ;
		}

		// 複数nodeが一致する曖昧な導入要求を拒否する。
		if( found) {
			return nativeErrorFromWin32( ERROR_DUP_NAME) ;
		}

		selectedDriver = driver ;
		found		   = true ;
	}

	// 指定条件に合う互換nodeがなければ導入しない。
	if( !found) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// Parentはcaller所有のHWNDをnative API境界でだけ元の型へ戻す。
	const HWND parentWindow = reinterpret_cast<HWND>( parentWindowNative) ;	// 非所有parent HWND。
	BOOL	   nativeRebootRequired = FALSE ;								// DiInstallDeviceが返す再起動要求flag。
	// 外部INFの指定node導入失敗を元の診断値で返す。
	if( driver_store_inf_detail::transport().install( parentWindow, devices.get(), &device,
													&selectedDriver, 0,
													&nativeRebootRequired) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	rebootRequired = nativeRebootRequired != FALSE ;
	rememberInstalledObservationTarget( instance->second, externalInf, selectedDriver.ProviderName,
									   selectedDriver.DriverVersion) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief scan で照合済みの Driver Store 候補を再列挙して導入する。
 * @param[in] target worker 内に保持した対象 metadata。
 * @param[in] parentWindowNative device installer UI の親 HWND。
 * @param[out] rebootRequired 完了に再起動が必要な場合は `true`。
 * @return 成功時は 0、失敗時は HRESULT bit pattern。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::installTarget( const InstallTarget &target,
											   const std::uintptr_t parentWindowNative,
											   bool				   &rebootRequired) const
{
	rebootRequired = false ;
	DeviceInfoSet devices(
		// 対象一件用set。
		driver_store_inf_detail::transport().create( nullptr, nullptr)) ;
	// device情報集合を取得できなければ保存候補の再照合を中止する。
	if( !devices.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	SP_DEVINFO_DATA device{} ;	// Instance IDで再openした対象device metadata。
	device.cbSize = sizeof( device) ;
	// scanで照合したdeviceを開けなければ指定版を導入しない。
	if( driver_store_inf_detail::transport().open( devices.get(), target.deviceInstanceId.c_str(),
												 nullptr, 0, &device) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 互換driver検索を構成できなければ検索範囲を広げず中止する。
	if( !configureCompatibleDriverSearch( devices.get(), device)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DriverInfoList driverList( devices.get(), device) ;	// 再構築compatible listのRAII guard。
	// Windowsの互換候補構築に失敗した場合は導入を中止する。
	if( driver_store_inf_detail::transport().build( devices.get(), &device, SPDIT_COMPATDRIVER) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	driverList.markBuilt() ;

	SP_DRVINFO_DATA_W selectedDriver{} ;	// 全metadataがscan時targetと一致したdriver node。
	bool			  found{} ;				// trueの場合だけselected_driverをDiInstallDeviceへ渡せる。
	// 再構築したcompatible listからscan時metadataと完全一致する一件だけを選択する。
	for( DWORD index = 0; index < MAXIMUM_DRIVERS_PER_DEVICE; ++index) {
		SP_DRVINFO_DATA_W driver{} ;	// 再照合中のcompatible driver node。
		driver.cbSize = sizeof( driver) ;
		// 列挙が終了または失敗した場合は候補探索を打ち切る。
		if( driver_store_inf_detail::transport().enumerate(
			   devices.get(), &device, SPDIT_COMPATDRIVER, index, &driver) == FALSE) {
			break ;
		}

		DriverDetail detail ;	// 再照合中nodeのINFとsection metadata。
		// 詳細を取得できないnodeを指定版として採用しない。
		if( !readDriverDetail( devices.get(), device, driver, detail)) {
			continue ;
		}

		// INF、section、provider、版、日付がscan記録と一致するnodeだけを採用する。
		if( normalizedFileName( detail.infFileName) == normalizedFileName( target.infFileName) &&
		   normalizeIdentifier( detail.sectionName) == normalizeIdentifier( target.sectionName) &&
		   normalizeIdentifier( driver.ProviderName) == normalizeIdentifier( target.providerName) &&
		   driver.DriverVersion == target.driverVersion &&
		   fileTimeTicks( driver.DriverDate) == target.driverDateTicks) {
			selectedDriver = driver ;
			found		   = true ;
			break ;
		}
	}

	// scan記録と一致するnodeが失われていれば導入しない。
	if( !found) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// parent は caller が整数化した HWND だけを受け取り、native API 境界で元の型へ戻す。
	// Installer UIに渡す呼出し元所有のparent Window handle。
	const HWND parentWindow			= reinterpret_cast<HWND>( parentWindowNative) ;
	BOOL	   nativeRebootRequired = FALSE ;	// DiInstallDeviceが返す再起動要求flag。
	// 保存候補の指定node導入失敗は診断値を保持して返す。
	if( driver_store_inf_detail::transport().install( parentWindow, devices.get(), &device,
													&selectedDriver, 0,
													&nativeRebootRequired) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	rebootRequired = nativeRebootRequired != FALSE ;
	rememberInstalledObservationTarget( target.deviceInstanceId, target.infFileName,
									   target.providerName, target.driverVersion) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 成功した指定対象だけを実事後照合用へ保持します。
 * @param[in] instance Worker内だけの元instanceです。
 * @param[in] inf 指定済みの実INFです。
 * @param[in] provider 指定nodeのproviderです。
 * @param[in] version 指定nodeのpacked版です。
 * @note 確保失敗は読取証明を省き、実導入結果を変更しません。
 */
//------------------------------------------------------------------------------
void DriverStoreProvider::rememberInstalledObservationTarget(
	const std::wstring_view instance, const std::wstring_view inf, const std::wstring_view provider,
	const std::uint64_t version) const noexcept
{
	// 再記録前に当該instanceの旧証明を無確保で消し、例外時は未確認にします。
	for( auto found = installedObservationTargets_.begin();
		found != installedObservationTargets_.end(); ++found) {
		// 同operationの旧対象を先に消して確保失敗時の流用を防ぎます。
		if( found->first == instance) {
			installedObservationTargets_.erase( found) ;
			break ;
		}
	}

	// 証明用copyの確保失敗を実API成功の失敗へ置き換えません。
	try {
		installedObservationTargets_.insert_or_assign( std::wstring( instance),
													  InstallTarget{std::wstring( instance),
																	std::wstring( inf),
																	{},
																	std::wstring( provider),
																	version,
																	0U}) ;
	} catch( ...) {
		// 欠測は後続で未確認として扱います。
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元scanの対象だけを同worker内で導入後にread-only照会する関数を作ります。
 * @param[in] session 元scan sessionです。導入権限を延長しません。
 * @param[in] devices 同scanの選択済みopaque device集合です。
 * @return 同workerのinstall呼出し内だけで一回使用する読取関数。生IDをUIへ渡しません。
 * @note 対象instanceとAPI表を一時所有し、期待mapはProviderから借用します。同owner thread・Provider生存中の同期呼出しだけが有効です。captured
 *       sessionと現在scanの不一致では期待mapを使いません。全PnP scan/再検出/候補発行は行いません。
 */
//------------------------------------------------------------------------------
std::function<std::vector<PostInstallDeviceObservation>()> DriverStoreProvider::
	capturePostInstallObservations( const ScanSessionId				   session,
								   const std::span<const std::wstring> devices) const
{
	// 前operationの表示証明を再使用しません。
	installedObservationTargets_.clear() ;
	// 通常scanの元deviceだけを有限に保持し、専用metadata fixtureをnativeへ補完しません。
	if( devices.empty() || devices.size() > MAXIMUM_OFFICIAL_INF_BINDINGS) {
		return {} ;
	}

	const bool valid = session != 0U && session == scanSessionId_ &&
					   ownerThreadId_ == GetCurrentThreadId() &&
					   !testInventoryTransport_ ;	// 同workerの元対応表です。
	std::vector<std::pair<std::wstring, std::wstring>>
		targets ;	// Opaqueとprivate instanceの一時対応です。
	targets.reserve( devices.size()) ;
	// 指定deviceだけをcopyし、未解決を別deviceや全列挙へ置き換えません。
	for( const auto &device : devices) {
		const auto found = deviceInstances_.find( device) ;	// 元scanで照合したprivate値です。
		targets.emplace_back( device,
							 valid && found != deviceInstances_.end() ? found->second : L"") ;
	}

	const auto calls =
		// 同worker fixtureまたは製品固定の完全表です。
		driver_store_inf_detail::transport() ;
	const DWORD owner = GetCurrentThreadId() ;	// 別threadへread処理を移しません。
	return [targets = std::move( targets), calls, owner, session, this] {
		std::vector<PostInstallDeviceObservation> observations ;	// 生IDを含まない返却値です。
		observations.reserve( targets.size()) ;
		// 最大元選択件数だけを一件ずつ再openし、compatible listやdriver候補を列挙しません。
		for( const auto &[deviceIdentity, instance] : targets) {
			PostInstallDeviceObservation observed ;	// 成功値を候補のmetadataで補完しません。
			observed.observation.scanSessionId	= session ;
			observed.observation.deviceIdentity = deviceIdentity ;
			// 解決失敗・thread違いはAPI前に拒否し、元bindingの寿命を延ばしません。
			if( instance.empty() || GetCurrentThreadId() != owner) {
				observed.error = static_cast<NativeError>( E_INVALIDARG) ;
				observations.push_back( std::move( observed)) ;
				continue ;
			}

			DeviceInfoSet	set{calls.create( nullptr, nullptr),
								calls.inventory} ;	// 対象一件用のread-only集合です。
			SP_DEVINFO_DATA device{} ;				// 再open先の現在metadataです。
			device.cbSize = sizeof( device) ;
			// 対象を開けなければ不在とAPI失敗を元診断で保持します。
			if( !set.valid() || !calls.open( set.get(), instance.c_str(), nullptr, 0U, &device)) {
				observed.error = nativeErrorFromWin32( GetLastError()) ;
				observations.push_back( std::move( observed)) ;
				continue ;
			}

			std::wstring actualInstance ;	// 値はこのcallbackの外へ渡しません。
			observed.observation.instanceIdentity =
				readObservedInstanceId( set.get(), device, actualInstance, calls.inventory) ;
			std::vector<std::byte> present ;	// 同対象の現在present属性だけです。
			const auto			   presentRead = readObservedProperty(
				set.get(), device, DEVPKEY_Device_IsPresent, DEVPROP_TYPE_BOOLEAN, present,
				calls.inventory) ;	// 既存の型/容量検証を使用します。
			// 元deviceと異なる返却・非present・確認不能は現在表示へ昇格しません。
			if( observed.observation.instanceIdentity.state != DevicePropertyReadState::VALUE ||
			   normalizeIdentifier( actualInstance) != normalizeIdentifier( instance) ||
			   presentRead.state != DevicePropertyReadState::VALUE ||
			   present.size() != sizeof( DEVPROP_BOOLEAN) ||
			   present.front() != static_cast<std::byte>( DEVPROP_TRUE)) {
				observed.error = nativeErrorFromWin32( presentRead.diagnostic.code != 0U
														  ? presentRead.diagnostic.code
														  : ERROR_NO_SUCH_DEVINST) ;
				observations.push_back( std::move( observed)) ;
				continue ;
			}

			auto &observation		 = observed.observation ;	// 同deviceの元読取状態です。
			observation.node		 = readObservedNode( device, calls.inventory) ;
			observation.friendlyName = readObservedDeviceString(
				set.get(), device, DEVPKEY_Device_FriendlyName, observed.name, calls.inventory) ;
			// FriendlyName欠損時だけ標準説明へfallbackし、元の欠損を保持します。
			if( observation.friendlyName.state != DevicePropertyReadState::VALUE) {
				observation.deviceDescription = readObservedDeviceString(
					set.get(), device, DEVPKEY_Device_DeviceDesc, observed.name, calls.inventory) ;
			}

			observation.manufacturer =
				readObservedDeviceString( set.get(), device, DEVPKEY_Device_Manufacturer,
										 observed.manufacturer, calls.inventory) ;
			observation.deviceClass = readObservedDeviceString(
				set.get(), device, DEVPKEY_Device_Class, observed.driverClass, calls.inventory) ;
			observed.deviceClassGuid = formatClassGuid( device.ClassGuid) ;
			std::wstring driverKey ;	// 生keyは現在値の登録有無だけへ分類して破棄します。
			observation.driverKey = readObservedDeviceString(
				set.get(), device, DEVPKEY_Device_Driver, driverKey, calls.inventory) ;
			const auto current =
				// 実propertyだけです。
				readCurrentDriver( set.get(), device, calls.inventory) ;
			observation.infName	 = current.infRead ;
			observation.provider = current.providerRead ;
			observation.version	 = current.versionRead ;
			observation.date	 = current.dateRead ;
			observation.driverPresence =
				classifyDeviceDriverPresence( observation.node, observation.driverKey) ;
			observed.provider	= current.provider ;
			observed.version	= current.version ;
			observed.driverDate = current.date ;
			const auto expected =
				session == scanSessionId_ && GetCurrentThreadId() == ownerThreadId_
					? installedObservationTargets_.find( instance)
					: installedObservationTargets_.end() ;	// 元scanの今回実指定したtargetだけです。
			bool sameInf = expected != installedObservationTargets_.end() &&
						   normalizedFileName( current.infFileName) ==
							   // 原名一致です。
							   normalizedFileName( expected->second.infFileName) ;
			// OEM別名でも、既登録rootと元INF全byteの一致を要求します。
			if( !sameInf && expected != installedObservationTargets_.end()) {
				RegisteredInfGuard			  registration ;	// 既保護root/元byteのscopeです。
				std::array<wchar_t, MAX_PATH> directory{} ;		// 同backendのWindows rootです。
				const auto					  length = calls.windowsDirectory( directory.data(),
																			  // production/fakeを混在させません。
																			  static_cast<UINT>( directory.size())) ;
				// 同backendのWindows rootと元INF検証が成立する場合だけ別名を照合します。
				if( length > 0 && length < directory.size() && directory[length] == L'\0' &&
				   registration.initialize( expected->second.infFileName) == 0) {
					const auto published = std::wstring( directory.data(), length) + L"\\INF\\" +
										   // 私有の登録先です。
										   normalizedFileName( current.infFileName) ;
					sameInf = registration.verify( published) == 0 ;
				}
			}

			observed.selectedTargetMatched =
				expected != installedObservationTargets_.end() &&
				current.infRead.state == DevicePropertyReadState::VALUE &&
				current.providerRead.state == DevicePropertyReadState::VALUE &&
				current.packedVersion && sameInf &&
				normalizeIdentifier( current.provider) ==
					normalizeIdentifier( expected->second.providerName) &&
				*current.packedVersion == expected->second.driverVersion ;

			observations.push_back( std::move( observed)) ;
		}

		return observations ;
	} ; // 元install呼出し内・Provider生存中にだけ使うread-only map借用です。install許可・leaseはcaptureしません。
}

//------------------------------------------------------------------------------
/**
 * @brief scan session と秘密性のある device metadata を失効させる。
 */
//------------------------------------------------------------------------------
void DriverStoreProvider::invalidateScanSession() noexcept
{
	installedObservationTargets_.clear() ;
	issuedIndexContext_ = {} ;
	activeIndexDevices_.clear() ;
	pendingIndexDevices_.clear() ;
	activeInstallDevices_.clear() ;
	activeInstallOperation_		  = 0U ;
	lastAcceptedInstallOperation_ = 0U ;
	installEntered_				  = false ;
	indexInventory_.reset() ;
	installProofInventory_.reset() ;
	installTargets_.clear() ;
	hardwareToDevice_.clear() ;
	deviceInstances_.clear() ;
	officialInfInstallBindings_.clear() ;
	officialInstallerBindings_.clear() ;
	stagedOfficialInfs_.clear() ;
	inventoryMeasurement_ = {} ;
	scanSessionId_		  = 0 ;
	ownerThreadId_		  = 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元scanのpresent deviceを公式installer専用の秘密guardへ固定します。
 * @param[in] session 元scan sessionです。
 * @param[in] device 元表示のopaque deviceです。
 * @param[in] provider 元現在行のproviderです。native再観測へ完全一致を要求します。
 * @param[in] version 元現在行の版です。
 * @param[in] date 元現在行の日付です。
 * @param[out] token 全原状態一致時だけ非zero guardです。失敗時0です。
 * @return 同worker/native x64/present/原現在状態確認0、拒否は元HRESULTです。
 * @note 標準INFのWindows rank合格を発行しません。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::createOfficialInstallerDeviceBinding(
	const ScanSessionId session, const std::wstring_view device, const std::wstring_view provider,
	const std::wstring_view version, const std::wstring_view date, std::uint64_t &token)
{
	token				= 0U ;
	const auto instance = deviceInstances_.find( std::wstring{device}) ;	// 同scan秘密instanceです。
	// 別thread/session/未知deviceや枠超過からguardを発行しません。
	if( session == 0U || session != scanSessionId_ || ownerThreadId_ != GetCurrentThreadId() ||
	   instance == deviceInstances_.end() || !ownsInstallDevice( device) ||
	   officialInstallerBindings_.size() >= MAXIMUM_OFFICIAL_INF_BINDINGS ||
	   nextOfficialBindingToken_ == 0U ||
	   nextOfficialBindingToken_ == std::numeric_limits<std::uint64_t>::max()) {
		return E_ACCESSDENIED ;
	}

	SYSTEM_INFO system{} ;	// 元低位backendの実architectureです。
	driver_store_inf_detail::transport().architecture( &system) ;
	// ARM64 emulation等をnative x64へ補完しません。
	if( system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	DeviceRankSnapshot current ;	// 実present/全current属性/全PnPを同時に確認します。
	const auto		   error =
		// rank成功は発行しません。
		readDeviceRankSnapshot( instance->second, current) ;
	// 元現在行と変わったnative状態からinstaller guardを発行しません。
	if( error != 0U || current.currentDriver.provider != provider ||
	   current.currentDriver.version != version || current.currentDriver.date != date) {
		return error != 0U ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	}

	OfficialInstallerDeviceBindingRecord record ;	// 同scanの秘密状態だけを保存します。
	record.session					= session ;
	record.identity					= device ;
	record.device					= {instance->second,
									   std::move( current.deviceClass),
									   std::move( current.hardwareIds),
									   std::move( current.compatibleIds),
									   std::move( current.matchingDeviceId),
									   std::move( current.currentDriver.infFileName),
									   std::move( current.currentDriver.provider),
									   std::move( current.currentDriver.version),
									   std::move( current.currentDriver.date),
									   current.currentDriver.packedVersion.value_or( 0U),
									   current.noDriver} ;
	record.device.classRead			= current.classRead ;
	record.device.classGuidRead		= current.classGuidRead ;
	record.device.observedClassGuid = std::move( current.observedClassGuid) ;
	record.device.nativeClassGuid	= std::move( current.nativeClassGuid) ;
	record.device.classState		= current.classState ;
	record.device.node				= current.node ;
	record.device.driverKeyRead		= current.driverKeyRead ;
	record.device.matchingRead		= current.matchingRead ;
	record.device.driverKey			= std::move( current.driverKey) ;
	const auto issued				= nextOfficialBindingToken_ ;	// 元issuerだけの単調tokenです。
	// 全値の保存後だけguardを発行し、既存tokenを上書きしません。
	if( !officialInstallerBindings_.emplace( issued, std::move( record)).second) {
		return HRESULT_FROM_WIN32( ERROR_ALREADY_EXISTS) ;
	}

	++nextOfficialBindingToken_ ;
	token = issued ;
	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元installer guardを変更直前のpresent/全秘密状態へ再照合します。
 * @param[in] session 元scanです。
 * @param[in] device 元opaque deviceです。
 * @param[in] token 未使用の同issuer guardです。
 * @return 全native状態一致0、それ以外は元HRESULTです。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::revalidateOfficialInstallerDeviceBinding(
	const ScanSessionId session, const std::wstring_view device, const std::uint64_t token) const
{
	const auto stored = officialInstallerBindings_.find( token) ;	// 同issuerの元guardです。
	// 別thread/元選択外/古session/使用済みguardの引継ぎを拒否します。
	if( session == 0U || session != scanSessionId_ || ownerThreadId_ != GetCurrentThreadId() ||
	   stored == officialInstallerBindings_.end() || stored->second.session != session ||
	   stored->second.identity != device || stored->second.consumed || !ownsInstallDevice( device)) {
		return E_ACCESSDENIED ;
	}

	DeviceRankSnapshot current ;							// 変更直前の全native状態です。
	const auto		  &original = stored->second.device ;	// UI/通常logへ渡さない元秘密状態です。
	const auto		   error =
		// 同低位backendだけです。
		readDeviceRankSnapshot( original.deviceInstanceId, current) ;
	// 完全なpresent/current/PnP/classの変化を無視して起動しません。
	if( error != 0U || current.deviceClass != original.deviceClass ||
	   current.classState != original.classState ||
	   current.classRead.state != original.classRead.state ||
	   current.classGuidRead.state != original.classGuidRead.state ||
	   current.observedClassGuid != original.observedClassGuid ||
	   current.nativeClassGuid != original.nativeClassGuid ||
	   current.node.statusFlags != original.node.statusFlags ||
	   current.node.problemCode != original.node.problemCode ||
	   current.driverKeyRead.state != original.driverKeyRead.state ||
	   current.matchingRead.state != original.matchingRead.state ||
	   current.driverKey != original.driverKey || current.hardwareIds != original.hardwareIds ||
	   current.compatibleIds != original.compatibleIds ||
	   current.matchingDeviceId != original.matchingDeviceId ||
	   current.currentDriver.infFileName != original.currentInfFileName ||
	   current.currentDriver.provider != original.currentProvider ||
	   current.currentDriver.version != original.currentVersion ||
	   current.currentDriver.date != original.currentDate ||
	   current.noDriver != original.noDriver ||
	   current.currentDriver.packedVersion.value_or( 0U) != original.currentPackedVersion) {
		return error != 0U ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 明示選択済みguardを一回だけ消費します。
 * @param[in] session 元scanです。
 * @param[in] device 元opaque deviceです。
 * @param[in] token 元未使用guardです。
 * @return 全再照合成功0、再使用/変化は元HRESULTです。
 */
//------------------------------------------------------------------------------
NativeError DriverStoreProvider::consumeOfficialInstallerDeviceBinding(
	const ScanSessionId session, const std::wstring_view device, const std::uint64_t token)
{
	const auto error =
		// 直前native確認です。
		revalidateOfficialInstallerDeviceBinding( session, device, token) ;
	// 失効したguardを消費済み成功へ変更しません。
	if( error == 0U) {
		officialInstallerBindings_.at( token).consumed = true ;
	}

	return error ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同issuerの未公開installer guardだけをrollbackします。
 * @param[in] session 元scanです。
 * @param[in] token 当該issuerの元guardです。
 * @return 元sessionのguardを除去した場合trueです。
 */
//------------------------------------------------------------------------------
bool DriverStoreProvider::discardOfficialInstallerDeviceBinding( const ScanSessionId session,
																const std::uint64_t token) noexcept
{
	const auto found = officialInstallerBindings_.find( token) ;	// このissuerだけの元guardです。
	// 古sessionや未知tokenの秘密状態へ触れません。
	if( found == officialInstallerBindings_.end() || found->second.session != session ||
	   ownerThreadId_ != GetCurrentThreadId()) {
		return false ;
	}

	officialInstallerBindings_.erase( found) ;
	return true ;
}

} // namespace drivercrate
