//------------------------------------------------------------------------------
/**
 * @file registered_driver_store_package_internal.h
 * @brief 現用INFに対応するDriver Store内の元パッケージを固定する
 * @version 01.16.00
 * @date 2026/11/19
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/19  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/22  登録済みストレージの選択節と元署名の読取り証拠を追加
 * Ver.01.02.00 Shunji Ogawa  2026/11/22  全現用登録からストレージ補助サービスの共有先を照合
 * Ver.01.03.00 Shunji Ogawa  2026/11/23  自動起動補助の署名付き元登録を読取り
 * Ver.01.04.00 Shunji Ogawa  2026/11/23  署名付き元登録から補助とイベントの現在観測を取得
 * Ver.01.05.00 Shunji Ogawa  2026/11/23  自動起動補助の署名付き元選択から電源定義を保持
 * Ver.01.06.00 Shunji Ogawa  2026/11/23  元宣言が書かないイベント資源を現在値と区別
 * Ver.01.07.00 Shunji Ogawa  2026/11/23  署名付き元選択の関連起動サービスの配置先と構成を保持
 * Ver.01.08.00 Shunji Ogawa  2026/11/23  登録済みイベント資源の元バイト数を保持
 * Ver.01.09.00 Shunji Ogawa  2026/11/23  現用同梱NVMeの選択、起動と電源の元証拠を読取る
 * Ver.01.10.00 Shunji Ogawa  2026/11/23  OEM登録の正逆対応と単一ブートの元署名を照合
 * Ver.01.11.00 Shunji Ogawa  2026/11/23  単一ブートの元署名を同じ現用機器の登録属性に結合
 * Ver.01.12.00 Shunji Ogawa  2026/11/23  同一サービスの署名付き局所設定を元登録に保持
 * Ver.01.13.00 Shunji Ogawa  2026/11/27  現用Displayの公開INFと補助EXEの署名証拠を保持
 * Ver.01.14.00 Shunji Ogawa  2026/11/27  現用親の必要子と署名付き子登録を照合
 * Ver.01.15.00 Shunji Ogawa  2026/11/27  複数INFの閉包から指定INFの登録内容を確認
 * Ver.01.16.00 Shunji Ogawa  2026/11/27  同じStore元INFの保持済みファイル位置を照合
 * </pre>
 * @note 証拠の読取りはworker内で同期実行し、導入許可や共有構成の所有は呼出し側で別に判断する
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/system_inf_effects_internal.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
struct OfficialInfPackage ;
struct OfficialZipEntry ;
struct DisplayInfUse ;
struct SelectedStorageServiceFacts ;
struct StorageAutoStartAuxiliarySnapshot ;
struct StorageAuxiliaryHostSnapshot ;
struct StorageEventSourceSnapshot ;
struct StorageSystemEventSnapshot ;

/** @brief 登録されたOEM INFから同じDriver Storeパッケージを照会する */
struct DriverStorePackageLookup {
	/// Windowsディレクトリを取得する
	decltype( &GetWindowsDirectoryW)			   windowsDirectory{} ;
	/// OEM INFに対応するDriver Store内の完全INF位置を取得する
	decltype( &SetupGetInfDriverStoreLocationW) storeLocation{} ;
	/// Driver Storeの元INFに対応するWindowsの公開INFを取得する
	decltype( &SetupGetInfPublishedNameW)	   publishedName{} ;
} ;

/** @brief 現用Displayの一つの登録パッケージと同じCATで確認した補助宣言 */
struct RegisteredDisplayAuxiliaryPackage {
	/// 同じ現用デバイスから観測した公開OEM INF名
	std::wstring							   publishedInf ;
	/// 実際にそのデバイスへ適用されているDDInstall節
	std::wstring							   installedSection ;
	/// 同じ選択のWindows関連サービス名
	std::wstring							   associatedService ;
	/// 公開名の正逆対応で確認したStore元INFの完全位置
	std::wstring							   storeInf ;
	/// 公開INFと元INFの両方で一致した保護付き観測のうち、公開側の元属性と全ハッシュ
	ProtectedExecutableSnapshot				   publishedFile ;
	/// Store元INFの独立した保護付き観測
	ProtectedExecutableSnapshot				   storeFile ;
	/// 元INFが選んだ同一パッケージのCATの保護付き観測
	ProtectedExecutableSnapshot				   catalogFile ;
	/// 選択された補助サービスの現用EXEの完全位置
	std::wstring							   executablePath ;
	/// 保持した補助EXE全体のSHA-256
	std::wstring							   executableSha256 ;
	/// 同じ保護元INFから読んだ補助サービスとイベントの全宣言
	OfficialDisplayAuxiliaryService			   declaration ;
	/// 同じ元親の実導入節が宣言するSWC IDと子名の集合
	std::vector<OfficialInfComponentReference> components ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現用Displayの登録INFと同じ署名配布にある補助EXEを確認する
 * @param[in] publishedInf 当該現用デバイスから読んだ公開OEM INF名
 * @param[in] basicSection 同じデバイスの元基本節名
 * @param[in] extension 同じデバイスの実装飾。Windowsで未指定のとき空
 * @param[in] associatedService 同じデバイスの関連サービス名
 * @param[in] intended 署名候補から確認した更新対象の同名補助とイベント源
 * @param[out] evidence 成功時の元登録・同一CAT・完全ハッシュ。失敗時は空
 * @return 公開名の正逆・元byte・実選択・CATメンバー照合の成立で0、それ以外はHRESULT
 * @note 通信や登録を行わない。現SCM・イベント源と他デバイスの所有は後段で確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredDisplayAuxiliaryPackage(
	std::wstring_view publishedInf, std::wstring_view basicSection, std::wstring_view extension,
	std::wstring_view associatedService, const OfficialDisplayAuxiliaryService &intended,
	RegisteredDisplayAuxiliaryPackage &evidence) ;

/** @brief 現用SoftwareComponentの主IDと実選択を確認した署名元 */
struct RegisteredSoftwareComponentPackage {
	/// 公開INFの正逆対応と同一ハッシュを確認したStore INF
	std::wstring				storeInf ;
	/// 現用デバイスがWindowsから得た実DDInstall節
	std::wstring				installedSection ;
	/// 正規公開INFの全ハッシュと保護
	ProtectedExecutableSnapshot publishedFile ;
	/// 同じStoreの署名済みINF実体の全ハッシュと保護
	ProtectedExecutableSnapshot storeFile ;
	/// 元INFに結び付いたCATの全ハッシュと保護
	ProtectedExecutableSnapshot catalogFile ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現用SWCの主ID・実DDInstall・署名配布をWindows登録から照合する
 * @param[in] publishedInf 当該present子の公開OEM INF名
 * @param[in] basicSection 当該present子のDriverInfSection。記録によっては装飾込み
 * @param[in] extension 当該現用の装飾。未指定は空
 * @param[in] hardwareId 現用子から観測した唯一の主Hardware ID
 * @param[out] evidence 全照合に成功した元署名・実節。失敗時は空
 * @return 公開名の正逆、同じバイト、現在Modelsと署名の照合成功で0、その他HRESULT
 * @note 読取専用。候補との共用判定、ソフトウェア実行、導入は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredSoftwareComponentPackage(
	std::wstring_view publishedInf, std::wstring_view basicSection, std::wstring_view extension,
	std::wstring_view hardwareId, RegisteredSoftwareComponentPackage &evidence) ;

//------------------------------------------------------------------------------
/**
 * @brief 同じWindowsの保護された公開INFを読み、対象Displayの作用との重複を調べる
 * @param[in] leaf 今のWindowsから得た公開INFまたはInclude INFの単独名
 * @param[in] installedSection 現用機器の実DDInstall。空なら依存側と拡張の全節を保守的に調べる
 * @param[in] target 同じ選択のサービス名とApplicationイベント源
 * @param[out] result 読取り成功時の作用と外部依存。失敗時は空
 * @param[out] file 同じ読取り中に固定した公開INFの保護・同一性。失敗時は空
 * @return 元領域と全作用の読取り成功で0、その他HRESULT
 * @note 通常のWindows INFだけを読む。未知のパスや他のファイルを読み直さず、導入しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readPublishedDisplayInfUse( std::wstring_view leaf,
													 std::wstring_view installedSection,
													 const OfficialDisplayAuxiliaryService &target,
													 DisplayInfUse						   &result,
													 ProtectedExecutableSnapshot		   &file) ;

//------------------------------------------------------------------------------
/**
 * @brief Windows公開領域にある標準形式の拡張INFの母集合を列挙する
 * @param[out] leaves 大小無視で一意な拡張INF単独名の昇順集合。失敗時は空
 * @return 全件のクラスを確認して0。不明または容量・列挙失敗はHRESULT
 * @note 適用関係不明時の保守的な読取対象であり、各拡張が現在導入済みとは判定しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError listPublishedExtensionInfs( std::vector<std::wstring> &leaves) ;

/** @brief 登録済みの選択節が明示した一つのSystemイベント登録 */
struct RegisteredStorageEventReference {
	/// 元AddServiceに結び付くSystemイベントソース名
	std::wstring							   name ;
	/// 元AddServiceのイベント登録節名
	std::wstring							   installSection ;
	/// Windowsで読み取った展開前の元EventMessageFile。元省略の場合は空
	std::wstring							   messageFile ;
	/// 元のTypesSupportedのDWORD値
	std::uint32_t							   typesSupported{} ;
	/// 明示イベントが宣言したカテゴリ数。関連イベントのように元未指定の場合は空
	std::optional<std::uint32_t>			   categoryCount ;
	/// 元CATと照合した旧イベントDLLの名前。該当しない場合は空
	std::wstring							   resourceLeaf ;
	/// 元CATと照合したイベントDLL全体のSHA-256。該当しない場合は空
	std::wstring							   resourceSha256 ;
	/// 同じイベントDLLの完全バイト数。資源の省略では0
	std::uint64_t							   resourceBytes{} ;
	/// 元イベントと同じSystem32で観測した実DLL。不在や署名元だけを読む場合は空
	std::optional<ProtectedExecutableSnapshot> deployedResource ;
	/**
	 * @brief 登録済みの同じイベント参照を再読取結果へ照合する
	 * @param[in] other 独立に読んだ同じイベント参照
	 * @return 全値一致時true
	 */
	bool operator==( const RegisteredStorageEventReference &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 署名付きのSystemイベント宣言を現在の元型と値に照合する
 * @param[in] declared 同じ元選択の署名付きイベント宣言
 * @param[in] current 確認済みの現在イベント
 * @param[in] writesOnly 元が資源を省略した場合に現在資源の有無を問わないときtrue
 * @return 現在の名前と照合対象の定義が全て一致した場合true
 * @note 省略された現在資源の所有は証明しない。別の元署名と現物で確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesRegisteredStorageEvent( const RegisteredStorageEventReference &declared,
												 const StorageEventSourceSnapshot	   &current,
												 bool writesOnly = false) noexcept ;

/** @brief 登録済みの元選択とCATが項目ごとに裏付ける補助サービス宣言 */
struct RegisteredStorageHelperEvidence {
	/// 元AddServiceの正確な補助サービス名
	std::wstring				name ;
	/// 元AddServiceが指定したサービス構成節
	std::wstring				installSection ;
	/// 元ServiceBinaryを解決したSystem32または同じDriver StoreパッケージのEXE位置
	std::wstring				binary ;
	/// 元ServiceTypeの完全値
	std::uint32_t				type{} ;
	/// 元StartTypeの完全値
	std::uint32_t				start{} ;
	/// 元ErrorControlの完全値
	std::uint32_t				errorControl{} ;
	/// 元DisplayNameの展開済み文字列。元指定が無ければ空
	std::wstring				display ;
	/// 元Descriptionの展開済み文字列。元指定が無ければ空
	std::wstring				description ;
	/// 元SecurityのSDDL。現在のSCM記述子は別に確認する
	std::wstring				security ;
	/// 同CATに属するDriver Storeの元EXE位置
	std::wstring				storePath ;
	/// 元EXEの完全SHA-256
	std::wstring				sourceSha256 ;
	/// 同CATの同全byteと現在のfile snapshotに一致した場合だけ保持するSHA-256
	std::optional<std::wstring> deployedSha256 ;
	/**
	 * @brief 補助サービスの同じ元宣言と実ファイル結合の再観測を照合する
	 * @param[in] other 同じ元選択の独立した再読取り
	 * @return 元宣言、元byte、現在fileの有無とhashが全て一致すればtrue
	 */
	bool operator==( const RegisteredStorageHelperEvidence &other) const = default ;
} ;

/** @brief 登録済みの元選択とCATに結合した関連起動サービスの構成 */
struct RegisteredStorageBootServiceEvidence {
	/// 元ServiceBinaryを展開し、DIRID 12のコピーと照合した完全な配置先
	std::wstring  binary ;
	/// 元LoadOrderGroupの展開済み文字列
	std::wstring  group ;
	/// 元ServiceTypeの完全値
	std::uint32_t type{} ;
	/// 元StartTypeの完全値
	std::uint32_t start{} ;
	/// 元ErrorControlの完全値
	std::uint32_t errorControl{} ;
	/**
	 * @brief 同じ元選択に属する起動サービスの構成を再観測と照合する
	 * @param[in] other 同じ元選択の独立した再読取り
	 * @return 元宣言と配置先が全て一致すればtrue
	 */
	bool		  operator==( const RegisteredStorageBootServiceEvidence &other) const = default ;
} ;

/** @brief 署名付き単一ブート選択が関連サービスのキーへ設定するDWORD値 */
struct RegisteredStorageServiceValue {
	/// 関連サービスのキーからの相対サブキー
	std::wstring  subkey ;
	/// 元AddRegの値名
	std::wstring  name ;
	/// 元AddRegのDWORD値
	std::uint32_t value{} ;
	/**
	 * @brief 同じ元候補のサービス設定を再読取りと比較する
	 * @param[in] other 同じ署名元の独立した読取り
	 * @return 相対位置、名前、DWORD値が一致する場合true
	 */
	bool		  operator==( const RegisteredStorageServiceValue &other) const = default ;
} ;

/** @brief Windowsが現在関連付けるOEM INFと署名済みStore選択の再確認用内部証拠 */
struct RegisteredStoragePackageEvidence {
	/// 現在の選択デバイスから渡された公開OEM INF名
	std::wstring												   publishedInf ;
	/// Windowsが記録した元基本節名
	std::wstring												   installedBasicSection ;
	/// Windowsが記録した元拡張。明示的に空または不存在なら空
	std::wstring												   installedSectionExtension ;
	/// 元基本節と拡張から確認した実選択節
	std::wstring												   installedSection ;
	/// SetupAPIが解決したFileRepository内の元INF位置
	std::wstring												   storeInf ;
	/// OEM INFとStoreの元INFに共通する完全SHA-256
	std::wstring												   infSha256 ;
	/// 元INFが指定した同じStoreディレクトリのCAT位置
	std::wstring												   storeCatalog ;
	/// 現在のWindowsの信頼を確認した元CATの完全SHA-256
	std::wstring												   catalogSha256 ;
	/// 元選択が関連サービスに結び付ける同CAT内のSYS位置
	std::wstring												   storeDriverBinary ;
	/// 同CATと読取りで確認した元SYSの完全SHA-256
	std::wstring												   driverSha256 ;
	/// 現在の関連サービスとして確認した元名。自動起動補助を読む場合だけ保持する
	std::wstring												   installedService ;
	/// 自動起動補助の元選択に結合した署名付き起動サービスの構成。従来経路では空
	std::optional<RegisteredStorageBootServiceEvidence>			   bootService ;
	/// 元選択が補助サービスを宣言していない場合は空
	std::optional<RegisteredStorageHelperEvidence>				   helper ;
	/// 関連サービス、補助サービスの順の元イベント証拠。未観測や明示宣言なしの場合は空
	std::array<std::optional<RegisteredStorageEventReference>, 2U> eventReferences ;
	/// 自動起動補助の元選択が明示した電源定義を元参照順に保持する。同経路で宣言がなければ空
	std::vector<RangedStoragePowerSetting>						   powerSettings ;
	/// 単一ブートの元OEM選択が関連サービスに宣言した局所DWORD
	std::vector<RegisteredStorageServiceValue>					   bootRegistryValues ;
	/**
	 * @brief 同一デバイスの同一登録と署名済み選択の再観測を照合する
	 * @param[in] other 別の時点で読んだ同一登録の証拠
	 * @return 元選択、全署名ファイルと該当する起動サービス、補助、イベント、電源定義が一致すればtrue
	 */
	bool operator==( const RegisteredStoragePackageEvidence &other) const = default ;
} ;

/** @brief 同じ元選択から確認した単一起動サービスと保護付き実体の現在証拠 */
struct RegisteredSingleBootStorageEvidence {
	/// 署名済みの元INF、選択節、元起動サービス、元SYSと電源宣言。イベントの現在値は別に観測する
	RegisteredStoragePackageEvidence	  package ;
	/// 同じ元サービスに結び付いたSCMの構成と保護
	SystemServiceEvidence				  service ;
	/// 保持中のStoreの元SYSと親を独立に確認した保護と全ハッシュ
	ProtectedExecutableSnapshot			  source ;
	/// 元CATと元SYSに結び付いた現在の正規配置と保護
	ProtectedExecutableSnapshot			  deployed ;
	/// 機器節の別の署名済み依存文書。明示参照がなければ空
	std::optional<WindowsSystemFileTrust> hardwareDependency ;
	/**
	 * @brief 同じ署名元と現在の配置を独立した再確認と比較する
	 * @param[in] other 同じ選択から再度取得した元証拠と現在値
	 * @return 元選択、全署名、サービスと保護付き実体が一致すればtrue
	 */
	bool operator==( const RegisteredSingleBootStorageEvidence &other) const = default ;
} ;

/** @brief 同一の現在機器から前後で照合した登録属性と署名元 */
struct RegisteredSingleBootDeviceEvidence {
	/// 正式に未導入の場合だけ空。実登録では選択節、元署名と現在の起動構成を保持
	std::optional<RegisteredSingleBootStorageEvidence> registered ;
	/// Windowsに記録された実節装飾。属性の不在と明示空を区別
	std::optional<std::wstring>						   sectionExtension ;
	/**
	 * @brief 同じ現在機器に対する独立した再観測と比較する
	 * @param[in] other 同じ機器を前後で照合した現在値
	 * @return 未導入状態または署名付き実登録と実節装飾が一致した場合true
	 */
	bool operator==( const RegisteredSingleBootDeviceEvidence &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 実在する同じ機器の現在登録を同梱またはOEMの保護付き署名元へ照合する
 * @param[in] instanceId 以前のOS観測で選択した一機器のインスタンス。外部へ送信しない
 * @param[in] noDriver 先の観測が未導入を確認していた場合true
 * @param[in] expectedInf 先に確認した現在の公開INF。機器の独立読取りでは空も許可
 * @param[out] result 前後一致した元署名と装飾。正式な未導入または失敗時は空
 * @return 元署名または明示未導入の照合で0、現在不明、途中変更、未対応元はHRESULT
 * @note 観測はworker上で同期的に行う。共有所有、候補適用性、導入の判断は別に行う
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCurrentSingleBootStorageDeviceEvidence(
	const std::wstring &instanceId, bool noDriver, std::wstring_view expectedInf,
	RegisteredSingleBootDeviceEvidence &result) ;

//------------------------------------------------------------------------------
/**
 * @brief 現用同梱NVMeの実節を元CAT、現在の起動サービス、配置SYSと電源宣言へ照合する
 * @param[in] publishedInf 同じ機器に現在登録されている公開INFの葉名
 * @param[in] selectedSection 基本節と装飾を合わせたWindowsの実選択
 * @param[in] installedService 同じ機器から独立して読んだ現在の関連サービス
 * @param[out] evidence 同じ文書と現在構成がすべて成立した場合だけ保持する証拠。失敗時は空
 * @return 元署名と役割の照合で0、未知の選択や不成立はHRESULT
 * @note 機器属性と選択の再読取り、全共有先、現在のローカル値や導入資格は呼出し側で確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredInboxSingleBootStorageEvidence(
	std::wstring_view publishedInf, std::wstring_view selectedSection,
	std::wstring_view installedService, RegisteredSingleBootStorageEvidence &evidence) ;

//------------------------------------------------------------------------------
/**
 * @brief 正逆のOEM登録対応を選択節、元CAT、元SYSと元電源宣言へ結び付ける
 * @param[in] publishedInf Windowsが記録した公開OEM INF葉名
 * @param[in] basicSection 同じ機器の元基本節
 * @param[in] extension 同じ機器の節装飾。不在の場合は空
 * @param[in] installedService 同じ機器が使用する関連サービス名
 * @param[out] evidence 成功時は元署名、元SYSと元作用。現在SCMと配置先は未観測。失敗時は空
 * @param[in] lookup 同じWindowsのルートと正逆の登録対応を読む同期API
 * @return 元署名の照合で0、登録、取得、元作用の不成立はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredOemSingleBootStorageOrigin(
	std::wstring_view publishedInf, std::wstring_view basicSection, std::wstring_view extension,
	std::wstring_view installedService, RegisteredSingleBootStorageEvidence &evidence,
	const DriverStorePackageLookup &lookup) ;

//------------------------------------------------------------------------------
/**
 * @brief OEMの登録原本を実Windowsの現在のブートサービスと配置済みSYSまで照合する
 * @param[in] publishedInf 同じ機器の公開OEM INF葉名
 * @param[in] basicSection Windowsが記録した元基本節
 * @param[in] extension Windowsが記録した節装飾。不在の場合は空
 * @param[in] installedService 同じ機器が使用する関連サービス名
 * @param[out] evidence 現在のSCM、元SYS、配置と元署名が成立した証拠。失敗時は空
 * @return すべて成立時0、OEM形式ではない公開名はERROR_NOT_SUPPORTEDのHRESULT、それ以外は読取り診断
 * @note 同じ機器の属性は呼出側で再読取りし、共有構成の変更を許可しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredOemSingleBootStorageEvidence(
	std::wstring_view publishedInf, std::wstring_view basicSection, std::wstring_view extension,
	std::wstring_view installedService, RegisteredSingleBootStorageEvidence &evidence) ;

//------------------------------------------------------------------------------
/**
 * @brief SCMの元バイナリが同じWindows内の署名済みSYS配置先を指すか照合する
 * @param[in] command SCMが返した完全値
 * @param[in] target 保護付き読取りで同じWindowsのdrivers直下と確認した正規絶対位置
 * @return 絶対位置又は同じWindowsに解決する既知表記に完全一致すればtrue
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		  matchesStorageBootImage( std::wstring_view command,
												  std::wstring_view target) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 選択デバイスが現在使うOEM INFと署名済みStoreの元作用を読取照合する
 * @param[in] publishedInf 同じ選択デバイスのWindows INF直下のOEM INF名
 * @param[in] installedBasicSection 同じ選択デバイスにWindowsが記録する元基本節名
 * @param[in] installedSectionExtension 同じ選択デバイスにWindowsが記録する拡張。元不在の場合は空
 * @param[in] intended 同じ選択デバイスへの検査済み更新候補。対象の二サービス名と正確な配置先を結ぶ
 * @param[in] host 更新候補が触れる現在ファイルとイベントの読取りsnapshot。所有の判断は全登録の収集後
 * @param[out] evidence 元登録、選択、署名とファイル結合が成立した場合だけ保持する比較用証拠
 * @param[in] lookup 同じWindowsの正規ルートと登録位置を照会する内部API表
 * @return 読取りと照合が成立すれば0、元読取り失敗や不明構成はHRESULT
 * @note キャッシュ内の証明書情報を使い、サービス、登録済みファイル、レジストリを変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredStoragePackageEvidence(
	std::wstring_view publishedInf, std::wstring_view installedBasicSection,
	std::wstring_view installedSectionExtension, const SelectedStorageServiceFacts &intended,
	const StorageAuxiliaryHostSnapshot &host, RegisteredStoragePackageEvidence &evidence,
	const DriverStorePackageLookup &lookup = {&GetWindowsDirectoryW,
											  &SetupGetInfDriverStoreLocationW}) ;

//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助が属する登録済みストレージの選択・元署名・現在ファイルを照合する
 * @param[in] publishedInf 現用デバイスのWindows INF直下にある公開OEM INF名
 * @param[in] installedBasicSection 同デバイスの実基本節
 * @param[in] installedSectionExtension 同デバイスに記録された実拡張。不存在では空
 * @param[in] installedService 同デバイスにWindowsが記録した現在関連サービス名
 * @param[in] intended 六欄の自動起動補助を宣言する署名済み更新候補
 * @param[in] host 同じ補助の現在SCM・Driver Store観測。正式不在では空
 * @param[in] events 現用関連サービスと明示Systemイベントの保護付き現在観測
 * @param[out] evidence 元INFとCATに結合した起動サービス、補助、イベント、電源定義の証拠。失敗時は空
 * @param[in] lookup 同じWindowsのルートと登録先を照会する内部API表
 * @return 確認した一つの元登録を読取照合できた場合0、失敗はHRESULT
 * @note 同名の現在補助が実在すれば元EXEの位置、全byte、保護を再確認する
 * @note 元CATの確認後に同じ実選択の電源定義を読み取る
 * @note キャッシュ内の信頼情報を使う。登録、起動、設定変更や共有所有の承認を行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredAutomaticStoragePackageEvidence(
	std::wstring_view publishedInf, std::wstring_view installedBasicSection,
	std::wstring_view installedSectionExtension, std::wstring_view installedService,
	const SelectedStorageServiceFacts &intended, const StorageAutoStartAuxiliarySnapshot &host,
	const StorageSystemEventSnapshot &events, RegisteredStoragePackageEvidence &evidence,
	const DriverStorePackageLookup &lookup = {&GetWindowsDirectoryW,
											  &SetupGetInfDriverStoreLocationW}) ;

//------------------------------------------------------------------------------
/**
 * @brief 現用機器の署名付き登録から現在の自動起動補助とイベントを読み取る
 * @param[in] publishedInf 現用機器のWindows INF直下にある公開OEM INF名
 * @param[in] installedBasicSection 同じ機器の実基本節
 * @param[in] installedSectionExtension Windowsが記録した実拡張。不在では空
 * @param[in] installedService 同じ機器に実登録された現在関連サービス名
 * @param[in] intended 検査済みの自動起動補助付き更新候補
 * @param[out] package 元INF・CAT・起動サービス・電源定義と現在ファイルの照合証拠。失敗時は空
 * @param[out] events 元宣言が示した二つの現在イベント観測。失敗時は空
 * @param[out] auxiliary 元宣言が示した補助の保護付き観測。失敗時は空
 * @param[in] lookup Windowsルートと現在登録位置を照会する同期API表
 * @return 一つの登録と観測が成立すれば0、読取り・変更・照合不成立はHRESULT
 * @note 署名を照合してから同一登録の元名を照会する。導入や設定変更は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCurrentRegisteredAutomaticStoragePackageEvidence(
	std::wstring_view publishedInf, std::wstring_view installedBasicSection,
	std::wstring_view installedSectionExtension, std::wstring_view installedService,
	const SelectedStorageServiceFacts &intended, RegisteredStoragePackageEvidence &package,
	StorageSystemEventSnapshot &events, StorageAutoStartAuxiliarySnapshot &auxiliary,
	const DriverStorePackageLookup &lookup = {&GetWindowsDirectoryW,
											  &SetupGetInfDriverStoreLocationW}) ;

//------------------------------------------------------------------------------
/**
 * @brief 同じサービスを使う全現用機器の署名付き元登録と現在の共有構成を照合する
 * @param[in] host 予定した補助サービスとコピー先、二つのSystemイベントの安定した現在観測
 * @param[in] owners 各現用機器から取得した署名・実選択の証拠を全件同期借用する
 * @return 確認済みの新規配置先または共有所有で0、欠落・競合・読取り失敗はHRESULT
 * @note 異なる元ハッシュを持つ登録でも、既存ファイルを所有する登録と他の宣言の整合を要求する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyRegisteredStorageAuxiliaryOwnership(
	const StorageAuxiliaryHostSnapshot						&host,
	std::span<const RegisteredStoragePackageEvidence *const> owners) ;

/** @brief 配置済みのINF、CAT、全必要ファイルを操作中の読取りに固定する */
class RegisteredDriverStorePackage final {
public:
	/**
	 * @brief 未確認で空の保持状態を作る
	 */
	RegisteredDriverStorePackage() noexcept ;
	/**
	 * @brief 読取りに使ったファイルとディレクトリを解放する
	 */
	~RegisteredDriverStorePackage() noexcept ;

	/**
	 * @brief Windowsが返した登録先で元閉包の各ファイルを確認して保持する
	 * @param[in] registeredInf 呼出し側が元INFと照合済みのWindows INF直下のOEM INF
	 * @param[in] original 署名確認済みの選択元INFとCAT、必要ファイルの元位置
	 * @param[in] entries 同じ閉包の展開済みファイルの長さとSHA-256
	 * @param[in] lookup 登録先を照会する完全なAPI表
	 * @return すべての原ファイルと配置先が同じ場合0、未知や不一致はHRESULT
	 * @note 閉包の署名確認と導入権限は呼出し側が確認する
	 */
	[[nodiscard]] NativeError pin( const std::wstring			   &registeredInf,
								  const OfficialInfPackage		   &original,
								  std::span<const OfficialZipEntry> entries,
								  const DriverStorePackageLookup   &lookup) ;
	/**
	 * @brief 複数INFの閉包から同じ登録パッケージが所有する元ファイルを選んで保持する
	 * @param[in] registeredInf 登録結果で確認したWindows INF直下のOEM INF
	 * @param[in] original 同じ署名パッケージが指定したINF、CAT、全必須ファイル
	 * @param[in] entries 選択元を含む全署名確認済み閉包の元ファイルと長さ、SHA-256
	 * @param[in] lookup 同じWindowsの登録先を照会するAPI表
	 * @return 指定INFの全ファイルと正規位置が一致した場合0、その他はHRESULT
	 * @note 別INFが所有するファイルの検査は各選択の呼出し側で行う
	 */
	[[nodiscard]] NativeError pinFromClosure( const std::wstring				  &registeredInf,
											 const OfficialInfPackage		  &original,
											 std::span<const OfficialZipEntry> entries,
											 const DriverStorePackageLookup	  &lookup) ;

	/**
	 * @brief OEM INFの照会先と保持した実ファイルを導入直前に再確認する
	 * @return 保持した同一ファイルと登録先が成立する場合0、未保持・不一致・失敗はHRESULT
	 */
	[[nodiscard]] NativeError verify() const ;

	/**
	 * @brief 確認済みの同じStore元INFが指定された全ファイルを保持しているか照合する
	 * @param[in] storeInf 独立に読んだ現在のStore元INF完全位置
	 * @param[in] paths 元INFのパッケージ内にある必要ファイルの完全位置
	 * @return 同一の元INFと空でない全ファイルが保持済みの場合true
	 * @note 位置の前後確認と呼出側の端末適用性判定は別途必要
	 */
	[[nodiscard]] bool		  containsPinnedMembers( std::wstring_view			  storeInf,
													std::span<const std::wstring> paths) const noexcept ;

private:
	struct State ;
	/// 全ファイルが成立した場合だけ所有する
	std::unique_ptr<State> state_ ;
} ;
} // namespace drivercrate
