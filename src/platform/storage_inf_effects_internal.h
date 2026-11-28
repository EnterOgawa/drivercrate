//------------------------------------------------------------------------------
/**
 * @file storage_inf_effects_internal.h
 * @brief PACKAGE由来の選択storage作用と現service観測を有限に検査します
 * @version 01.40.00
 * @date 2026/11/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/15  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/16  MTD元HW propertyの非権限型を保持
 * Ver.01.02.00 Shunji Ogawa  2026/11/17  MTD handlerと現在HW propertyを私有資格へ保持
 * Ver.01.03.00 Shunji Ogawa  2026/11/21  メディアチェンジャーの起動順を再照合用に保持
 * Ver.01.04.00 Shunji Ogawa  2026/11/21  HDCのAutoLoggerと順位の静的検査結果を保持
 * Ver.01.05.00 Shunji Ogawa  2026/11/21  HDCのAutoLoggerの現在値と保護状態を読み取る
 * Ver.01.06.00 Shunji Ogawa  2026/11/21  現在のHDC起動サービスのSYSを再照合に保持
 * Ver.01.07.00 Shunji Ogawa  2026/11/21  IDEブートグループの位置を再照合に保持
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  選択SCSI基本節の順位を再照合に保持
 * Ver.01.09.00 Shunji Ogawa  2026/11/22  補助サービスとコピー先・イベント登録の現在値を保持
 * Ver.01.10.00 Shunji Ogawa  2026/11/22  補助サービスの現在構成と登録済み元宣言の照合を追加
 * Ver.01.11.00 Shunji Ogawa  2026/11/23  選択機器節のトリアージAutoLoggerの読取契約を追加
 * Ver.01.12.00 Shunji Ogawa  2026/11/23  自動起動ストレージの共有ACPI・DMAと元イベントを作用に保持
 * Ver.01.13.00 Shunji Ogawa  2026/11/23  共有ACPIとAutoLoggerの現在値・保護を読取りで保持
 * Ver.01.14.00 Shunji Ogawa  2026/11/23  Systemの明示イベント源と現在のカテゴリ値を保持
 * Ver.01.15.00 Shunji Ogawa  2026/11/23  自動起動補助の現在SCM構成とDriver Store内のEXEを保持
 * Ver.01.16.00 Shunji Ogawa  2026/11/23  現用登録の関連イベントと補助サービスを観測
 * Ver.01.17.00 Shunji Ogawa  2026/11/23  自動起動補助の現用登録と共有設定を一緒に再観測
 * Ver.01.18.00 Shunji Ogawa  2026/11/23  現用と候補の関連サービスを使う全機器の元登録を保持
 * Ver.01.19.00 Shunji Ogawa  2026/11/23  元選択に対応するWindowsの現用電源設定を保持
 * Ver.01.20.00 Shunji Ogawa  2026/11/23  現用登録と候補の電源設定の関係を分類
 * Ver.01.21.00 Shunji Ogawa  2026/11/23  自動起動補助とSystemイベントの共有先を分類
 * Ver.01.22.00 Shunji Ogawa  2026/11/23  起動サービスとSYS配置先を現用登録へ照合
 * Ver.01.23.00 Shunji Ogawa  2026/11/23  元AutoLogger名のETW稼働観測を保持
 * Ver.01.24.00 Shunji Ogawa  2026/11/23  自動起動型が指定した共有作用の適用後照合を追加
 * Ver.01.25.00 Shunji Ogawa  2026/11/23  Windows再起動要求と署名付き旧起動SYSを照合
 * Ver.01.26.00 Shunji Ogawa  2026/11/23  名前付きイベント用DLLの現在配置と所有判定を保持
 * Ver.01.27.00 Shunji Ogawa  2026/11/23  単一ブートサービスの電源と局所作用の元検査を追加
 * Ver.01.28.00 Shunji Ogawa  2026/11/23  電源設定GUIDの全登録場所の観測を追加
 * Ver.01.29.00 Shunji Ogawa  2026/11/23  単一起動サービスの現在Systemイベントを観測
 * Ver.01.30.00 Shunji Ogawa  2026/11/23  選択機器キーと関連サービスの局所値を保持
 * Ver.01.31.00 Shunji Ogawa  2026/11/23  一つの選択に現在登録と局所観測を結合
 * Ver.01.32.00 Shunji Ogawa  2026/11/23  電源設定の元宣言と他機器の未確認を保持
 * Ver.01.33.00 Shunji Ogawa  2026/11/23  単一ブートの電源設定の変更種別を保持
 * Ver.01.34.00 Shunji Ogawa  2026/11/23  単一起動サービスと局所設定の変更種別を保持
 * Ver.01.35.00 Shunji Ogawa  2026/11/23  単一起動の元観測と変更種別を同じ選択の資格へ保持
 * Ver.01.36.00 Shunji Ogawa  2026/11/23  単一起動の適用後の元署名と実作用を照合
 * Ver.01.37.00 Shunji Ogawa  2026/11/27  DisplayのApplicationイベント源と保護の証拠を追加
 * Ver.01.38.00 Shunji Ogawa  2026/11/27  Display補助の現用SCM構成と署名実体を照合
 * Ver.01.39.00 Shunji Ogawa  2026/11/27  Display登録処理が読むSoftwareComponentクラスを観測
 * Ver.01.40.00 Shunji Ogawa  2026/11/27  選択DisplayのOpenCL登録値と共有の旧マーカーを観測
 * </pre>
 *
 * @note ここで返す値は非権限です。ADMIN原byteと一意native nodeを持つprivate factoryだけが資格化します
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_types.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/mtd_handler_internal.h"
#include "platform/registered_driver_store_package_internal.h"
#include "platform/system_inf_effects_internal.h"
#include <SetupAPI.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
/** @brief 正確な一serviceの明示不存在又は安定config/SDです */
struct StorageServiceSnapshot {
	/// 原selected又はDependenciesの正確なservice名です
	std::wstring						 name ;
	/// 明示ERROR_SERVICE_DOES_NOT_EXISTだけが空の根拠です
	std::optional<SystemServiceEvidence> evidence ;
	/**
	 * @brief 同原値の全fieldをfresh再構築値へ比較します
	 * @param[in] other 同用途の独立した比較元です。同期中だけ借用します
	 * @return 省略状態/全値/順序が一致する場合trueです
	 */
	bool operator==( const StorageServiceSnapshot &other) const = default ;
} ;

/** @brief 現在のWindowsにおけるストレージ起動グループの元順序 */
struct StorageLoadOrder {
	/// Windowsが宣言したSCSI Miniportの位置
	std::size_t				   miniport{} ;
	/// Windowsが宣言したSCSI Classの位置
	std::size_t				   deviceClass{} ;
	/// IDEブートドライバーの使用時だけ保持するSystem Bus Extenderの位置
	std::optional<std::size_t> systemBusExtender ;
	/// System Bus Extenderより前にある元グループ名と各終端
	std::wstring			   precedingGroups ;
	/**
	 * @brief 同じ端末で再確認した起動グループの位置を元の観測と照合する
	 * @param[in] other 後続の読み取り結果
	 * @return 観測対象と全位置が一致するときtrue
	 */
	bool					   operator==( const StorageLoadOrder &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元の複数文字列から対象の起動グループの一意な順序を確認する
 * @param[in] groups 終端を含む元のREG_MULTI_SZ文字列
 * @param[out] order 検査に成功した位置。失敗時は空の値
 * @param[in] legacyIde System Bus Extenderを要求する場合true。既定はSCSIの二位置
 * @return 順序が成立すれば0、不完全、欠落、重複、逆順はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectStorageLoadOrder( std::span<const wchar_t> groups,
												  StorageLoadOrder &order, bool legacyIde = false) ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsのロード順グループを読み取り専用で確認する
 * @param[out] order 検査に成功した位置。失敗時は空の値
 * @param[in] legacyIde System Bus Extenderを要求する場合true。既定はSCSIの二位置
 * @return 検査成功0、読取または元の順序に問題がある場合はHRESULT
 * @note サービスの参照、開始、登録、レジストリの変更は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStorageLoadOrder( StorageLoadOrder &order, bool legacyIde = false) ;

/** @brief 同原文のregistry操作を型と一緒に保持します */
enum class StorageInfAction : std::uint32_t {
	/// 元directive又は有限service設定です
	DECLARATION,
	/// 元AddRegの正確な型付き値です
	REGISTRY_VALUE,
	/// 正確な共有disk timeout DWORDです
	SHARED_DISK_TIMEOUT,
	/// 当該deviceの限定named valueだけのDelRegです
	HARDWARE_VALUE_DELETE,
	/// 同serviceのSystem event resource dataです
	EVENT_RESOURCE,
	/// MTD hardware keyの正式DeviceType DWORDです
	MTD_DEVICE_TYPE,
	/// MTD hardware keyの正式DeviceCharacteristics DWORDです
	MTD_DEVICE_CHARACTERISTICS,
	/// HDCの元DDInstallが指定した順位です
	FEATURE_SCORE,
	/// 選択HW節が参照した共有AutoLogger設定です
	AUTOLOGGER_VALUE,
	/// 関連サービスが宣言した自サービスのストレージ機能のDWORD
	SERVICE_STORAGE_FEATURES,
	/// 関連サービスが別のWindows ACPIサービスへ設定する共有DWORD
	SHARED_ACPI_STORAGE_FEATURES,
	/// 関連サービスの従来方式のDMAリマッピング条件
	SERVICE_DMA_COMPATIBILITY,
	/// 選択機器のDMAリマッピング対応の指定
	DEVICE_DMA_SUPPORT,
	/// 選択機器のDMAリマッピング条件の指定
	DEVICE_DMA_FLAGS,
	/// 選択基本節が参照する元の電源設定群
	POWER_SETTINGS,
} ;

/** @brief 全原tupleと型を併存させる内部の非権限事実です */
struct StorageInfEffect {
	/// 文脈/owner/原節/ordinal/全fieldです。PACKAGE由来をSYSTEMへ変えません
	SystemInfEffect	 original ;
	/// 元directiveとscopeから独立に決めた限定作用です
	StorageInfAction action{StorageInfAction::DECLARATION} ;
	/**
	 * @brief 同原値の全fieldをfresh再構築値へ比較します
	 * @param[in] other 同用途の独立した比較元です。同期中だけ借用します
	 * @return 省略状態/全値/順序が一致する場合trueです
	 */
	bool			 operator==( const StorageInfEffect &other) const = default ;
} ;

/** @brief 一つの共有AutoLoggerセッションとプロバイダーの型付き原設定 */
struct StorageAutoLoggerEffects {
	/// HKLM配下の元セッションキーの完全相対パス
	std::wstring  sessionPath ;
	/// 元セッション直下のプロバイダーキーの完全相対パス
	std::wstring  providerPath ;
	/// セッションのGuid値に指定された元のREG_SZ文字列
	std::wstring  sessionGuid ;
	/// プロバイダーキーを構成する元のGUID文字列
	std::wstring  providerGuid ;
	/// メモリバッファーモードを指定するLogFileModeの元DWORD
	std::uint32_t logFileMode{} ;
	/// セッションの開始設定を指定するStartの元DWORD
	std::uint32_t start{} ;
	/// セッションのバッファーサイズを指定するBufferSizeの元DWORD
	std::uint32_t bufferSize{} ;
	/// プロバイダーの追加プロパティを指定するEnablePropertyの元DWORD
	std::uint32_t enableProperty{} ;
	/// プロバイダーの有効状態を指定するEnabledの元DWORD
	std::uint32_t enabled{} ;
	/// プロバイダーのレベルを指定するEnableLevelの元DWORD
	std::uint32_t enableLevel{} ;
	/// プロバイダーの選別フラグを指定するEnableFlagsの元DWORD
	std::uint32_t enableFlags{} ;
	/**
	 * @brief 共有設定の型付き原観測を同じINFの再検査結果に照合する
	 * @param[in] other 独立した再検査結果
	 * @return キー、GUID、各DWORDが完全一致すればtrue
	 * @note FileNameの型と値の省略、各行の全フィールドと順序はStorageInfEffects::effectsが保持する
	 */
	bool		  operator==( const StorageAutoLoggerEffects &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 選択機器の元HW節にあるトリアージ指定付き共有AutoLoggerを読み取る
 * @param[in] hardware 署名と適用元を照合した同じ文書の選択HW節
 * @param[in] api 選択時の元文書読取と共用する節・レジストリ行の制限
 * @param[out] result 元値の全行を検査した設定。該当なしと失敗時は空
 * @return 元宣言の読取りと型の照合が成立した場合0、それ以外はHRESULT
 * @note 共有設定の現在値、所有や復旧は判定せず、導入資格を発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStorageTriageAutoLogger(
	const SystemInfSection &hardware, const SystemInfEffectApi &api,
	std::optional<StorageAutoLoggerEffects> &result) ;

/** @brief 共有AutoLoggerの閉じた現在値とその保護状態の読み取り結果 */
struct StorageAutoLoggerSnapshot {
	/// CurrentControlSetリンクが指した正式ControlSet名
	std::wstring							controlSet ;
	/// 完全なセッションとプロバイダーの実観測値。両方が正式に不在なら空
	std::optional<StorageAutoLoggerEffects> existing ;
	/// 実在するセッションに終端付きの明示空REG_SZがあった場合true
	bool									fileNamePresent{} ;
	/// SYSTEMからプロバイダーまでの固定順の元owner/group/DACL。正式不在の葉は空
	std::array<std::vector<std::byte>, 8U>	security ;
	/// セッションとプロバイダーの元最終書込み時刻。正式不在なら両方0
	std::array<std::uint64_t, 2U>			leafLastWrite{} ;
	/**
	 * @brief 元キーの現在値と保護状態を後続の読み取り結果と照合する
	 * @param[in] other 別の時点で読み取った共有設定
	 * @return 不在、元の値、保護状態、最終書込み時刻が完全一致すればtrue
	 */
	bool operator==( const StorageAutoLoggerSnapshot &other) const = default ;
} ;

/** @brief AutoLoggerを宣言した元選択のログモードの区分 */
enum class StorageAutoLoggerProfile {
	/// HDCのメモリバッファー設定
	MEMORY_BUFFER,
	/// 自動起動補助と一緒に宣言されたトリアージダンプ追加設定
	TRIAGE_BUFFER,
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元選択のAutoLogger作用先を読み取り専用で調べる
 * @param[in] desired INFの選択HW節から検査済みの一セッションと一プロバイダー
 * @param[out] snapshot 両キーの正式不在または保護された完全な現在値。失敗時は空
 * @param[in] profile 選択が宣言した元ログモード。HDCの既定ではメモリバッファーを使う
 * @return 読み取り成功0、保護、値、形、安定性の不成立または読取失敗はHRESULT
 * @note サービスへの所有結合は呼出元が確認する。レジストリ値やACLは変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStorageAutoLoggerSnapshot(
	const StorageAutoLoggerEffects &desired, StorageAutoLoggerSnapshot &snapshot,
	StorageAutoLoggerProfile profile = StorageAutoLoggerProfile::MEMORY_BUFFER) ;

//------------------------------------------------------------------------------
/**
 * @brief 元AutoLoggerのセッション名で現在のETW稼働状態を読み取る
 * @param[in] declared INFの選択HW節から検査済みの一セッションと一プロバイダー
 * @param[out] present 照会成功ならtrue、ETWが元セッションの不在を返した場合はfalse。失敗時は変更しない
 * @return 稼働またはERROR_WMI_INSTANCE_NOT_FOUNDを確認できた場合0、引数不正やその他の照会失敗はHRESULT
 * @note セッション名で照会する。ETWの構成、セッション状態、レジストリは変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStorageAutoLoggerRuntimePresence(
	const StorageAutoLoggerEffects &declared, bool &present) ;

/** @brief Windowsの共有ACPIキーの現在位置、明示的不在と保護を保持する */
struct StorageAcpiSnapshot {
	/// CurrentControlSetリンクから確認した正式のControlSet名
	std::wstring						   controlSet ;
	/// ACPI配下のParametersが読み取りできる通常キーだった場合true
	bool								   parametersPresent{} ;
	/// Parametersに存在する元DWORD。不在は空
	std::optional<std::uint32_t>		   storageSupportedFeatures ;
	/// SYSTEMからParametersまでの元owner、group、DACL。正式不在の葉は空
	std::array<std::vector<std::byte>, 6U> security ;
	/// Parametersに記録された最終書込み時刻。正式不在は0
	std::uint64_t						   parametersLastWrite{} ;
	/**
	 * @brief 同じ共有先の読み取り結果を独立した再観測に照合する
	 * @param[in] other 同じWindowsの現在値と保護
	 * @return 現在位置、不在、元値、保護、時刻がすべて一致した場合true
	 */
	bool operator==( const StorageAcpiSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsの正規ACPI登録から共有ストレージ機能の現在DWORDを読み取る
 * @param[out] snapshot 正式の不在または現在DWORDと保護。失敗時は空
 * @return 保護と安定性を照合した読取り成功は0、値の型や読取りの不成立はHRESULT
 * @note 同じACPIサービスの正規SYSと現在構成は呼出元が別途確認する。レジストリは変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStorageAcpiSnapshot( StorageAcpiSnapshot &snapshot) ;

/** @brief 一つの保護された電源設定キーの存在と不変性を確認する元値 */
struct StoragePowerKeySnapshot {
	/// 正式な不在の場合は空。実在するキーの保護を検証して得た記述子
	std::vector<std::byte>		 security ;
	/// 実在するキーのWindows最終書込み時刻。正式な不在では空
	std::optional<std::uint64_t> lastWrite ;
	/**
	 * @brief 同じ電源設定キーの保護と変更時刻を比較する
	 * @param[in] other 同じ位置の独立した読取り結果
	 * @return 正式不在または保護と書込み時刻が一致した場合true
	 */
	bool						 operator==( const StoragePowerKeySnapshot &other) const = default ;
} ;

/** @brief 展開せず読み取った型付きの電源設定文字列 */
struct StoragePowerTextSnapshot {
	/// Windowsが保持している元文字列。値が不存在の場合は空
	std::optional<std::wstring> value ;
	/// 同じ値のREG_SZまたはREG_EXPAND_SZ。不在では0
	std::uint32_t				type{} ;
	/**
	 * @brief 同じ電源設定項目の型と元文字列を再観測結果へ照合する
	 * @param[in] other 同じ現在値の独立した観測
	 * @return 不在、元型、展開前文字列が同じ場合true
	 */
	bool						operator==( const StoragePowerTextSnapshot &other) const = default ;
} ;

/** @brief 同じ電源設定GUIDを観測したPowerSettings内の登録場所 */
struct StoragePowerLocationSnapshot {
	/// PowerSettingsの直接子名と設定GUIDが一致した場合true
	bool					  rootMatch{} ;
	/// 同GUIDのキーが実在した括弧付きサブグループGUIDの昇順
	std::vector<std::wstring> matchingSubgroups ;
	/**
	 * @brief 同じ設定GUIDの登録場所を再観測と照合する
	 * @param[in] other 同じ電源設定の独立した登録場所の観測
	 * @return 直下の一致と全サブグループが一致する場合true
	 */
	bool					  operator==( const StoragePowerLocationSnapshot &other) const = default ;
} ;

/** @brief 元の署名付き電源設定が参照する定義と既定値の現在状態 */
struct StoragePowerSettingSnapshot {
	/// 元選択から確認した括弧付きサブグループGUID
	std::wstring								 subgroup ;
	/// 元選択から確認した括弧付き設定GUID
	std::wstring								 setting ;
	/// サブグループ、設定、既定値親、高パフォーマンス、バランス、省電力の順の現在観測
	std::array<StoragePowerKeySnapshot, 6U>		 keys ;
	/// 設定値の元下限。正式な値の不在では空
	std::optional<std::uint32_t>				 minimum ;
	/// 設定値の元上限。正式な値の不在では空
	std::optional<std::uint32_t>				 maximum ;
	/// 設定値の元増分。正式な値の不在では空
	std::optional<std::uint32_t>				 increment ;
	/// 設定の表示などを示す元属性。正式な値の不在では空
	std::optional<std::uint32_t>				 attributes ;
	/// 同じ選択で変更し得る現在の表示名
	StoragePowerTextSnapshot					 displayName ;
	/// 同じ選択で変更し得る現在の説明
	StoragePowerTextSnapshot					 description ;
	/// 比較する範囲の値に付く現在の表示単位
	StoragePowerTextSnapshot					 unitLabel ;
	/// 高パフォーマンス、バランス、省電力の順に各AC/DCの元既定値。不在は空
	std::array<std::optional<std::uint32_t>, 6U> defaults ;
	/// 全登録場所と直下の同名。元のサブグループ以外を列挙していない場合はnullopt
	std::optional<StoragePowerLocationSnapshot>	 locations ;
	/**
	 * @brief 同じ署名付き設定に結ぶ端末側の全観測を比較する
	 * @param[in] other 同じ元設定を再度読み取った端末観測
	 * @return 識別子、保護、値の正式不在、全値と登録場所の観測が一致した場合true
	 */
	bool operator==( const StoragePowerSettingSnapshot &other) const = default ;
} ;

/** @brief 一つの制御セットから保護を確認した電源設定の全観測 */
struct StoragePowerSettingsSnapshot {
	/// CurrentControlSetリンクから確認した正式の制御セット
	std::wstring							 controlSet ;
	/// SYSTEMからPowerSettingsまでの親キーの保護
	std::array<std::vector<std::byte>, 6U>	 parents ;
	/// 元選択の電源設定と同じ順の現在状態
	std::vector<StoragePowerSettingSnapshot> settings ;
	/**
	 * @brief 同じ候補の電源設定を新しい観測と比較する
	 * @param[in] other 同じ候補に対する独立した端末観測
	 * @return 制御セット、親の保護、設定と既定値が一致した場合true
	 */
	bool operator==( const StoragePowerSettingsSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元選択が指定した電源設定の登録定義と六つの既定値を読み取る
 * @param[in] settings 元INFの署名付き選択節から検査した電源設定の一覧
 * @param[out] snapshot 同じ現在制御セットの値と保護。失敗時は空
 * @return 同じ保護付きの位置で正式不在又は値を観測できれば0、失敗はHRESULT
 * @note 現在の電源プランやレジストリを変更しない。導入資格や元配布の所有は別に判断する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStoragePowerSettingsSnapshot(
	std::span<const RangedStoragePowerSetting> settings, StoragePowerSettingsSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 元位置の電源定義と既定値に加え、同じ設定GUIDの直下とサブグループを読み取る
 * @param[in] settings 元INFの署名付き選択節から検査した電源設定の一覧
 * @param[out] snapshot 現在制御セットの値と保護に全登録場所を加えた観測。失敗時は空
 * @return 正式不在を含む保護付きの現在値と全登録場所の観測で0、不成立はHRESULT
 * @note PowerSettingsの直下にあるGUID形式のキーとその直接子に限定する
 * @note 読取り専用で、電源プラン、署名元の所有や端末への導入資格は別に扱う
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStoragePowerSettingsAndLocationsSnapshot(
	std::span<const RangedStoragePowerSetting> settings, StoragePowerSettingsSnapshot &snapshot) ;

/** @brief 自動起動補助を持つ元選択に対応する共有設定の端末観測 */
struct StorageSharedHostSnapshot {
	/// Windows同梱ACPIの保護された現在のブートサービス構成
	SystemServiceEvidence	  acpiService ;
	/// 同じ現在制御セットの共有ACPIのレジストリ観測
	StorageAcpiSnapshot		  acpi ;
	/// 同じ現在制御セットのAutoLoggerの観測
	StorageAutoLoggerSnapshot autoLogger ;
	/**
	 * @brief 同じ元選択の端末観測を独立した再観測へ照合する
	 * @param[in] other 同じ共有先の現在構成・値・保護
	 * @return すべての観測が一致すればtrue
	 */
	bool					  operator==( const StorageSharedHostSnapshot &other) const = default ;
} ;

/** @brief 一つのSystemイベント登録に実在する元値と保護 */
struct StorageEventSourceSnapshot {
	/// Systemログ直下の確認済みのイベントソース名
	std::wstring				 name ;
	/// 保護された通常キーが開けた場合はtrue
	bool						 present{} ;
	/// 実在するEventMessageFileの展開前の値。値の不存在は空
	std::optional<std::wstring>	 messageFile ;
	/// 文字列の元型。値が存在する場合はREG_SZまたはREG_EXPAND_SZ
	std::uint32_t				 messageFileType{} ;
	/// 実在するTypesSupportedの完全DWORD。値の不存在は空
	std::optional<std::uint32_t> typesSupported ;
	/// 明示イベントのCategoryCountの元DWORD。値の不在と対象外は空
	std::optional<std::uint32_t> categoryCount ;
	/// 葉のowner、group、DACLの読取り。正式な不存在では空
	std::vector<std::byte>		 security ;
	/// 実在する葉が記録する最終書込み時刻
	std::uint64_t				 lastWrite{} ;
	/**
	 * @brief 一つの元イベントソースを再観測と比較する
	 * @param[in] other 別の時点で読み取った同じイベントソース
	 * @return 元値、不存在、保護、時刻が一致すればtrue
	 */
	bool operator==( const StorageEventSourceSnapshot &other) const = default ;
} ;

/** @brief 元選択が指定した既定イベントと明示イベントの現在登録 */
struct StorageSystemEventSnapshot {
	/// 元のSystemイベント登録に対応した正式ControlSet名
	std::wstring							   controlSet ;
	/// SYSTEMからSystemログまでの親の保護。確認できた場合だけ保持する
	std::array<std::vector<std::byte>, 6U>	   eventParents ;
	/// 関連サービスの既定名と補助サービスが明示した名前の順
	std::array<StorageEventSourceSnapshot, 2U> events ;
	/**
	 * @brief 同じ選択のSystemイベント観測を独立した再観測と比較する
	 * @param[in] other 同じ制御セットとイベント源を検査した現在状態
	 * @return 親・葉の値と保護が完全に一致した場合true
	 */
	bool operator==( const StorageSystemEventSnapshot &other) const = default ;
} ;

/** @brief 単一起動サービスの元選択が指定するSystemイベントの現在状態 */
struct StorageSingleBootEventSnapshot {
	/// Windowsが示す正式制御セット名
	std::wstring						   controlSet ;
	/// SYSTEMからSystemログまでの各元親の保護
	std::array<std::vector<std::byte>, 6U> eventParents ;
	/// 関連サービスの一つのイベント源と元値。葉の正式不在はpresentがfalse
	StorageEventSourceSnapshot			   event ;
	/**
	 * @brief 同じ元選択の現在イベントを独立した再観測と比較する
	 * @param[in] other 同じ関連サービスの独立した観測
	 * @return 制御セットと親・葉の観測が一致すればtrue
	 */
	bool operator==( const StorageSingleBootEventSnapshot &other) const = default ;
} ;

/** @brief 元Display宣言と型・値が一致した一つのApplicationイベント源の保護観測 */
struct DisplayApplicationEventSnapshot {
	/// Windowsが示す正式制御セット名
	std::wstring						   controlSet ;
	/// SYSTEMからApplicationログまでの各元親の保護
	std::array<std::vector<std::byte>, 6U> eventParents ;
	/// 署名宣言に結び付く直接子のイベント源名
	std::wstring						   name ;
	/// 保護された通常キーの実在を確認したときtrue
	bool								   present{} ;
	/// 葉から取得した元owner、groupとDACL
	std::vector<std::byte>				   security ;
	/// 同じ葉の最終書込時刻を100ns単位のWindows元値で保持する
	std::uint64_t						   lastWrite{} ;
	/**
	 * @brief 同じ宣言への独立した再照合の保護観測を比較する
	 * @param[in] other 同じ元宣言と全値が一致した再読取観測
	 * @return 制御セット、親と葉の保護と位置・時刻が等しい場合true
	 */
	bool operator==( const DisplayApplicationEventSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 保護された既存Applicationイベント源の全値を現用INFの宣言へ照合する
 * @param[in] declaration 現用署名済みDisplay INFが指定した同名イベント源と元値
 * @param[out] snapshot 全値・型・保護と安定性が確認できた場合だけ保持。失敗時は空
 * @return 既存の名前と全登録が一致して0、不在・不一致・読取エラーはHRESULT
 * @note リソースDLLを読み込まず、登録を変更しない。デバイス所有の判定は呼出側で行う
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDisplayApplicationEventSnapshot(
	const OfficialDisplayAuxiliaryService &declaration, DisplayApplicationEventSnapshot &snapshot) ;

/** @brief 現在のSoftwareComponentクラスにある一つの保護付き登録 */
struct DisplayType1ClassRegistration {
	/// クラスキー内の4桁の登録名
	std::wstring				slot ;
	/// Windowsが登録した元MatchingDeviceId。正式不在は空のoptional
	std::optional<std::wstring> matchingId ;
	/// Windowsが登録した元DriverStorePath。正式不在は空のoptional
	std::optional<std::wstring> storePath ;
	/// 同じ登録キーのowner、groupとDACL
	std::vector<std::byte>		security ;
	/**
	 * @brief 同じ登録の独立した読み取りを比較する
	 * @param[in] other 比較するクラス登録
	 * @return 元値と保護が一致する場合true
	 */
	bool operator==( const DisplayType1ClassRegistration &other) const = default ;
} ;

/** @brief SoftwareComponentの全番号付きクラス登録と確認したWindowsの元制御セット */
struct DisplayType1ClassSnapshot {
	/// 現行Windowsが使う元制御セット名
	std::wstring							   controlSet ;
	/// SYSTEMからSoftwareComponentクラスまでの元保護
	std::array<std::vector<std::byte>, 6U>	   parents ;
	/// 署名検査や現在機器への対応付け前のクラス登録の名前順
	std::vector<DisplayType1ClassRegistration> registrations ;
	/**
	 * @brief 別時点に読んだ同じ母集合と保護を比較する
	 * @param[in] other 同じWindowsから独立に読み取った値
	 * @return 現元制御セット、親の保護と全登録が同じ場合true
	 */
	bool operator==( const DisplayType1ClassSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じWindowsのSoftwareComponentクラスの全番号付き登録を保護付きで読む
 * @param[out] snapshot 登録と通知の一貫性の確認が完了した場合だけ返す。失敗時は空
 * @return 読取り成功で0、読取・保護・途中変更の失敗はHRESULT
 * @note 現用かどうか、元署名や実行範囲はこの観測だけで確定しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDisplayType1ClassSnapshot( DisplayType1ClassSnapshot &snapshot) ;

/** @brief 保護されたレジストリに実在するType 1の作用対象一値 */
struct DisplayType1RegistryValue {
	/// Windowsが保持する元のREG_*型
	std::uint32_t		   type{} ;
	/// 展開や終端補完を行う前の全バイト。ゼロ長も実在値の一つ
	std::vector<std::byte> bytes ;
	/**
	 * @brief 同じ値の元型と全バイトを比較する
	 * @param[in] other 同じ作用先の独立した読取り
	 * @return 元型と全バイトが等しい場合true
	 */
	bool				   operator==( const DisplayType1RegistryValue &other) const = default ;
} ;

/** @brief 選択DisplayのOpenCL Type 1が触れるレジストリの非権限観測 */
struct DisplayType1RegistrySnapshot {
	/// Windowsが選択親に割り当てたDisplayクラスの相対Driverキー名
	std::wstring							 driverKey ;
	/// 正式リンクで解決した現在の制御セット名
	std::wstring							 controlSet ;
	/// SYSTEM、リンク、実制御セット、Control、Class、Display、選択slot、VM二種、Services、
	/// 共有サービス、SOFTWARE、AMD、EEUの順の元owner、groupとDACL。正式不在だけ空
	std::array<std::vector<std::byte>, 14U>	 keySecurity ;
	/// 選択slotのOpenCLDriverName。正式不在は空のoptional
	std::optional<DisplayType1RegistryValue> openClDriverName ;
	/// 選択slotのOpenCLDriverNameWow。正式不在は空のoptional
	std::optional<DisplayType1RegistryValue> openClDriverNameWow ;
	/// 選択slotの旧CheckRegistration。正式不在は空のoptional
	std::optional<DisplayType1RegistryValue> parentCheckRegistration ;
	/// 選択slotのCopyToVMOverwriteにあるAMDOpenCL。正式不在は空のoptional
	std::optional<DisplayType1RegistryValue> copyToVmOverwrite ;
	/// 選択slotのCopyToVMOverwriteWow64にあるAMDOpenCL。正式不在は空のoptional
	std::optional<DisplayType1RegistryValue> copyToVmOverwriteWow64 ;
	/// AMD External Events Utilityサービスの旧CheckRegistration。正式不在は空のoptional
	std::optional<DisplayType1RegistryValue> serviceCheckRegistration ;
	/// SOFTWAREのAMD EEUにある旧CheckRegistration。正式不在は空のoptional
	std::optional<DisplayType1RegistryValue> softwareCheckRegistration ;
	/**
	 * @brief 同じ端末での独立した現在値と保護の読取りを比較する
	 * @param[in] other 同じ選択Displayの別読取り
	 * @return 選択親のDriverキー、制御セット、各保護と元値が一致すればtrue
	 */
	bool operator==( const DisplayType1RegistrySnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 選択Displayの実Driverキーと二つの共有先からOpenCL Type 1の対象値を読み取る
 * @param[in] devices 選択親を開いたWindowsのデバイス情報集合。同期中だけ借用する
 * @param[in,out] parent 同じ情報集合に属する選択Displayのデバイス情報
 * @param[out] snapshot 保護、元型、元値と正式な不在。失敗時は空
 * @return 現在の相対Driverキーと各作用先を安定して読めた場合0、その他は元HRESULT
 * @note レジストリは読取り専用。元実行物、親子関係、他の作用、導入可否は確定しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDisplayType1RegistrySnapshot( HDEVINFO						 devices,
														   SP_DEVINFO_DATA				&parent,
														   DisplayType1RegistrySnapshot &snapshot) ;

/** @brief 現用の補助サービスとその署名パッケージの実行ファイルについて確認した現在状態 */
struct DisplayAuxiliaryServiceObservation {
	/// 現用SCMの構成、状態、元保護
	AuxiliaryStorageServiceSnapshot service ;
	/// 同じCATメンバーと照合した実EXEと全保護親
	ProtectedExecutableSnapshot		executable ;
	/**
	 * @brief 同じ対象の独立した再観測を比較する
	 * @param[in] other 同じ現用構成と物理実ファイルの再観測
	 * @return 全観測が一致すればtrue
	 */
	bool operator==( const DisplayAuxiliaryServiceObservation &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現在のDisplay補助サービスの実行条件を署名付き現用INFの宣言へ照合する
 * @param[in] declaration 現用サービスのクラス、開始指定とグループまで照合済みの元宣言
 * @param[in] actual 同じSCMサービスの元構成と保護付き観測
 * @return 宣言の実行条件と現在構成が同じ場合0、失敗はHRESULT
 * @note SCMコマンドに対応するファイルとCATは呼出側が照合する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError matchDisplayAuxiliaryServiceExecution(
	const OfficialDisplayAuxiliaryService &declaration,
	const AuxiliaryStorageServiceSnapshot &actual) ;

//------------------------------------------------------------------------------
/**
 * @brief 現用署名パッケージの実行ファイルと同じ補助サービスのSCM構成を照合する
 * @param[in] registered 同じ選択の公開名・実節・元署名を確認した現用パッケージ
 * @param[out] observation 同じ構成と実EXEの二度の完全観測。失敗時は空
 * @return 現用の元実行条件と正規ファイルが一致して0、それ以外はHRESULT
 * @note 読取専用。端末上の他デバイスとの共用や導入許可はここでは決めない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredDisplayAuxiliaryService(
	const RegisteredDisplayAuxiliaryPackage &registered,
	DisplayAuxiliaryServiceObservation		&observation) ;

//------------------------------------------------------------------------------
/**
 * @brief 単一起動サービスがSystemログに持つ一つのイベント登録を読み取る
 * @param[in] serviceName 同じ署名付き元選択が指定する関連サービス名
 * @param[out] snapshot 保護付きの現在元値または正式不在。失敗時は空
 * @return 現在値または正式な葉の不在を確認できれば0、元診断はHRESULT
 * @note 読取り専用。現在値から所有を推定せず、元宣言と資源は呼出元が照合する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSingleBootStorageEventSnapshot(
	std::wstring_view serviceName, StorageSingleBootEventSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 署名付き選択が指定した関連サービスと名前付きのSystemイベントを読取専用で観測する
 * @param[in] selected 検証済みの元選択と六欄形式のAddServiceを持つ自動起動補助サービス
 * @param[out] snapshot 正式な不在と、存在する場合の元値・保護。失敗時は空
 * @return 二つの元イベントを観測できれば0、それ以外はHRESULT
 * @note 現在値から旧所有やファイルの信頼を推定せず、登録・起動は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readNamedStorageEventSnapshot( const SelectedStorageServiceFacts &selected,
														StorageSystemEventSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 署名付きの現用登録が宣言した二つのSystemイベントを同じ制御セットで読む
 * @param[in] declared 同じ機器の登録INFと元CATに照合済みのイベント宣言
 * @param[out] snapshot 現用関連サービスと明示イベントの観測。失敗時は空
 * @return 保護付きで両方を読めた場合0、入力・保護・読取りの不成立はHRESULT
 * @note 元と同じ直接のイベント名だけを読み、登録や現在値を変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredNamedStorageEventSnapshot(
	const RegisteredStoragePackageEvidence &declared, StorageSystemEventSnapshot &snapshot) ;

/** @brief 同じ元選択に結ぶ補助サービスの端末現在状態。所有資格は別に確認する */
struct StorageAuxiliaryHostSnapshot {
	/// SCMの明示不在または現在構成と保護
	std::optional<AuxiliaryStorageServiceSnapshot> service ;
	/// 保護されたSystem32の元コピー先ファイルの現在状態
	System32ExecutableSnapshot					   executable ;
	/// Systemイベント登録の通常リンクが指したControlSet名
	std::wstring								   controlSet ;
	/// SYSTEMからSystemログの親までの同じ保護とリンクを固定順で記録する
	std::array<std::vector<std::byte>, 6U>		   eventParents ;
	/// 関連ドライバー、補助サービスの順の同じSystemイベント登録
	std::array<StorageEventSourceSnapshot, 2U>	   events ;
	/**
	 * @brief 元選択が触れる現在値を独立した再観測へ照合する
	 * @param[in] other 同一端末で再読取りした元状態
	 * @return 各不在、元値、保護、ファイル同一性が一致すればtrue
	 */
	bool operator==( const StorageAuxiliaryHostSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元補助サービス、System32の元コピー先、二つのSystemイベント登録を現端末で読む
 * @param[in] selected 元署名と選択から検査済みの関連サービスと補助サービス
 * @param[out] snapshot 正式な不在を含む読み取り結果。失敗時は空
 * @return 読取り成功0、権限、元位置、安定性、型又は元読取失敗はHRESULT
 * @note SCMとファイル・レジストリは変更しない。既存配布との所有照合は別に必要
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStorageAuxiliaryHostSnapshot(
	const SelectedStorageServiceFacts &selected, StorageAuxiliaryHostSnapshot &snapshot) ;

/** @brief Driver Storeに配置される自動起動補助サービスの現在構成とファイル */
struct StorageAutoStartAuxiliarySnapshot {
	/// 正式不在なら空。実在する場合はSCMの現在構成、状態、保護を全て保持する
	std::optional<AuxiliaryStorageServiceSnapshot> service ;
	/// 現在構成の実行ファイルを同じWindowsから解決した正規パス。サービス不在なら空
	std::wstring								   executablePath ;
	/// 実行ファイルの現在値と二つの親の保護。サービス不在なら空の観測
	ProtectedExecutableSnapshot					   executable ;
	/**
	 * @brief 補助サービスの同じ選択に対する再観測の完全な一致を判定する
	 * @param[in] other 別の時点で読んだ現在構成、位置、保護と元ファイル
	 * @return 現在構成と保護付きファイルの全状態が一致すればtrue
	 */
	bool operator==( const StorageAutoStartAuxiliarySnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元選択の自動起動補助の現在SCM構成とDriver Store内のファイルを読み取る
 * @param[in] selected 署名付きの元選択と直接コピーの補助EXE宣言
 * @param[out] snapshot 正式不在または保護を確認した現在構成と実ファイル。失敗時は空
 * @return 同じ端末の保護付き観測が成立すれば0、構成・位置・読取の不成立はHRESULT
 * @note 同じ現在ファイルと元登録の署名による所有照合は別工程。サービスの起動・変更は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readAutoStartStorageAuxiliarySnapshot(
	const SelectedStorageServiceFacts &selected, StorageAutoStartAuxiliarySnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 署名付きの現用登録が宣言した自動起動補助の現在SCMと元EXEを読み取る
 * @param[in] declared 同じ機器の登録INFと元CATに照合済みの補助サービスの証拠
 * @param[out] snapshot 正式不在または同じ登録元に一致した現在観測。失敗時は空
 * @return 読取りと元位置・バイトの照合が成立すれば0、失敗はHRESULT
 * @note 同じ場所の保護付きファイルを読み、補助の起動・停止・構成変更は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredAutoStartStorageAuxiliarySnapshot(
	const RegisteredStorageHelperEvidence &declared, StorageAutoStartAuxiliarySnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 現在の補助サービスの実行条件と保護を署名付き元宣言へ照合する
 * @param[in] actual 同じサービスの構成、状態、追加設定と保護の安定した観測
 * @param[in] declared 同じ補助サービスの署名付き登録から確認した元宣言とSystem32の絶対宛先
 * @return 実行条件と保護が成立すれば0、端末の状態や元宣言の不一致はHRESULT
 * @note 表示名と説明、現在EXEの署名元は呼出元で照合する。元観測の値と記述子は保持する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError matchRegisteredStorageAuxiliaryService(
	const AuxiliaryStorageServiceSnapshot &actual, const RegisteredStorageHelperEvidence &declared) ;

/** @brief 選択機器の現用ドライバーと元署名に結び付く現在観測 */
struct StorageAutomaticRegistrationSnapshot {
	/// 現用の署名付き登録。正式な未導入では空
	std::optional<RegisteredStoragePackageEvidence> package ;
	/// 現用機器の実節の装飾属性。正式不在と明示空を区別する
	std::optional<std::wstring>						sectionExtension ;
	/// 元登録が指定した関連イベントと明示イベントの現在値
	StorageSystemEventSnapshot						events ;
	/// 元登録が指定した補助と、同じパッケージから実行される現在のEXE
	StorageAutoStartAuxiliarySnapshot				auxiliary ;
	/**
	 * @brief 同じ選択機器の現用登録と現在構成の全観測を比較する
	 * @param[in] other 同じ機器の独立した再観測
	 * @return 不在、署名元、現在構成と保護が同じ場合true
	 */
	bool operator==( const StorageAutomaticRegistrationSnapshot &other) const = default ;
} ;

/** @brief 関連サービスの一覧から照合した一つの現用機器 */
struct StorageAutomaticServiceOwner {
	/// Windowsが返した内部インスタンス識別。外部とログへ渡さない
	std::wstring						 instance ;
	/// 同じ機器が現在使う署名付き元登録と現在観測
	StorageAutomaticRegistrationSnapshot registered ;
	/// 候補と同じ関連サービスの機器に対し、Windowsが候補を選んだ基本節
	std::wstring						 candidateSection ;
	/// 候補と同じ関連サービスの機器について確認した候補順位。現用旧サービスだけなら空
	std::optional<std::uint32_t>		 candidateRank ;
	/**
	 * @brief 同じ関連サービスを使用する機器の読み取りを比較する
	 * @param[in] other 同じ機器の再観測
	 * @return インスタンス、現在配布と候補の観測が全て同じならtrue
	 */
	bool operator==( const StorageAutomaticServiceOwner &other) const = default ;
} ;

/** @brief 一つの選択機器と、現用・候補の関連サービスを使う現在機器の観測 */
struct StorageAutomaticDeviceSnapshot {
	/// 同じ選択機器の元署名と現在観測
	StorageAutomaticRegistrationSnapshot	  selected ;
	/// 現用と候補の関連サービスから確認した全インスタンスと元署名
	std::vector<StorageAutomaticServiceOwner> owners ;
	/**
	 * @brief 同じ選択に属する現用機器の観測を独立した再確認結果と比較する
	 * @param[in] other 同じ選択から再構築した現在機器一覧
	 * @return 選択機器、全所有者と現在配布が同じ場合true
	 */
	bool operator==( const StorageAutomaticDeviceSnapshot &other) const = default ;
} ;

/** @brief 一つの電源設定に対し、現用登録と候補の定義を照らし合わせた結果 */
enum class StoragePowerChange {
	/// 定義は正式に不在で、確認した現用登録も使用していない
	CREATE,
	/// 現用登録に一致する定義と既定値を候補も維持する
	KEEP,
	/// 選択機器の現用登録に一致し、その定義または既定値を候補が変更する
	UPDATE_SELECTED,
	/// 候補を適用しない他機器の現用登録に一致する定義または既定値を変更する
	UPDATE_SHARED,
	/// 現在定義と署名付き現用登録の対応を確認できない
	UNVERIFIED,
} ;

//------------------------------------------------------------------------------
/**
 * @brief 保護付き端末観測と署名付き現用登録から候補の電源設定の関係を分類する
 * @param[in] candidate 同じ署名付き候補が実選択で指定する電源設定
 * @param[in] observed 候補順の設定定義と既定値の現在観測
 * @param[in] device 選択機器と候補・現用サービスを共有する全present機器の登録証拠
 * @param[out] changes 成功時は候補順の分類。失敗時は空
 * @return 分類できた場合0、観測の欠落・食い違いはHRESULT
 * @note 関係の分類だけを行う。現在の電源プラン値と導入・上書きの可否は別に判断する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError classifyStoragePowerChanges(
	std::span<const RangedStoragePowerSetting> candidate,
	const StoragePowerSettingsSnapshot &observed, const StorageAutomaticDeviceSnapshot &device,
	std::vector<StoragePowerChange> &changes) ;

/** @brief 候補のサービスまたはイベントの現在定義との関係 */
enum class StorageServiceChange {
	/// 対象が正式に存在せず、現用登録に同名定義がない
	CREATE,
	/// 元登録で照合した現在定義を候補が維持する
	KEEP,
	/// 選択機器の現用登録を候補が変更する
	UPDATE_SELECTED,
	/// 選択外の機器が利用する現在定義を候補が変更する
	UPDATE_SHARED,
	/// 現用の元定義、実ファイル、資源を確認できない
	UNVERIFIED,
} ;

/** @brief 元の候補が変更する起動サービスと配布先の現在観測 */
struct StorageAutomaticBootSnapshot {
	/// 候補と同名のSCMの現在構成。正式な不在ではevidenceは空
	StorageServiceSnapshot		related ;
	/// 原INFが指定したSYSの配置先とその親の保護。正式な葉の不在ではexistingは空
	ProtectedExecutableSnapshot destination ;
	/// 元登録と現在構成への照合で成立した関係
	StorageServiceChange		change{StorageServiceChange::UNVERIFIED} ;
	/**
	 * @brief 起動サービスとSYSの現在状態を再観測へ照合する
	 * @param[in] other 同じ元選択の独立した観測
	 * @return 名称、構成、保護、現物と分類が一致した場合true
	 */
	bool operator==( const StorageAutomaticBootSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 候補の起動サービスと配置先の現在値を、同じサービスを使う署名元へ照合する
 * @param[in] selected 署名付き候補の検査済み元選択
 * @param[in] device 選択機器と現用・候補サービスを使用する機器の元登録
 * @param[in] boot 候補が変更する二つの場所の現在観測
 * @return 同じ名前・配置先について確認した関係。所有不明ならUNVERIFIED
 * @note 保護付きの現在観測と署名検証済み登録だけを渡す。資格や導入の許可は発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] StorageServiceChange classifyStorageAutomaticBoot(
	const SelectedStorageServiceFacts &selected, const StorageAutomaticDeviceSnapshot &device,
	const StorageAutomaticBootSnapshot &boot) noexcept ;

/** @brief 名前付きイベントの候補が直接更新するDLLの現在観測と所有 */
struct StorageAutomaticEventResourceSnapshot {
	/// System32の保護と元候補が指定したDLLの実在・元バイト
	ProtectedExecutableSnapshot destination ;
	/// 現用機器と署名元への照合結果。読取りのみではUNVERIFIED
	StorageServiceChange		change{StorageServiceChange::UNVERIFIED} ;
	/**
	 * @brief 同じ配置の独立した現在観測と分類を照合する
	 * @param[in] other 同じ元選択による観測結果
	 * @return 配置、保護、現物と分類が全て一致する場合true
	 */
	bool operator==( const StorageAutomaticEventResourceSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元候補が名前付きイベントに使うSystem32のDLLを保護付きで読む
 * @param[in] selected コピー先と元バイトを照合済みの選択
 * @param[out] resource 元候補がDLLを指定した場合の観測。省略や失敗時は空
 * @return 観測または元の省略を確認した場合0、それ以外はHRESULT
 * @note 同名の既存DLLを元配布の所有と見なさない。DLLをロードせず変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStorageAutomaticEventResource(
	const SelectedStorageServiceFacts					 &selected,
	std::optional<StorageAutomaticEventResourceSnapshot> &resource) ;

/** @brief 自動起動補助を持つ一つの選択に結ぶ現在機器と共有先 */
struct StorageAutomaticHostSnapshot {
	/// 選択機器の現用観測。機器を指定しない読取りでは空
	std::optional<StorageAutomaticDeviceSnapshot>		 device ;
	/// 観測したACPIの署名付きWindows構成、共有値とAutoLogger
	StorageSharedHostSnapshot							 shared ;
	/// 元選択が触れる電源定義と既定値を、同じ端末から読み取った現在観測
	StoragePowerSettingsSnapshot						 power ;
	/// 元候補順の電源定義の差。現用機器一覧を照合しない観測では空
	std::vector<StoragePowerChange>						 powerChanges ;
	/// 候補の二つのSystemイベントが参照する現在状態
	StorageSystemEventSnapshot							 events ;
	/// 元候補がSystem32に明示配置するイベントDLLの現在観測。コピーの省略では空
	std::optional<StorageAutomaticEventResourceSnapshot> eventResource ;
	/// 候補の補助が参照する現在のSCM、ファイルと保護
	StorageAutoStartAuxiliarySnapshot					 auxiliary ;
	/// 補助サービス、関連イベント、明示イベントの順の分類。機器観測があれば保持する
	std::optional<std::array<StorageServiceChange, 3U>>	 serviceChanges ;
	/// 候補と同名の起動サービスと元のSYS配置先の観測。機器観測があれば保持する
	std::optional<StorageAutomaticBootSnapshot>			 boot ;
	/// 元AutoLogger名のETW稼働観測。未照会は空、ETWがその名前の不在を返した場合だけfalse
	std::optional<bool>									 autoLoggerRuntimePresent ;
	/**
	 * @brief 同じ選択に結ぶ現在の各観測を再読結果と比較する
	 * @param[in] other 同じ候補から調べた現在機器と共有先
	 * @return 観測の有無、現用登録、各値と保護が一致すればtrue
	 */
	bool operator==( const StorageAutomaticHostSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現用と候補の両方で観測した現在の共有先が同じ状態だったか確かめる
 * @param[in] selected 同じ候補が宣言した署名付き補助構成
 * @param[in] host 現用と候補をそれぞれの署名元から確認した現在観測
 * @return 一つの制御セットで共通箇所が一致すれば0、観測の差は再試行HRESULT
 * @note 元観測を合成しない。他の機器を含む所有判断と導入許可は呼出元の別工程
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyStorageAutomaticHostCoherence(
	const SelectedStorageServiceFacts &selected, const StorageAutomaticHostSnapshot &host) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 候補の補助とイベントを現在の定義と署名付き現用登録に照合する
 * @param[in] selected 固定された元選択の作用検査を終えた自動起動補助
 * @param[in] infSha256 同じ元選択のINFの完全SHA-256
 * @param[in] catalogSha256 同じ元選択の署名付きCATの完全SHA-256
 * @param[in,out] host 現用機器と現在観測。成功時に照合結果、失敗時には空の分類を保持する
 * @return 全分類の成功0。構造の矛盾や途中の観測不一致はHRESULT
 * @pre 同じ候補の元作用と現用・候補の共通箇所を照合済みであること
 * @note 元宣言が書く作用だけを比較する。復旧、導入の許可と適用後の確認は別に判断する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError classifyStorageAutomaticServiceChanges(
	const SelectedStorageServiceFacts &selected, std::wstring_view infSha256,
	std::wstring_view catalogSha256, StorageAutomaticHostSnapshot &host) ;

/** @brief storage原graphの全検査後だけ保持する非権限結果です */
struct StorageInfEffects {
	/// 元service factsです。StartTypeの原値を保持します
	SelectedStorageServiceFacts					   service ;
	/// 同原文の全到達行です
	std::vector<StorageInfEffect>				   effects ;
	/// 必要だったassociated/依存serviceだけの観測です
	std::vector<StorageServiceSnapshot>			   services ;
	/// 正式メディアチェンジャーが参照する現在の起動グループ順序
	std::optional<StorageLoadOrder>				   loadOrder ;
	/// 全作用で実際に確認した原disk timeoutです。最終行の原値です
	std::optional<std::uint32_t>				   sharedDiskTimeout ;
	/// 署名付きの選択から確認した共有ACPIの元機能ビット
	std::optional<std::uint32_t>				   sharedAcpiStorageFeatures ;
	/// 原MTD hardware keyで明示したDeviceTypeです
	std::optional<std::uint32_t>				   mtdDeviceType ;
	/// 原MTD hardware keyで明示したDeviceCharacteristicsです
	std::optional<std::uint32_t>				   mtdDeviceCharacteristics ;
	/// 検査した選択DDInstall基本節の元順位
	std::optional<std::uint32_t>				   featureScore ;
	/// 元HW節にある共有AutoLoggerの型付き設定。現端末の観測は含まない
	std::optional<StorageAutoLoggerEffects>		   autoLogger ;
	/// 選択基本節が参照する電源設定と元の設定範囲
	std::vector<RangedStoragePowerSetting>		   powerSettings ;
	/// 関連サービスだけを持つブート選択で確認した元イベントの型と値
	std::optional<RegisteredStorageEventReference> singleBootEvent ;
	/// 単一ブートの署名付き元選択が関連サービスに宣言した局所DWORD
	std::vector<RegisteredStorageServiceValue>	   singleBootRegistryValues ;
	/// 自動起動補助がある場合に照合した現用機器と候補の変更先
	std::optional<StorageAutomaticHostSnapshot>	   automaticHost ;
	/// 既存HDCサービスのSYSの完全SHA-256。正式不存在または対象外は空
	std::wstring								   currentHdcBinarySha256 ;
	/// 補助サービスを持つ元選択でだけ、現在の変更先を読み取った結果
	std::optional<StorageAuxiliaryHostSnapshot>	   auxiliaryHost ;
	/**
	 * @brief 同原値の全fieldをfresh再構築値へ比較します
	 * @param[in] other 同用途の独立した比較元です。同期中だけ借用します
	 * @return 省略状態/全値/順序が一致する場合trueです
	 */
	bool operator==( const StorageInfEffects &other) const = default ;
} ;

/** @brief 元作用一行が指定する現在の局所レジストリ値 */
struct StorageSingleBootRegistryValue {
	/// 同じ署名付き選択の作用配列にある元行の位置
	std::size_t							  effectIndex{} ;
	/// Windowsが返した元型。正式な不在はREG_NONE
	std::uint32_t						  type{} ;
	/// レジストリが返した完全バイト。値またはそのキーの正式な不在では未設定
	std::optional<std::vector<std::byte>> bytes ;
	/**
	 * @brief 同じ元作用の現在値を独立した再観測と比較する
	 * @param[in] other 同じ元位置からの観測
	 * @return 元行・型・バイト・実在の有無が一致すればtrue
	 */
	bool operator==( const StorageSingleBootRegistryValue &other) const = default ;
} ;

/** @brief 一つの署名付き選択が書き込む機器とサービスの現在局所値 */
struct StorageSingleBootRegistrySnapshot {
	/// 対象サービスのキー保護を保持する位置
	static constexpr std::size_t				SERVICE_KEY_INDEX = 4U ;
	/// 選択機器のハードウェアキー保護を保持する位置
	static constexpr std::size_t				HARDWARE_KEY_INDEX = 7U ;
	/// 端末とサービスの両方に使うWindowsの正式制御セット名
	std::wstring								controlSet ;
	/// SYSTEM、標準リンク、実制御セット、Services、対象サービス、Parameters、PnpInterface、
	/// 機器ハードウェアキー、割込みの親、MSI設定、割込み先の順の元保護。正式不在の位置は空
	std::array<std::vector<std::byte>, 11U>		keySecurity ;
	/// 候補で指定された元AddRegの順に、型付きの完全な値または正式不在
	std::vector<StorageSingleBootRegistryValue> values ;
	/**
	 * @brief 同じ選択の全局所作用先を再読取りと比較する
	 * @param[in] other 同じ機器とサービスの独立読取り
	 * @return 制御セット・各位置の保護・各値が一致すればtrue
	 */
	bool operator==( const StorageSingleBootRegistrySnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ機器と関連サービスに対する署名付き元選択の局所値を読み取る
 * @param[in] devices 現在の選択機器を開いたWindowsの情報集合
 * @param[in,out] device 同じ情報集合に属する選択機器のWindows情報
 * @param[in] instanceId 同じ機器から確認した完全インスタンス識別。外部へ出力しない
 * @param[in] effects 同じ署名付き選択について全作用を検査した結果
 * @param[out] snapshot 同じ制御セットの保護付き観測と型付き値。失敗時は空
 * @return 元作用の位置と値または正式な不在の読取りは0、未確認はHRESULT
 * @note 機器属性の前後照合と現在サービスの所有は呼出元で確認し、設定やACLは変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSingleBootStorageRegistrySnapshot(
	HDEVINFO devices, SP_DEVINFO_DATA &device, std::wstring_view instanceId,
	const StorageInfEffects &effects, StorageSingleBootRegistrySnapshot &snapshot) ;

/** @brief 同じ機器登録の前後確認で安定性を確認した候補と現用サービスの観測 */
struct StorageSingleBootDeviceSnapshot {
	/// 同じ現在機器の署名付き現用元。正式未導入では登録が空
	RegisteredSingleBootDeviceEvidence			  installed ;
	/// 同じ元候補が指定する局所値。各行は呼出元が保持する同じ作用配列を参照
	StorageSingleBootRegistrySnapshot			  registry ;
	/// 署名付き候補が指定する関連サービス名の保護付き現在イベント
	StorageSingleBootEventSnapshot				  candidateEvent ;
	/// 選択機器が異なる関連サービスを使用する場合の保護付き現在イベント
	std::optional<StorageSingleBootEventSnapshot> otherInstalledEvent ;
	/// 署名付き候補と同名をSCMから照会した元構成、または正式な不在
	StorageServiceSnapshot						  candidateService ;
	/**
	 * @brief 同じ元選択に対する独立観測を照合する
	 * @param[in] other 同じ機器と候補の独立読取り
	 * @return 署名元、局所値、イベントとSCMの元観測が全て一致すればtrue
	 */
	bool operator==( const StorageSingleBootDeviceSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 二つの読取りを同じ制御セットの安定した機器観測へ結び付ける
 * @param[in] read 同じ機器と作用配列を同期中に借用する読取り
 * @param[out] snapshot 二回の全観測が一致した場合の結果。失敗時は空
 * @return 同じ元値と整合した位置を二度確認したら0、変更または読取り失敗はHRESULT
 * @note この結果から導入資格を発行しない。元機器を前後で照合する処理内から呼び出す
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStableSingleBootDeviceSnapshot(
	const std::function<NativeError( StorageSingleBootDeviceSnapshot &)> &read,
	StorageSingleBootDeviceSnapshot										&snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsの一つの現在機器と署名付き候補の局所作用先を読取専用で照合する
 * @param[in] instanceId 先のWindows順位観測で特定した同じ機器の完全識別
 * @param[in] noDriver 先の観測で現在INFとサービスが正式に不在だった場合true
 * @param[in] expectedInf 先の観測で確認した公開INF。未導入なら空
 * @param[in] intended 同じ候補の署名と選択を検査済みの局所作用
 * @param[out] snapshot 全観測と現在機器の前後照合が成立した結果。失敗時は空
 * @return 正式な未導入を含む元機器と観測の確認成功0、不成立はHRESULT
 * @note 現在イベントの観測をその所有証明には使わない。局所行は同じintendedの生存中だけ照合する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCurrentSingleBootStorageDeviceSnapshot(
	const std::wstring &instanceId, bool noDriver, std::wstring_view expectedInf,
	const StorageInfEffects &intended, StorageSingleBootDeviceSnapshot &snapshot) ;

/** @brief 選択外のpresent機器の署名付き元宣言または未確認理由 */
struct StorageSingleBootPeerEvidence {
	/// 同じOS内で元機器を照合する完全識別。外部出力には渡さない
	std::wstring									instance ;
	/// 機器が現在使用する関連サービス。正式不在または未確認では空
	std::wstring									service ;
	/// 関連サービスの属性で値または正式な不在を読めた場合true
	bool											serviceKnown{} ;
	/// 同じ機器から読み取れた現在INF名。未確認機器でも得られた値を保持
	std::wstring									publishedInf ;
	/// 現在INFから選ばれた機器の元基本節。未確認の場合は空
	std::wstring									basicSection ;
	/// 元の節装飾。未確認または不存在と、明示された空を区別
	std::optional<std::wstring>						sectionExtension ;
	/// 元INFとサービスに正式不在を確認した場合true
	bool											noDriver{} ;
	/// 元属性または署名付き元の未確認理由。正式未導入と確認済み署名では0
	NativeError										diagnostic{} ;
	/// 現在の属性から署名まで確認した元登録。正式不在と未確認では空
	std::optional<RegisteredStoragePackageEvidence> origin ;
	/**
	 * @brief 同一機器の元登録または未確認理由を比較する
	 * @param[in] other 同じOS内の独立した観測
	 * @return 機器、サービス、元証拠または未確認理由が一致した場合true
	 */
	bool operator==( const StorageSingleBootPeerEvidence &other) const = default ;
} ;

/** @brief 一つの候補電源設定に対する署名付き現用宣言と現在値の対応 */
struct StorageSingleBootPowerUse {
	/// 選択機器の署名付き元に同じ設定GUIDの宣言がある場合true
	bool		selectedDeclared{} ;
	/// 選択機器の元宣言が現在の定義・値・所在に一致した場合true
	bool		selectedMatches{} ;
	/// 元宣言が現在の定義・値・所在に一致した選択外機器数
	std::size_t sharedMatches{} ;
	/// 同じGUIDを宣言するが現在の定義・値・所在が異なる選択外機器数
	std::size_t sharedConflicts{} ;
	/**
	 * @brief 同一候補GUIDに対する独立観測を比較する
	 * @param[in] other 同じ候補GUIDと現在定義から得た対応
	 * @return 選択機器と他機器の照合結果が一致した場合true
	 */
	bool		operator==( const StorageSingleBootPowerUse &other) const = default ;
} ;

/** @brief 一回の選択から読み取った局所状態、電源の所在と現用元宣言 */
struct StorageSingleBootSharingSnapshot {
	/// 同じ候補と現在機器に結ばれた登録、イベントと局所観測
	StorageSingleBootDeviceSnapshot			   device ;
	/// 関連サービスの同じ候補が配置する正式SYSの現在ファイルと親の保護
	ProtectedExecutableSnapshot				   destination ;
	/// 同じ候補順に取得した正式制御セットの値・所在
	StoragePowerSettingsSnapshot			   power ;
	/// 選択外の全present機器の元証拠・正式不在・未確認
	std::vector<StorageSingleBootPeerEvidence> peers ;
	/// 候補のサービスに所属する全present機器の端末内識別
	std::vector<std::wstring>				   candidateServiceDevices ;
	/// 現用の異なるサービスに所属する全present機器の端末内識別
	std::vector<std::wstring>				   otherInstalledServiceDevices ;
	/// 同じ候補順に現用宣言と現在の定義・所在を照合した結果
	std::vector<StorageSingleBootPowerUse>	   use ;
	/// 同じ署名付き候補順の変更種別。合成観測で確認した場合だけ保持
	std::vector<StoragePowerChange>			   powerChanges ;
	/**
	 * @brief 同じ選択で独立に読み取った共有観測を照合する
	 * @param[in] other 候補と端末が同じ独立読取り
	 * @return 局所観測、所在、元証拠と個別結果がすべて同じ場合true
	 */
	bool operator==( const StorageSingleBootSharingSnapshot &other) const = default ;
} ;

/** @brief 署名付き単一ブート選択が更新する保護付き配置と局所値の分類 */
struct StorageSingleBootChanges {
	/// 候補の同名起動サービスと同じ正規SYSの変更を合わせた分類
	StorageServiceChange			  boot{StorageServiceChange::UNVERIFIED} ;
	/// 同名Systemイベントの設定に対する変更種別
	StorageServiceChange			  event{StorageServiceChange::UNVERIFIED} ;
	/// 同じ局所観測順で機器またはサービスの各元AddRegに対応する変更種別
	std::vector<StorageServiceChange> registry ;
	/**
	 * @brief 同じ選択の変更分類を独立読取りの結果と照合する
	 * @param[in] other 同じ元候補と機器を対照した分類
	 * @return 起動、イベントと局所のすべての変更分類が同じならtrue
	 */
	bool operator==( const StorageSingleBootChanges &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ元選択が変更する起動サービス、SYS、イベントと局所値を分類する
 * @param[in] intended 全作用に署名が結び付いた同じ候補。同期中だけ借用する
 * @param[in] snapshot 同じ選択機器と同名サービスの全present所属の保護付き観測
 * @param[out] changes 全作用の分類。元観測不整合や読取り未確認では初期値
 * @return 分類を取得できれば0。照合対象の不足や矛盾はHRESULT
 * @note 端末やレジストリを変更せず、共有変更や未確認の上書きに資格を発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError classifySingleBootStorageChanges(
	const StorageInfEffects &intended, const StorageSingleBootSharingSnapshot &snapshot,
	StorageSingleBootChanges &changes) ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ設定GUIDの署名付き元宣言を候補の現在の定義と所在に照合する
 * @param[in,out] snapshot 一つの選択の元登録、全peerの観測と候補順の全所在。成功時だけuseへ反映
 * @return 観測と既知の宣言を分類できれば0、元観測の欠損や矛盾はHRESULT
 * @note 未確認の現用元はpeersに残す。肯定的な一致から他機器の不使用や導入資格を導かない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError classifySingleBootStoragePowerUse(
	StorageSingleBootSharingSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名付き候補順に電源設定の登録時の変更種別を判定する
 * @param[in] candidate 同じ元選択の署名付き電源定義の一覧
 * @param[in,out] snapshot 同じ候補の全所在と現用機器の読み取り。成功時のuseとpowerChangesを保持
 * @return 全候補を分類できれば0。元観測と候補の不一致や読取り不足はHRESULT
 * @note 全場所での正式不在を機器の不使用とは区別し、導入資格や書込権限を発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError classifySingleBootStoragePowerChanges(
	std::span<const RangedStoragePowerSetting> candidate,
	StorageSingleBootSharingSnapshot		  &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 選択機器と同じ候補の全電源所在、他機器の現用元、サービス所属を読み取る
 * @param[in] instanceId 同じ候補の前観測で特定した選択機器
 * @param[in] noDriver その機器のINFとサービスが正式不在だった場合true
 * @param[in] expectedInf 同じ前観測の公開INF。未導入では空
 * @param[in] intended 検査済み署名候補の効果と電源定義
 * @param[out] snapshot 機器群・局所状態・所在を前後で照合した結果。失敗時は空
 * @return 同じ選択と安定した観測が確認できれば0。途中変更や全体の読取り失敗はHRESULT
 * @note この結果では導入資格を発行しない。読取り専用でIDを外へ出さない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCurrentSingleBootStorageSharingSnapshot(
	const std::wstring &instanceId, bool noDriver, std::wstring_view expectedInf,
	const StorageInfEffects &intended, StorageSingleBootSharingSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 自動起動型の元選択が設定する作用を適用後の値へ照合する
 * @param[in] intended 同じ選択の署名確認済み作用と適用前のACPI観測
 * @param[in] current 同じ機器の元INF・CAT・SYS・EXEを照合済みの適用後観測
 * @param[in] rebootRequired 同じ指定適用APIがWindowsの再起動を要求した場合true
 * @return 元選択と共有設定の反映は0、署名済みの旧起動構成だけが残る再起動要求はS_FALSE、他の相違はHRESULT
 * @note 適用後の値は保護確認済みの読取りから渡す。旧資源、他機器と実際の起動は別に確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyAppliedAutomaticStorageEffects(
	const StorageInfEffects &intended, const StorageAutomaticHostSnapshot &current,
	bool rebootRequired = false) noexcept ;

/** @brief 元deviceのMTD HW property実値または正式な不存在です */
struct MtdCurrentProperties {
	/// 正式ERROR_NOT_FOUNDなら空、それ以外は原DWORDです
	std::optional<std::uint32_t> deviceType ;
	/// 正式ERROR_NOT_FOUNDなら空、それ以外は原DWORDです
	std::optional<std::uint32_t> characteristics ;
	/**
	 * @brief 原型と値をfresh観測へ比較します
	 * @param[in] other 同deviceの再観測です
	 * @return 不存在を含む全値が一致すればtrueです
	 */
	bool						 operator==( const MtdCurrentProperties &other) const = default ;
} ;

/** @brief exact storage serviceへだけ安定config/SD又は明示不存在を返す内部readerです */
using StorageServiceReadFunction =
	std::function<NativeError( std::wstring_view, SystemServiceEvidence &)> ;

//------------------------------------------------------------------------------
/**
 * @brief 元PACKAGEの全選択作用を原文脈/所有scope/有限型へ検査します
 * @param[in] seeds 同NativeLoaderが確定したPACKAGEだけの選択/Needs到達節です
 * @param[in] api 同原byteの全field readerとWindows helper検証です
 * @param[in] service 同原選択と一意SYSコピーへ結ぶ非権限factsです
 * @param[in] readService 同じ完全backendのexact service読取です。欠損をnative補完しません
 * @param[in] osBuild 現在のNativeLoaderが二度照合する実OS buildです
 * @param[out] result 全作用/依存/現service成立時だけの原結果です。失敗時空です
 * @param[out] stage 最初の固定数値拒否です。本文を一般logへ出しません
 * @return 全成立0、未知/欠損/重複/型/所有scope又は元APIのHRESULTです
 * @note registry/SCMへの書込み、service起動、独自driver実行、未知作用の省略を行いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectStorageInfEffects( std::span<const SystemInfSection>  seeds,
												   const SystemInfEffectApi			 &api,
												   const SelectedStorageServiceFacts &service,
												   const StorageServiceReadFunction	 &readService,
												   std::uint32_t osBuild, StorageInfEffects &result,
												   std::uint32_t &stage) ;

//------------------------------------------------------------------------------
/**
 * @brief HDCの単一カーネルブートサービスと元PACKAGEの選択作用を静的に検査する
 * @param[in] seeds 一つのPACKAGEから確定した基本節、HW節、Services節
 * @param[in] api 同じ原INFの全フィールド読取とWindows保護イベント資源の検証
 * @param[in] service 同選択と単一の署名済みSYSコピーに結合した非権限の原事実
 * @param[in] osBuild 同じNativeLoaderが観測したWindowsのビルド番号
 * @param[out] result 全作用を確認した型付き原結果。失敗時は空
 * @param[out] stage 原値を含まない固定診断。成功時は0
 * @return 検査成功0、未対応の作用や元の読取不成立はHRESULT
 * @note 呼出元でPACKAGE由来と同CATのINF/SYSを検証する。現在のサービスやAutoLoggerの所有は導入前に別途確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectHdcInfContentEffects( std::span<const SystemInfSection>	 seeds,
													  const SystemInfEffectApi			&api,
													  const SelectedStorageServiceFacts &service,
													  std::uint32_t						 osBuild,
													  StorageInfEffects					&result,
													  std::uint32_t						&stage) ;

//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助サービスを含む一つの署名付きストレージ選択の元作用を検査する
 * @param[in] seeds 元の署名付き基本節・機器節・Services節の完全な集合
 * @param[in] api 署名文書の全行とWindowsのイベント資源を読み取る操作
 * @param[in] service 元選択と閉包に結び付いたサービス事実
 * @param[out] result 全作用が成立した場合だけ返す型付きの元事実。失敗時は空
 * @param[out] stage 失敗時に示す固定診断番号。成功時は0
 * @return 元作用が成立すれば0、それ以外はHRESULT
 * @note 端末のサービスや共有設定を変更せず、選択の導入資格も発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectAutoStartStorageInfContentEffects(
	std::span<const SystemInfSection> seeds, const SystemInfEffectApi &api,
	const SelectedStorageServiceFacts &service, StorageInfEffects &result, std::uint32_t &stage) ;

//------------------------------------------------------------------------------
/**
 * @brief 単一ブートサービスの元電源、局所レジストリ、イベントを同じ署名付き選択で照合する
 * @param[in] seeds 同じ元INFの基本節、機器節、サービス節
 * @param[in] api 元INFの行とWindowsイベント資源を読み取る操作
 * @param[in] service 同じ選択とAMD64の元SYSに結び付いたサービスの事実
 * @param[out] result 全作用を確認できた場合だけ返す元事実。失敗時は空
 * @param[out] stage 最初の失敗の固定診断。成功時は0
 * @return 成功0、元の宣言、参照、形式、資源が不成立の場合はHRESULT
 * @note 元作用だけを検査し、現在の電源の所有、端末の適用性、導入資格は呼出側で別に検査する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSingleBootStorageInfContentEffects(
	std::span<const SystemInfSection> seeds, const SystemInfEffectApi &api,
	const SelectedStorageServiceFacts &service, StorageInfEffects &result, std::uint32_t &stage) ;

class DriverStoreProvider ;
class SignedIndexCandidateBindingSession ;
struct CommonInfInspection ;
struct StorageServiceOwnershipProof ;

/** @brief 同じ単一起動選択の保護付き観測と元作用の分類 */
struct StorageSingleBootInstallScope {
	/// 同じ機器と元候補に結ぶ現在の配置、設定と他機器の観測
	StorageSingleBootSharingSnapshot observed ;
	/// 元選択が起動、イベントと局所値へ行う変更
	StorageSingleBootChanges		 changes ;
	/**
	 * @brief 同じ選択の現在観測と分類を再取得結果と比較する
	 * @param[in] other 同じ端末と元候補の独立した再取得結果
	 * @return 現在観測とすべての分類が一致した場合true
	 */
	bool operator==( const StorageSingleBootInstallScope &other) const = default ;
} ;

/** @brief 適用後に独立して確認した別名の旧関連サービスと現在の所属 */
struct StorageSingleBootRetainedServiceSnapshot {
	/// 旧関連サービス名と保護付きの現在SCM構成
	StorageServiceSnapshot		   service ;
	/// 旧署名元が指定した正規位置の現在SYSと親の保護
	ProtectedExecutableSnapshot	   destination ;
	/// 旧関連サービス名で確認した同じ制御セットのSystemイベント
	StorageSingleBootEventSnapshot event ;
	/// 旧関連サービスに現在所属するpresent機器の正規化済み識別の昇順
	std::vector<std::wstring>	   devices ;
	/**
	 * @brief 同じ旧関連サービスの独立観測を比較する
	 * @param[in] other 旧関連サービスの再観測
	 * @return SCM構成、配置、イベントと全所属が一致すればtrue
	 */
	bool operator==( const StorageSingleBootRetainedServiceSnapshot &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 適用後の実登録と全作用を署名付き単一起動選択および適用前の保護へ照合する
 * @param[in] intended 同じ署名付き選択の元構成と全作用
 * @param[in] before 指定適用前に確認した同じ選択の現在観測と変更種別
 * @param[in] after 同じ機器と候補を独立して読み取った適用後の現在観測
 * @param[in] publishedInf 登録直後に元閉包と照合した公開INF名
 * @param[in] infSha256 元INFの完全SHA-256
 * @param[in] catalogSha256 元CATの完全SHA-256
 * @param[in] selectedInstance 同じ選択機器の正規化済み識別。所属一覧と同じ表記
 * @param[in] retained 旧関連サービスが別名の場合の独立した適用後の観測
 * @return 実登録・元バイト・作用・保護・所属がすべて成立すれば0、不一致はHRESULT
 * @note 観測を比較する。再起動後の確認待ちと、端末からの読取りは呼出側が扱う
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyAppliedSingleBootStorageEffects(
	const StorageInfEffects &intended, const StorageSingleBootInstallScope &before,
	const StorageSingleBootSharingSnapshot &after, std::wstring_view publishedInf,
	std::wstring_view infSha256, std::wstring_view catalogSha256,
	std::wstring_view											   selectedInstance,
	const std::optional<StorageSingleBootRetainedServiceSnapshot> &retained) ;

//------------------------------------------------------------------------------
/**
 * @brief 新登録の確認が不成立の場合に再起動後の確認待ちの根拠を照合する
 * @param[in] before 指定適用前に確認した同じ選択の全観測
 * @param[in] newReadError 新登録の観測が返した非0の元診断
 * @param[in] rebootRequired Windowsの指定適用が再起動を要求した場合true
 * @param[in] readBefore 必要な場合に一回だけ同じ機器と旧状態を独立に安定観測する読取り
 * @return 再起動要求と全旧状態の一致が成立した場合は再起動後の確認待ち、その他は未確認と診断
 * @note 署名や保護の読取り失敗を再起動要求で補わない。再起動は実行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverStorageReflectionResult resolveUnconfirmedSingleBootStorageReflection(
	const StorageSingleBootSharingSnapshot &before, NativeError newReadError, bool rebootRequired,
	const std::function<NativeError( StorageSingleBootSharingSnapshot &)> &readBefore) ;

/** @brief 外部DTO/JSON/purposeから構築できない、同issuer元選択専用の不変資格です */
class StorageInfQualification final {
public:
	/**
	 * @brief private factoryが作った一時資格の所有を移します
	 * @param[in,out] other 同issuerが構築した移動元です。移動後は再使用しません
	 */
	StorageInfQualification( StorageInfQualification &&other) noexcept = default ;
	/**
	 * @brief private資格の複製構築を禁止します
	 */
	StorageInfQualification( const StorageInfQualification &) = delete ;
	/**
	 * @brief private資格のcopy代入を禁止します
	 */
	StorageInfQualification &operator=( const StorageInfQualification &) = delete ;

private:
	friend class DriverStoreProvider ;
	friend class SignedIndexCandidateBindingSession ;
	/**
	 * @brief 同issuer factoryだけが未公開の原資格領域を構築します
	 */
	StorageInfQualification() = default ;
	/// 同scan/device/選択原INFの結合です。外部identityから許可を生成しません
	ScanSessionId										session_{} ;
	/// 同scanで明示選択したopaque device identityです
	std::wstring										deviceIdentity_ ;
	/// 原ADMIN workspace内のINF完全位置です
	std::wstring										infPath_ ;
	/// 同native nodeで確定した基本DDInstall名です
	std::wstring										basicSection_ ;
	/// 元whole graphと現在観測のraw tupleです
	StorageInfEffects									effects_ ;
	/// MTDの同device/classに登録されたhost handlerの元観測です
	std::optional<MtdHandlerObservation>				mtdHandlers_ ;
	/// MTDの選択deviceに実在したDWORD又は正式不在です
	std::optional<MtdCurrentProperties>					mtdCurrentProperties_ ;
	/// HDCの同共有AutoLoggerの正式不在または保護された完全な現在値
	std::optional<StorageAutoLoggerSnapshot>			autoLogger_ ;
	/// 単一起動の署名付き元選択について同じ機器から確認した変更範囲
	std::optional<StorageSingleBootInstallScope>		singleBoot_ ;
	/// 既存driverを持つ元deviceのexact Service propertyです
	std::wstring										currentDeviceService_ ;
	/// 元全byte/CATを毎回独立再検査する不変snapshotです
	std::shared_ptr<const CommonInfInspection>			inspection_ ;
	/// 同名現serviceのexact所有adapterと同原packageのnative適合証拠です
	std::shared_ptr<const StorageServiceOwnershipProof> ownershipProof_ ;
} ;
} // namespace drivercrate
