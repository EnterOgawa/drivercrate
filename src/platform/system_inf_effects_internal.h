//------------------------------------------------------------------------------
/**
 * @file system_inf_effects_internal.h
 * @brief 同選択SYSTEM原文の型付き作用と不変tupleの内部契約です
 * @version 01.14.00
 * @date 2026/11/13
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/13  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.02.00 Shunji Ogawa  2026/11/20  収集で原署名とStoreを確認したSDバスINFの識別を追加
 * Ver.01.03.00 Shunji Ogawa  2026/11/20  収集で選択したWindows標準のPorts INFへサービスとイベントの作用を結合
 * Ver.01.04.00 Shunji Ogawa  2026/11/20  収集で選択した標準NVMeとPCIの文書および電源作用を追加
 * Ver.01.05.00 Shunji Ogawa  2026/11/21  収集で選択した標準AHCIの文書と電源作用を追加
 * Ver.01.06.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの同梱サービス検査に元文書IDを追加
 * Ver.01.07.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスのフィルター置換と端末照合の情報を追加
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの表示名と説明の登録値・展開値を保持
 * Ver.01.09.00 Shunji Ogawa  2026/11/22  ストレージ補助サービスのSCM構成・状態・監査の読取契約を追加
 * Ver.01.10.00 Shunji Ogawa  2026/11/23  署名付きストレージINFの電源値域と既定値の読取り契約を追加
 * Ver.01.10.01 Shunji Ogawa  2026/11/23  元電源設定の全項目を再読取り結果と比較
 * Ver.01.11.00 Shunji Ogawa  2026/11/23  現用同梱NVMeとPCIの原作用と電源宣言を照合
 * Ver.01.12.00 Shunji Ogawa  2026/11/24  自前媒体を使う収集選択のSerenumの型を追加
 * Ver.01.13.00 Shunji Ogawa  2026/11/24  収集で同一性を確認した正規WinUSB文書の識別を追加
 * Ver.01.14.00 Shunji Ogawa  2026/11/27  Display補助サービスの有効名とSCM保護の読取を追加
 * </pre>
 *
 * @note NativeLoaderが検証済みSYSTEM/INBOX/Storeの正確な選択だけを渡します。公開許可DTOではありません
 * @see docs/adr/0491-typed-system-needs-effects-and-complete-selection-qualification.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
/** @brief SYSTEM全作用の閉じた拒否地点です。observedは件数/固定型だけです */
enum class SystemInfDiagnosticStage : std::uint32_t {
	/// 元reader/共有予算又は元APIによる拒否です
	READ = 13000U,
	/// 正確な参照名/辺が不正です
	REFERENCE = 13001U,
	/// data節参照が不正です
	DATA_REFERENCE = 13002U,
	/// 宣言field/重複が不正です
	DECLARATION = 13003U,
	/// copy参照/共同予算が不正です
	COPY_REFERENCE = 13004U,
	/// device優先宣言が不正です
	DEVICE_PREFERENCE = 13005U,
	/// 実Windows moduleが不成立です
	MODULE = 13006U,
	/// 同原service型/必須fieldが不成立です
	SERVICE = 13007U,
	/// 同原interface宣言が不成立です
	INTERFACE = 13008U,
	/// framework宣言が不成立です
	FRAMEWORK = 13009U,
	/// 必要な既存service証拠が不成立です
	SERVICE_SNAPSHOT = 13010U,
	/// secure companionの子実体/設定が不成立です
	SECURE_COMPANION = 13011U,
	/// 同原companion親子関係が不成立です
	COMPANION = 13012U,
	/// 未知又は異文脈directiveです
	DIRECTIVE = 13013U,
	/// registry型/root/全fieldが不成立です
	REGISTRY = 13014U,
	/// NTMPDriverと同service実体が不一致です
	STREAM_MODULE = 13015U,
	/// HW設定/filter関係が不成立です
	HARDWARE = 13016U,
	/// interface相対dataが不成立です
	INTERFACE_DATA = 13017U,
	/// 媒体COM data/関係が不成立です
	COM_METADATA = 13018U,
	/// Windows VfW三者/実体が不成立です
	VFW = 13019U,
	/// 同serviceの全ETW集合が不成立です
	EVENT_PUBLISHER = 13020U,
	/// 限定device propertyが不成立です
	PROPERTY = 13021U,
	/// 選択された標準ストレージの電源設定参照又は全設定値が不成立です
	POWER_SETTING = 13022U,
	/// 仮想Wi-Fiバスの上位フィルター置換に必要な端末観測が未成立です
	WIFI_FILTER_BINDING = 13023U,
} ;
/** @brief HKRと参照の所有先を区別する有限文脈です */
enum class SystemInfContext : std::uint32_t {
	/// 元deviceのsoftware keyです
	DEVICE = 1U,
	/// 元deviceのhardware keyです
	HARDWARE = 2U,
	/// AddServiceを宣言する元Servicesです
	SERVICES = 3U,
	/// AddInterfaceを宣言する元Interfacesです
	INTERFACES = 4U,
	/// KMDF/UMDF/companionを宣言する元Wdfです
	FRAMEWORK = 5U,
	/// 同原AddServiceのservice-installです
	SERVICE = 6U,
	/// 同原serviceのevent-logです
	EVENT_LOG = 7U,
	/// 正確なGUID/referenceへ結ぶinterface-installです
	INTERFACE = 8U,
	/// 同原KMDF serviceの設定です
	KMDF = 9U,
	/// 同原UMDF serviceの設定です
	UMDF = 10U,
	/// 同原KMDF/UMDF間のcompanion関係です
	COMPANION = 11U,
	/// 親文脈を保持するregistry dataです
	REGISTRY = 12U,
	/// 同deviceの限定property dataです
	PROPERTY = 13U,
	/// 元DDInstallが参照する標準ストレージの電源設定です
	POWER_SETTING = 14U,
} ;
/** @brief MODULE拒否の閉じた役割です。file名/pathを一般logへ出しません */
enum class SystemInfModuleRole : std::uint32_t {
	/// 同原AddServiceのkernel実体です
	SERVICE_SYS = 1U,
	/// 同原UMDF宣言の単一実体です
	UMDF_DLL = 2U,
	/// Windows VfW三者登録が参照する実体です
	VFW_DLL = 3U,
	/// 同serviceのETW resource/messageです
	EVENT_RESOURCE = 4U,
	/// 元configが指定した既存inbox service実体です
	EXISTING_SERVICE = 5U,
	/// 同DDInstallのNTMPDriverと同serviceの実体です
	STREAM_SYS = 6U,
} ;
/** @brief 元APIの一行を所有し任意本文を一般logへ出さない内部値です */
struct SystemInfRow {
	/// 元節内の0起点行位置です
	std::uint32_t			  ordinal{} ;
	/// Directive節のkeyです。data行では空です
	std::wstring			  key ;
	/// 元1起点fieldを順に所有します。空fieldも省略しません
	std::vector<std::wstring> values ;
	/**
	 * @brief 元行の位置/key/全fieldをfresh値へ比較します
	 * @param[in] other 同原文から再構築した行です
	 * @return 全field一致時trueです
	 */
	bool					  operator==( const SystemInfRow &other) const = default ;
} ;
/** @brief 同document/正確な節/所有者で型を選ぶ参照です */
struct SystemInfSection {
	/// 元NativeLoaderの非零document identityです
	std::uint64_t	 document{} ;
	/// 推測で装飾しない元節名です
	std::wstring	 name ;
	/// 元選択と宣言が決めた作用文脈です
	SystemInfContext context{SystemInfContext::DEVICE} ;
	/// Registry/propertyへ入る前の相対scopeです
	SystemInfContext scope{SystemInfContext::DEVICE} ;
	/// service名又はinterface GUID/referenceなどの元所有者です
	std::wstring	 owner ;
	/**
	 * @brief 元document/節/文脈/所有者の完全一致を確認します
	 * @param[in] other 独立に再構築した元参照です
	 * @return 全field一致時trueです
	 */
	bool			 operator==( const SystemInfSection &other) const = default ;
} ;
/** @brief 元原文の全fieldと型/所有先を私有計画へ保持します */
struct SystemInfEffect {
	/// 元document/節/文脈と親所有者です
	SystemInfSection source ;
	/// 元rowの全key/fieldと行位置です
	SystemInfRow	 row ;
	/**
	 * @brief 原作用の全fieldと所有先を再構築値へ比較します
	 * @param[in] other 同選択のfresh作用です
	 * @return 全field一致時trueです
	 */
	bool			 operator==( const SystemInfEffect &other) const = default ;
} ;
/** @brief raw QUERY_SERVICE_CONFIG pointerを保持しない安定したreadonly証拠です */
struct SystemServiceEvidence {
	/// 同原SYSTEM文脈の正確なservice名です
	std::wstring			  name ;
	/// 元service typeです
	std::uint32_t			  type{} ;
	/// 元開始方式です
	std::uint32_t			  start{} ;
	/// 元error controlです
	std::uint32_t			  errorControl{} ;
	/// 元tag IDです
	std::uint32_t			  tag{} ;
	/// 元の全binary pathです。引数を切り捨てません
	std::wstring			  binary ;
	/// 元load-order groupです
	std::wstring			  group ;
	/// 原順の全依存serviceです
	std::vector<std::wstring> dependencies ;
	/// 元account名です
	std::wstring			  account ;
	/// SCMが返す表示名です
	std::wstring			  display ;
	/// 仮想Wi-Fiバス又はストレージ補助サービスについてSCMが返す説明です
	std::wstring			  description ;
	/// 仮想Wi-Fiバスの展開前の表示名です。他のサービスでは空です
	std::wstring			  rawDisplay ;
	/// 仮想Wi-Fiバスの展開前の説明です。他のサービスでは空です
	std::wstring			  rawDescription ;
	/// 元owner/group/control/全DACLです。補助サービスの場合は取得した監査SACLも含みます
	std::vector<std::byte>	  security ;
	/**
	 * @brief 原config安定fieldと元SDをfresh値へ完全比較します
	 * @param[in] other 同一serviceの独立したreadonly観測です
	 * @return 全field一致時trueです
	 */
	bool					  operator==( const SystemServiceEvidence &other) const = default ;
} ;
/** @brief 補助サービスの起動・停止条件に含まれる一項目の元種別と値です */
struct AuxiliaryStorageServiceTriggerData {
	/// SCMが返した元データ種別です
	std::uint32_t		   type{} ;
	/// 同種別の完全なバイト列です
	std::vector<std::byte> bytes ;
	/**
	 * @brief 発火条件の同じ位置のデータを比較します
	 * @param[in] other 独立した読取が返した条件の一項目です
	 * @return 種別と全バイトが一致する場合trueです
	 */
	bool operator==( const AuxiliaryStorageServiceTriggerData &other) const = default ;
} ;
/** @brief 補助サービスの一つのトリガーをポインターなしで保持します */
struct AuxiliaryStorageServiceTrigger {
	/// SCMが返した元トリガー種別です
	std::uint32_t									type{} ;
	/// SCMが返した開始又は停止の作用です
	std::uint32_t									action{} ;
	/// 元GUIDバイトです。SCMが省略した場合は空です
	std::optional<std::array<std::byte, 16U>>		subtype ;
	/// 順序を保った元発火条件です
	std::vector<AuxiliaryStorageServiceTriggerData> data ;
	/**
	 * @brief トリガーの元作用と全発火条件を再読取の値へ比較します
	 * @param[in] other 同順序で得た独立した読取結果です
	 * @return 全項目が一致する場合trueです
	 */
	bool operator==( const AuxiliaryStorageServiceTrigger &other) const = default ;
} ;
/** @brief SCMが報告した補助サービスの実行状態です */
struct AuxiliaryStorageServiceStatus {
	/// 状態報告のサービス種別です
	std::uint32_t type{} ;
	/// 停止、実行中などのSCM状態です
	std::uint32_t state{} ;
	/// 現時点でサービスが受け付ける制御のビット集合です
	std::uint32_t controlsAccepted{} ;
	/// 状態報告のWindows終了コードです
	std::uint32_t win32ExitCode{} ;
	/// 状態報告のサービス固有終了コードです
	std::uint32_t serviceExitCode{} ;
	/// 状態遷移中の元チェックポイントです
	std::uint32_t checkpoint{} ;
	/// 状態遷移中の応答目安を示す元ミリ秒値です
	std::uint32_t waitHint{} ;
	/// SCMが当該状態で報告したプロセスIDです
	std::uint32_t processId{} ;
	/// 状態報告のサービスフラグです
	std::uint32_t flags{} ;
	/**
	 * @brief 状態遷移とサービスの入れ替わりを検出するため元報告を比較します
	 * @param[in] other 同じSCMサービスから再取得した状態です
	 * @return 全項目が一致する場合trueです
	 */
	bool		  operator==( const AuxiliaryStorageServiceStatus &other) const = default ;
} ;
/** @brief 同じストレージ補助サービスの私有観測です。所有・導入の許可を表しません */
struct AuxiliaryStorageServiceSnapshot {
	/// 元構成、説明、及び自己相対のowner/group/DACL/SACLです
	SystemServiceEvidence						config ;
	/// 構成と保護の読取前後で一致した状態です
	AuxiliaryStorageServiceStatus				status ;
	/// 障害回数をリセットするまでの元秒数です
	std::uint32_t								failureResetSeconds{} ;
	/// 障害時に使われる元の再起動メッセージです
	std::wstring								failureRebootMessage ;
	/// 障害時に使われる元のコマンドです。内部比較だけに使用します
	std::wstring								failureCommand ;
	/// 障害時動作を元順で保持します。各組は作用種別と遅延ミリ秒です
	std::vector<std::array<std::uint32_t, 2U>>	failureActions ;
	/// 非クラッシュ障害も回復処理を行う指定です
	bool										failureActionsOnNonCrash{} ;
	/// 遅延自動開始の元指定です
	bool										delayedAutoStart{} ;
	/// サービストークンで使うSID種別です
	std::uint32_t								serviceSidType{} ;
	/// サービストークンへ要求する特権の元順です
	std::vector<std::wstring>					requiredPrivileges ;
	/// 前停止通知の元タイムアウトミリ秒です
	std::uint32_t								preshutdownTimeout{} ;
	/// サービスを起動・停止する元トリガーの順序付き全項目です
	std::vector<AuxiliaryStorageServiceTrigger> triggers ;
	/// SCMが返した優先NUMAノードの元値です
	std::uint16_t								preferredNode{} ;
	/// 優先NUMAノード応答の削除フラグです
	bool										preferredNodeDelete{} ;
	/// 対応しない元NUMA照会では元HRESULT。値を読めた場合のみ0
	NativeError									preferredNodeError{} ;
	/// 保護されたサービスとして起動する元種別です
	std::uint32_t								launchProtection{} ;
	/**
	 * @brief 既存サービスの構成・状態・保護を独立した観測へ比較します
	 * @param[in] other 同じ名前について再取得した完全観測です
	 * @return 全項目が一致する場合trueです
	 */
	bool operator==( const AuxiliaryStorageServiceSnapshot &other) const = default ;
} ;
/** @brief 正確なservice名へ安定config/SDを返す同期内部reader型です */
using SystemInfServiceReadFunction =
	std::function<NativeError( std::wstring_view, SystemServiceEvidence &)> ;
/** @brief 型付き全作用が検査に使う同NativeLoaderの限定操作です */
struct SystemInfEffectApi {
	/// 正確な同document節だけを上限内で読みます。不存在/不正は元errorです
	std::function<NativeError( const SystemInfSection &, std::vector<SystemInfRow> &)> read ;
	/// 単一Windows moduleを同原文・実file/CAT/SDへ結びます
	std::function<NativeError( std::uint64_t, std::wstring_view)>					  module ;
	/// 同原行を既媒体/固定SWENUM又は既HKR検査へ接続します
	std::function<NativeError( const SystemInfEffect &, bool)> legacyRegistry ;
	/// 正確なinbox serviceのreadonly安定config/SDを読みます
	SystemInfServiceReadFunction							  service ;
	/// 全旧/新registryと補助interfaceが共有する最大4096の累積です
	std::size_t												 *registryRows{} ;
	/// 元Include/Needs graphで既に消費した参照辺数です。追加型も合計4096へ拘束します
	std::size_t												  graphReferences{} ;
	/// 収集でINBOX署名と対応Storeの原文を確認したWindows sdbus.infのIDです。未指定と端末では0です
	std::uint64_t											  sdBusInboxDocument{} ;
	/// 収集のPorts選択で正規msports.infのINBOX署名・Store・同CATを確認した文書IDです。端末と未指定時は0です
	std::uint64_t											  msPortsInboxDocument{} ;
	/// 同じmsports.infのSerialEnumeratorとそのサービスだけを確認する場合true
	bool													  serialEnumeratorOnly{} ;
	/// 収集のNVMe選択で原署名・Store・CATを確認した正規stornvme.infです。PCIと同時に指定します
	std::uint64_t											  storNvmeInboxDocument{} ;
	/// 同じ選択のPciForceSBR.HWを所有する原署名・Store・CAT確認済みの正規pci.infです
	std::uint64_t											  pciNvmeInboxDocument{} ;
	/// 収集のAHCI選択で原署名・Store・CATを確認した正規mshdc.infです。端末と未指定時は0です
	std::uint64_t											  storAhciInboxDocument{} ;
	/// AHCIの除外IDと照合する元配布の全PnP IDです。読取中だけ借用します
	std::span<const std::wstring>							  ahciHardwareIds{} ;
	/// 到達後にINBOX署名とStoreの同一性を確認したnetvwifibus.infのIDです。該当しないときは0です
	std::uint64_t											  wifiBusInboxDocument{} ;
	/// 収集で署名とStoreの同一性を確認した正規winusb.infのIDです。該当しないときは0です
	std::uint64_t											  winUsbInboxDocument{} ;
} ;
/** @brief 一つのストレージ電源設定の元ValueRangeと既定値です */
struct RangedStoragePowerSetting {
	/// 同じ署名文書の参照先と親の選択節です
	SystemInfSection			  source ;
	/// 既存サブグループのGUIDです
	std::wstring				  subgroup ;
	/// 同節が定義する設定GUIDです
	std::wstring				  setting ;
	/// 元の表示名です。省略時は空です
	std::wstring				  displayName ;
	/// 元の説明です。省略時は空です
	std::wstring				  description ;
	/// 元の表示単位です。省略時は空です
	std::wstring				  unitLabel ;
	/// 明示された属性です。属性欄がなければ空です
	std::optional<std::uint32_t>  attributes ;
	/// 選択値の下限です。単位はunitLabelの元表記に従います
	std::uint32_t				  minimum{} ;
	/// 選択値の上限です
	std::uint32_t				  maximum{} ;
	/// 下限からの正の増分です
	std::uint32_t				  increment{} ;
	/// 高パフォーマンス・バランス・省電力の順に各AC/DCの元既定値を保持します
	std::array<std::uint32_t, 6U> defaults{} ;
	/**
	 * @brief 元の選択範囲、電源設定と既定値を独立した再読取り結果に照合する
	 * @param[in] other 同じ署名文書から確認した比較値
	 * @return 識別子・値域・既定値と省略を含む属性が一致する場合true
	 */
	bool operator==( const RangedStoragePowerSetting &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 選択DDInstallまたはそのHW節が参照したValueRange形式の電源設定を読み取ります
 * @param[in] selected 検証済み文書の選択節です。呼出し中だけ借用します
 * @param[in] api 同じ文書の読み取りと累積参照数です。現在端末の照会は使いません
 * @param[out] settings 全参照の成立時だけ元順に保持します。失敗時は空です
 * @return 全読取り成功0。未知形式、不一致、元読取り失敗はHRESULTです
 * @note 読取り結果は端末での既存値、変更先の所有、導入資格を表しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSelectedRangedStoragePowerSettings(
	const SystemInfSection &selected, const SystemInfEffectApi &api,
	std::vector<RangedStoragePowerSetting> &settings) ;

//------------------------------------------------------------------------------
/**
 * @brief 署名確認済みの標準NVMeの実選択とPCI依存節を照合して電源宣言を読む
 * @param[in] api 元のNVMe・PCI文書の異なるIDと同じ原バイトに対する同期の行読取り
 * @param[out] settings 全到達節と四つの電源宣言が成立した時だけ保持する元値。失敗時は空
 * @return 元作用と電源宣言が一致すれば0、元読取りや範囲の不成立はHRESULT
 * @note 元の署名、Needsの所有先の一意性、コピー実体と現在の構成は呼出側で照合する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readVerifiedNvmeInboxPowerSettings(
	const SystemInfEffectApi &api, std::vector<RangedStoragePowerSetting> &settings) ;

/** @brief 全行/参照/実体を消費した同選択の私有結果です */
struct SystemInfEffects {
	/// 元graphと追加型が消費した有限な参照辺数です
	std::size_t						   references{} ;
	/// 前方参照を含めて検査した全原作用です
	std::vector<SystemInfEffect>	   effects ;
	/// CopyFilesの元検査も必要な追加directive節です
	std::vector<SystemInfSection>	   copySections ;
	/// 必要だった既存inbox serviceの原安定証拠です
	std::vector<SystemServiceEvidence> services ;
	/// 上位フィルターの置換を宣言した元INBOX文書IDです。作用がなければ0です
	std::uint64_t					   wifiBusFilterDocument{} ;
	/// 固定SWENUM登録が実際に成立した場合だけtrueです
	bool							   delayedRegistration{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 同SYSTEM全参照を列挙後に型と実file/関係へ照合します
 * @param[in] seeds 同元graphで検証済みのSYSTEM選択節/文脈です
 * @param[in] api 同期中有効な全read/module/legacy/service操作です
 * @param[out] result 全成立時だけの不変作用です。失敗時は空です
 * @param[out] stage 最初の固定拒否地点です。任意本文を含みません
 * @param[out] observed 固定型/件数の補足です。GUID/値の転記はしません
 * @return 全成立0、元API error又は限定型の拒否HRESULTです
 * @note 一同期最大1024節/4096行/64 fieldで、registry/SCM/driverを変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSystemInfEffects( std::span<const SystemInfSection> seeds,
												  const SystemInfEffectApi		   &api,
												  SystemInfEffects &result, std::uint32_t &stage,
												  std::uint32_t &observed) ;
//------------------------------------------------------------------------------
/**
 * @brief 正確な既存kernel serviceの安定configと保守主体だけの変更権限を確認します
 * @param[in] name 同原SYSTEM文脈で検証された最大31文字のservice名です
 * @param[out] evidence 全成立時だけの安定config/SDです。失敗時は空です
 * @return 読取/保護成立0、元SCM/SD error又は不正/未知権限のHRESULTです
 * @note QUERY_CONFIG/READ_CONTROLだけで開き、SCM/registry/driverを変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSystemServiceEvidence( std::wstring_view	   name,
													SystemServiceEvidence &evidence) ;
//------------------------------------------------------------------------------
/**
 * @brief 固定の仮想Wi-Fiバスサービスの安定構成と表示名・説明の登録値を読み取ります
 * @param[out] evidence 全読取と保護の成立時だけの構成・SD・登録文字列です。失敗時は空です
 * @return 読取と保護の成立時0、元OSエラー又は不正構成のHRESULTです
 * @note 同梱文書と結合したサービスに使い、SCMと登録値を変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readWifiBusServiceEvidence( SystemServiceEvidence &evidence) ;
//------------------------------------------------------------------------------
/**
 * @brief 実SCMと内部fixtureが共有する安定config/元SDの閉じた安全条件を確認します
 * @param[in] evidence 全長を所有する原configとself-relative SDです
 * @return 型/全byte境界/保守主体限定変更が成立0、不正又は未知権限のHRESULTです
 * @note 任意serviceを探索せず、SDを適用しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateSystemServiceEvidence( const SystemServiceEvidence &evidence) ;

//------------------------------------------------------------------------------
/**
 * @brief exact storage serviceの原config/全SDだけを読取り専用で固定します
 * @param[in] name 同原選択又はDependenciesが示す最大256文字のservice名です
 * @param[out] evidence 全成立時だけ原値です。失敗/正式不存在時空です
 * @return 元読取/保護成立0、正式不存在又は元SCM/SDのHRESULTです
 * @note BOOT0/SYSTEM1/DEMAND3の原値を保持し、旧SYSTEM限定policyを変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readStorageServiceEvidence( std::wstring_view		name,
													 SystemServiceEvidence &evidence) ;

//------------------------------------------------------------------------------
/**
 * @brief 元選択の正確な補助サービスについてSCMの構成・状態・保護を読取ります
 * @param[in] name 同選択が指定する最大256文字のサービス名です
 * @param[out] snapshot 全読取時の私有観測です。明示不存在又はエラー時は空です
 * @return 完全な読取又はSCMの明示不存在で0、その他は元診断又は不正応答のHRESULTです
 * @note 同期処理です。監査読取のハンドル取得だけで保持特権を一時使用します
 * @see docs/adr/0569-selected-storage-auxiliary-services.md
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readAuxiliaryStorageServiceSnapshot(
	std::wstring_view name, std::optional<AuxiliaryStorageServiceSnapshot> &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 現用INFが指定するDisplayの補助サービスを保護付きで照会する
 * @param[in] name 元INFのサービス名。区切りを含まないASCII名と内部空白を許す
 * @param[out] snapshot 現用SCMの構成と保護。失敗時は空
 * @return 実在と保守主体だけの構成変更権を確認して0、失敗や不在はHRESULT
 * @note 現用サービスを起動、停止、変更しない。監査記述子の読取に既存の一時特権を使う
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDisplayAuxiliaryScmSnapshot(
	std::wstring_view name, AuxiliaryStorageServiceSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief storageだけのkernel1/Start0/1/3原configと保守主体限定SDを検査します
 * @param[in] evidence 同期所有する全原config/SDです
 * @return 全有限型/権限成立0、不明又は逸脱はHRESULTです
 * @note 現旧binary/configを提案新版へ一致させず、原値を書き換えません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateStorageServiceEvidence( const SystemServiceEvidence &evidence) ;
} // namespace drivercrate
