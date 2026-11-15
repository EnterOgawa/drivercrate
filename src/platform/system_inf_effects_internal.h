//------------------------------------------------------------------------------
/**
 * @file system_inf_effects_internal.h
 * @brief 同選択SYSTEM原文の型付き作用と不変tupleの内部契約です
 * @version 01.00.00
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
 * </pre>
 *
 * @note NativeLoaderが検証済みSYSTEM/INBOX/Storeの正確な選択だけを渡します。公開許可DTOではありません
 * @see docs/adr/0491-typed-system-needs-effects-and-complete-selection-qualification.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include <cstddef>
#include <cstdint>
#include <functional>
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
	/// 元display nameです
	std::wstring			  display ;
	/// 元owner/group/control/全DACLのself-relative snapshotです
	std::vector<std::byte>	  security ;
	/**
	 * @brief 原config安定fieldと元SDをfresh値へ完全比較します
	 * @param[in] other 同一serviceの独立したreadonly観測です
	 * @return 全field一致時trueです
	 */
	bool					  operator==( const SystemServiceEvidence &other) const = default ;
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
} ;
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
 * @brief 実SCMと内部fixtureが共有する安定config/元SDの閉じた安全条件を確認します
 * @param[in] evidence 全長を所有する原configとself-relative SDです
 * @return 型/全byte境界/保守主体限定変更が成立0、不正又は未知権限のHRESULTです
 * @note 任意serviceを探索せず、SDを適用しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateSystemServiceEvidence( const SystemServiceEvidence &evidence) ;
} // namespace drivercrate
