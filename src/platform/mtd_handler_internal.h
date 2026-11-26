//------------------------------------------------------------------------------
/**
 * @file mtd_handler_internal.h
 * @brief 指定導入に関与するクラスと端末の登録を型付きで観測する
 * @version 01.03.00
 * @date 2026/11/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/17  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/19  独自クラスの登録と端末の作用の読み取りを追加
 * Ver.01.02.00 Shunji Ogawa  2026/11/19  導入直前に対象の登録と既存作用を比較
 * Ver.01.03.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの選択端末の上位フィルター観測を追加
 * </pre>
 *
 * @note 読取り専用です。登録値を実行許可へ変換しません
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace drivercrate {
/** @brief host handler propertyの有限な原観測です */
enum class MtdHandlerState : std::uint32_t {
	/// 正式ERROR_NOT_FOUNDです
	ABSENT,
	/// 正式な空STRING_LISTです
	EMPTY_LIST,
	/// 型付きの非空登録があります
	PRESENT,
	/// 型/全byte/終端が不正です
	INVALID,
	/// 読取り又は権限が失敗しました
	FAILED,
	/// 終端だけの型付きSTRINGです
	EMPTY_STRING,
} ;
/** @brief 一つのhandler propertyの原観測です */
struct MtdHandlerProperty {
	/// 正式不在、空、登録、不正又は読取失敗です
	MtdHandlerState		   state{MtdHandlerState::FAILED} ;
	/// 直後のWindows error又は固定検査errorです
	std::uint32_t		   error{} ;
	/// OSが返した元DEVPROPTYPEです
	std::uint32_t		   type{} ;
	/// 成功したpropertyの全原byteです
	std::vector<std::byte> bytes ;
	/**
	 * @brief 同propertyを直前の独立観測と比較します
	 * @param[in] other 同対象の再観測です
	 * @return 状態と全raw byteが一致する場合trueです
	 */
	bool				   operator==( const MtdHandlerProperty &other) const = default ;
} ;
/** @brief 同MTD classとdeviceに参加する全handler propertyです */
struct MtdHandlerObservation {
	/// setup class Installer32です
	MtdHandlerProperty classInstaller ;
	/// 同classのCoDeviceInstallers値です
	MtdHandlerProperty classCoInstallers ;
	/// 同device software keyのCoInstallers32です
	MtdHandlerProperty deviceCoInstallers ;
	/**
	 * @brief 同handler集合の全原値を直前再観測と比較します
	 * @param[in] other 同class/deviceの再観測です
	 * @return 全propertyが一致する場合trueです
	 */
	bool			   operator==( const MtdHandlerObservation &other) const = default ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 同MTD class/deviceの登録handlerを読み既知空だけを許します
 * @param[in] set 同一deviceを含む所有集合です
 * @param[in,out] device 同一選択の元deviceです
 * @param[out] observation 不在/空/登録/不正/読取失敗を保持します
 * @return 全propertyが正式不在又は空listなら0、それ以外は最初のHRESULTです
 * @note 欠損fake slotからnativeへfallbackせず、registryやdeviceを変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectMtdHandlers( HDEVINFO set, SP_DEVINFO_DATA &device,
											 MtdHandlerObservation &observation) ;

/** @brief 両方向の名前照会とクラスキーで確認した登録状態 */
enum class SetupClassRegistration {
	/// 初期状態または照会未完了
	UNOBSERVED,
	/// 対象クラスのキーと名前が未登録
	UNREGISTERED,
	/// 対象クラスの名前とGUIDが一致
	REGISTERED,
} ;

/** @brief 独自クラスの指定導入で再確認する端末とクラスの登録内容 */
struct DeclarativeClassEffects {
	/// 対象INFのクラスの登録状態
	SetupClassRegistration registration{SetupClassRegistration::UNOBSERVED} ;
	/// 照会対象の端末が現在持つクラスGUID
	GUID				   sourceClass{} ;
	/// 対象クラスのInstaller32
	MtdHandlerProperty	   classInstaller ;
	/// クラスキー外の対象GUIDに対応するコインストーラー
	MtdHandlerProperty	   classCoInstallers ;
	/// 対象クラスのプロパティページ
	MtdHandlerProperty	   classPropPage ;
	/// 対象クラスの上位フィルター
	MtdHandlerProperty	   classUpperFilters ;
	/// 対象クラスの下位フィルター
	MtdHandlerProperty	   classLowerFilters ;
	/// 端末のドライバーに登録済みのコインストーラー
	MtdHandlerProperty	   deviceCoInstallers ;
	/// 端末のドライバーに登録済みのプロパティページ
	MtdHandlerProperty	   devicePropPage ;
	/// 端末の上位フィルター
	MtdHandlerProperty	   deviceUpperFilters ;
	/// 端末の下位フィルター
	MtdHandlerProperty	   deviceLowerFilters ;
	/**
	 * @brief 同じ元端末と対象クラスの読取り結果を比較する
	 * @param[in] other 再確認した同じ端末と対象クラスの観測
	 * @return 登録状態、元端末クラス、プロパティの状態と値が一致する場合true
	 */
	bool				   operator==( const DeclarativeClassEffects &other) const = default ;
} ;

/** @brief 同じPnP端末のプロパティを読み取るSetupAPIの関数型です */
using DevicePropertyRead = decltype( &SetupDiGetDevicePropertyW) ;

/** @brief 独自クラスの登録を読み取る完結したWindows API表 */
struct SetupClassReadApi {
	/// 対象GUIDからクラス名を取得する
	decltype( &SetupDiClassNameFromGuidW)  className{} ;
	/// 同名の登録済みGUIDを取得する
	decltype( &SetupDiClassGuidsFromNameW) classGuids{} ;
	/// 既存クラスキーを読み取りで開く
	decltype( &SetupDiOpenClassRegKeyExW)  openClassKey{} ;
	/// 対象クラスの既存プロパティを取得する
	decltype( &SetupDiGetClassPropertyW)	  classProperty{} ;
	/// 元端末の既存プロパティを取得する
	DevicePropertyRead					  deviceProperty{} ;
	/// クラスキー外のコインストーラーキーを読み取りで開く
	decltype( &RegOpenKeyExW)			  openKey{} ;
	/// 同クラスのコインストーラー値を取得する
	decltype( &RegQueryValueExW)			  readValue{} ;
	/// 読み取り専用キーを閉じる
	decltype( &RegCloseKey)				  closeKey{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 対象クラスと選択端末の登録状態を指定導入の評価用に読み取る
 * @param[in] set 選択端末を含む情報集合
 * @param[in,out] device 一覧構築前の選択端末
 * @param[in] targetClass 元INFが宣言する対象クラスGUID
 * @param[in] expectedName 元INFが宣言する対象クラス名
 * @param[in] api 読取りだけの完全なWindows API表
 * @param[out] observation 登録状態と効果の型付き観測。失敗時は空
 * @return 正常観測時は0、照会失敗、矛盾、または不正な型はHRESULT
 * @note 既存の非空値は元の観測として保持し、ここでは導入可否を決めない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError observeDeclarativeClassEffects( HDEVINFO set, SP_DEVINFO_DATA &device,
														 const GUID				 &targetClass,
														 const std::wstring		 &expectedName,
														 const SetupClassReadApi &api,
														 DeclarativeClassEffects &observation) ;
//------------------------------------------------------------------------------
/**
 * @brief 単一の仮想Wi-Fiバスへ置換しても別フィルターを失わない端末の原値を保持する
 * @param[in] set 確認中の端末を含む有効なdevice情報集合です
 * @param[in,out] device 実選択した端末を示すSetupAPIの元情報です
 * @param[in] property 同じAPI表の端末プロパティ読取りです
 * @param[out] observed 成功時の存在状態・型・全raw byteです。失敗時は空です
 * @return 正式不存在、型付き空、または単一vwifibusで0です。それ以外はHRESULTです
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError observeWifiBusUpperFilters( HDEVINFO set, SP_DEVINFO_DATA &device,
													 DevicePropertyRead	 property,
													 MtdHandlerProperty &observed) ;
} // namespace drivercrate
