//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native_test_api.h
 * @brief 専用compileだけに存在する同期INF native API注入契約
 * @version 01.11.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  封印所有者のnative接続試験入口を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/13  専用compileのサービス出力契約回帰入口を追加
 * Ver.01.03.00 Shunji Ogawa  2026/10/15  専用compileのHKR設定と正確な文脈伝播回帰を追加
 * Ver.01.03.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.03.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.03.03 Shunji Ogawa  2026/11/13  Needs AddRegの元拒否leafを既匿名診断へ接続
 * Ver.01.03.04 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.03.05 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.04.00 Shunji Ogawa  2026/11/16  storage通常選択と完全native表の正負・原結果を検証
 * Ver.01.05.00 Shunji Ogawa  2026/11/20  共通原内容の再検証fixtureを同じAPI表に追加
 * Ver.01.06.00 Shunji Ogawa  2026/11/21  起動グループ順序を架空の完全APIへ追加
 * Ver.01.07.00 Shunji Ogawa  2026/11/24  無線バスの旧名転送の双方向照合を回帰
 * Ver.01.08.00 Shunji Ogawa  2026/11/24  USB Bluetoothの元参照照合を架空データから試験
 * Ver.01.09.00 Shunji Ogawa  2026/11/24  USB Bluetoothの保護コピー宣言の試験入口を追加
 * Ver.01.10.00 Shunji Ogawa  2026/11/24  USB BluetoothとPCIの機器設定宣言の試験入口を追加
 * Ver.01.11.00 Shunji Ogawa  2026/11/24  USB Bluetoothの共有作用照合の試験入口を追加
 * </pre>
 *
 * @note 製品にcompileしない。架空署名を導入許可や実署名の測定値へ変換しない
 * @see docs/adr/0271-compile-isolated-inf-native-api-tests.md
 */
//------------------------------------------------------------------------------

#pragma once
#ifndef DRIVERCRATE_INF_DEPENDENCY_TESTING
#error This header is restricted to the isolated INF dependency test target.
#endif

#include "platform/inf_dependency_native.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <cstdint>
#include <functional>
#include <span>
#include <string>

namespace drivercrate::test {
class TestContext ;
//------------------------------------------------------------------------------
/**
 * @brief 架空の元選択と解決済み依存辺で旧名転送の双方向照合を検証する
 * @param[in] selected 架空の元基本INFの選択と参照
 * @param[in] rootIdentity 架空の元基本INFの識別子
 * @param[in] edges 事前に解決済みの状態を試験入力とした架空graph
 * @return 元参照と旧名転送を一意に照合できた場合true
 * @note 署名とWindows由来はこの架空graph検査では認定しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchScopedWifiBusReferencesForTest( const OfficialInfInstallInventory &selected,
													   std::uint64_t rootIdentity,
													   std::span<const InfDependencyEdge> edges) ;

//------------------------------------------------------------------------------
/**
 * @brief USB Bluetoothの同梱INF間の参照を試験用の依存グラフで照合する
 * @param[in] edges 解決状態を与えた架空の全参照辺
 * @param[in] seeds 架空の元基本節、HW節、Services節をこの順に保持する一覧
 * @param[in] rootIdentity 架空の元INF識別子
 * @return 両同梱INFと用途ごとの八参照が一意に一致した場合true
 * @note 署名、Windows由来、参照先の作用はこの試験の対象外
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchScopedBluetoothUsbReferencesForTest(
	std::span<const InfDependencyEdge> edges, std::span<const std::wstring> seeds,
	std::uint64_t rootIdentity) ;

//------------------------------------------------------------------------------
/**
 * @brief 架空のUSB Bluetooth INFから保護コピーとSetupAPIの配備先を読み取る
 * @param[in] path 試験用領域内に作成済みの元INF
 * @param[in] driversDirectory SetupAPIの読み取り結果に要求する絶対ディレクトリ
 * @return コピー行と配備先が期待に一致して0、読取または構造不一致はHRESULT
 * @note INFを書き換えず、読み取ったコピーも実行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyBluetoothUsbCopyDeclarationForTest(
	const std::wstring &path, std::wstring_view driversDirectory) ;

//------------------------------------------------------------------------------
/**
 * @brief 架空のBluetoothとPCI INFから機器設定の元宣言を読み取る
 * @param[in] bluetoothPath 試験用領域内のBluetooth INF
 * @param[in] pciPath 試験用領域内のPCI INF
 * @return 両文書の機器相対作用が一致して0、読取・構造・型の不一致はHRESULT
 * @note 架空宣言だけを読む。署名、端末の現在値と導入時の処理順は検査しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyBluetoothUsbHardwareDeclarationsForTest(
	const std::wstring &bluetoothPath, const std::wstring &pciPath) ;

//------------------------------------------------------------------------------
/**
 * @brief 指定した試験用INFを同梱Bluetoothの共有作用比較に通す
 * @param[in] path 呼出し元が選んだ読取り専用の試験用INF
 * @return 元宣言の全件が一致して0、読取りや既知作用との不一致はHRESULT
 * @note これだけでは署名を確認しない。INFの内容やWindowsの設定を書き換えない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyBluetoothUsbSharedDeclarationsForTest( const std::wstring &path) ;

//------------------------------------------------------------------------------
/**
 * @brief 専用compileだけで実AddReg parserの全行と文脈拒否を検査します
 * @param[in] path 架空保護workspace内の実INFです
 * @param[in] contexts DDInstall/HW/未対応の既定bit集合です
 * @param[in,out] registryRows 元累積予算です
 * @param[in,out] diagnostic 任意の元pair診断です。合否の入力に使いません
 * @return 実parserの元HRESULTです。署名・由来・device適合の認定ではありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectNeedsAddRegForTest(
	const std::wstring &path, unsigned char contexts, std::size_t &registryRows,
	RequiredInfBindingDiagnostic *diagnostic = nullptr) ;
//------------------------------------------------------------------------------
/**
 * @brief 元選択からの正確なNeeds文脈伝播を架空graphで確認します
 * @param[in] result 架空の元graphです。導入能力を持ちません
 * @param[in] seeds 元rootの基本節と付随節です
 * @param[in] rootIdentity 架空の元document identityです
 * @return 元sectionsと同順の文脈bit集合です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<unsigned char> inspectNeedsRegistryContextsForTest(
	const InfDependencyNativeResult &result, std::span<const std::wstring> seeds,
	std::uint64_t rootIdentity) ;

//------------------------------------------------------------------------------
/**
 * @brief 有効な実INFでサービス集合の正常終端と途中失敗の出力契約を直接確認します
 * @param[in,out] context 同期中だけ借用する試験集計です
 * @note 列挙障害だけを専用翻訳単位で注入し、製品API・設定・実導入を追加しません
 */
//------------------------------------------------------------------------------
void runOfficialServiceOutputContractTests( TestContext &context) ;

/** @brief 固定CATとINF memberを同期借用し元診断を返す専用callback型 */
using InfDependencyCatalogTestFunction =
	std::function<NativeError( const std::wstring &, std::span<const std::wstring>)> ;
/** @brief 一同期runで借用する架空API。0以外は元HRESULTを保持する */
struct InfDependencyNativeTestApi {
	/// 初回と終了時のOS情報。未知product typeの検査は実adapterに委譲する
	std::function<NativeError( OSVERSIONINFOEXW &, SYSTEM_INFO &)>			   version ;
	/// 有限な架空Windows directory。path検査は実adapterに委譲する
	std::function<NativeError( std::wstring &)>								   windowsDirectory ;
	/// INF自身の架空署名応答。CAT固定とscore照合は実adapterに委譲する
	std::function<NativeError( const std::wstring &, SP_INF_SIGNER_INFO_W &)>   infSignature ;
	/// CATとINF memberの架空署名。実signatureではない
	InfDependencyCatalogTestFunction										   catalogSignature ;
	/// 現OSの架空Store対応位置。実fileのhashはadapterで計算する
	std::function<NativeError( const std::wstring &, std::wstring &)>		   driverStore ;
	/// 任意の属性API注入。空の場合は実属性APIを必ず呼ぶ
	std::function<NativeError( HANDLE, FILE_ATTRIBUTE_TAG_INFO &)>			   attributes ;
	/// 標準SYSTEM登録だけの完全な元helper/CAT期待です。空の場合は作用拒否です
	std::function<NativeError( const std::wstring &, WindowsSystemFileTrust &)> systemFileTrust ;
	/// storageだけの現kernel証拠です。空なら実SCMへfallbackしません
	std::function<NativeError( std::wstring_view, SystemServiceEvidence &)>	   storageService ;
	/// 正式メディアチェンジャーに必要な架空の起動グループ順序
	std::function<NativeError( StorageLoadOrder &)>							   storageLoadOrder ;
	/// 必要な正確なinbox serviceの安定証拠です。空なら実SCMへfallbackしません
	std::function<NativeError( std::wstring_view, SystemServiceEvidence &)>	   systemService ;
	/// 専用fixtureの共通原内容再検証です。空なら既存の製品関数を使います
	std::function<NativeError( const CommonInfInspection &)>					   reverifyCommonInf ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief このthreadの一同期呼出しにだけ架空APIを結合する
 * @param[in] api 必須五callbackと任意属性callback。呼出し終了まで生存し再入しない
 * @param[in] workspace 架空fileの所有領域
 * @param[in] members 閉じたINF一覧
 * @param[in] rootIndex 開始member
 * @param[in] seeds 明示節群
 * @param[in] observationId 非零の架空run
 * @param[out] result 全再確認成功時だけ保持し、失敗時は空
 * @return 内部観測0、不完全API・再入・例外またはadapterの失敗HRESULT
 * @note 製品buildにはこの関数もthread-local slotも含めない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectInfDependenciesWithTestApi(
	const InfDependencyNativeTestApi &api, const OfficialDownloadWorkspace &workspace,
	std::span<const InfDependencyPackageMember> members, std::size_t rootIndex,
	std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result) ;

//------------------------------------------------------------------------------
/**
 * @brief 封印所有者の同期入口へ専用APIを借用する。実取得・署名を認定しない
 * @param[in] api 必須五callbackと任意属性callback。同期呼出し中だけ生存する
 * @param[in] binding 架空取得から作った封印所有者
 * @param[in] session 架空取得の生存issuer
 * @param[in] archiveWorkspace 架空原取得領域
 * @param[in] rootIndex 開始INF位置
 * @param[in] seeds 明示節群
 * @param[in] observationId 非零の架空run世代
 * @param[out] result 全成功時だけのsnapshot。失敗時は空
 * @return 完了0、不完全API・再入・境界・例外のHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectAcquiredInfDependenciesWithTestApi(
	const InfDependencyNativeTestApi &api, const OfficialInfArchiveBinding &binding,
	const OfficialAcquisitionSession &session, const OfficialDownloadWorkspace &archiveWorkspace,
	std::size_t rootIndex, std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result) ;
} // namespace drivercrate::test
