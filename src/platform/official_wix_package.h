//------------------------------------------------------------------------------
/**
 * @file official_wix_package.h
 * @brief 公式WiX v3配布内の検証済みMSIと規約を扱う
 * @version 01.02.01
 * @date 2026/11/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/23  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/23  全AMD64 MSIのドライバー内容閉包を比較する
 * Ver.01.02.00 Shunji Ogawa  2026/11/23  収集と端末で共用する非実行のWiX検査上限を定義
 * Ver.01.02.01 Shunji Ogawa  2026/11/23  EXE取得証拠を署名付き形式の共通型へ接続
 * </pre>
 *
 * @note 所有worker内で使う。検査済み元ファイルを保持し、MSI実行や規約同意の成立を表さない
 * @see docs/adr/0572-signed-wix-burn-driver-content.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_types.h"
#include "platform/official_cab.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"
#include "platform/official_msi.h"
#include "platform/official_sfx.h"
#include "platform/official_wix_manifest.h"
#include "platform/official_zip.h"

#include <cstdint>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief 同じ公式配布について内容役割と一時領域の用途を指定する
 */
struct OfficialWixPackageRequest {
	/// 検証済みの取得証拠から組み立てた元EXEと許可署名者
	OfficialSignedExecutableSource			   source ;
	/// 保護一時領域を元の検査へ結ぶ非ゼロ識別子
	ScanSessionId							   scanSessionId ;
	/// 現在のworkerが固定した検査用途
	OfficialWorkspaceMode					   workspaceMode ;
	/// 元Chainと同じ順序の全MSIの役割指定
	std::span<const OfficialWixMsiSelector>	   packages ;
	/// 表示に使う言語順の規約指定
	std::span<const OfficialWixMemberSelector> licenses ;
} ;

/**
 * @brief 元配布と展開へ適用する有限上限を保持する
 */
struct OfficialWixPackagePolicy {
	/// 元EXE全体と外側CABの格納長上限
	OfficialWixBurnInspectionPolicy bundle ;
	/// 個々の外側CABの内容と件数上限
	OfficialCabExtractionPolicy		cabinet ;
	/// ネイティブMSI検査へ渡す一件の元データベース上限
	std::uint64_t					maximumDatabaseBytes ;
} ;

/**
 * @brief マニフェストとMSI実値を照合した一件のデータベースを表す
 */
struct OfficialWixVerifiedDatabase {
	/// 保護領域内の再検証用の相対名、サイズ、SHA-256
	OfficialZipEntry		   file ;
	/// MSI Summary Informationで照合したプラットフォーム
	OfficialWixMsiArchitecture architecture ;
	/// MSI Summary Informationで照合した一件の言語ID
	std::uint16_t			   language ;
} ;

/**
 * @brief 署名付き元配布から検証したMSIと規約の保護領域を所有する
 */
struct OfficialWixPackageContent {
	/// 検査成功時だけ結果と共に保持する一時領域
	std::unique_ptr<OfficialDownloadWorkspace> workspace ;
	/// 元Chain順の全MSI
	std::vector<OfficialWixVerifiedDatabase>   databases ;
	/// 指定言語順の規約の原ファイル情報
	std::vector<OfficialZipEntry>			   licenses ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元EXEの署名に結び付く全MSIの原バイトと実属性および規約の原バイトを照合する
 * @param[in] request 元の取得証拠、元Chainと規約の指定、保護用途
 * @param[in] policy 元ファイル、外側CAB、各MSIの独立した有限上限
 * @param[out] content 全照合が成立した場合だけ移す所有結果。失敗時は空
 * @return 成功0、先に発生した構造、信頼、内容またはI/O失敗のHRESULT
 * @pre 呼出workerがCOMを初期化する
 * @note EXEとMSIは実行しない。共通INF閉包、CAT信頼、規約提示と同意は別途必要
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialWixPackageContent( const OfficialWixPackageRequest &request,
														   const OfficialWixPackagePolicy  &policy,
														   OfficialWixPackageContent &content) ;

/**
 * @brief 元MSIのFile keyと展開後の論理ファイル名を結ぶ
 */
struct OfficialWixDriverFile {
	/// 内側CABに格納された一要素のFile key
	std::wstring_view cabinetMember ;
	/// MSIのFileNameが明示する一要素のWindowsファイル名
	std::wstring_view targetName ;
} ;

/**
 * @brief 同一ドライバーを比較する元内側CABと明示OS用の内容を指定する
 */
struct OfficialWixDriverSelection {
	/// 元MSIのMediaで指定する埋込みCAB stream
	std::wstring_view					   streamName ;
	/// 順序を固定した対象OSのINF、CAT、全参照ファイルの対応
	std::span<const OfficialWixDriverFile> files ;
	/// filesに一意に含まれる元INF論理名
	std::wstring_view					   infName ;
} ;

/**
 * @brief 内側MSIとINF内容検査の有限上限と許可値を表す
 */
struct OfficialWixDriverPolicy {
	/// 元MSIのMediaとFile照会上限
	OfficialMsiCabinetInventoryPolicy inventory ;
	/// 元MSIから抽出する一つの埋込みCABの上限
	OfficialMsiStreamExtractionPolicy stream ;
	/// 埋込みCABの全項目とファイルの展開上限
	OfficialCabExtractionPolicy		  cabinet ;
	/// 選択したINFに適用する非実行の収集内容検査
	OfficialInfInspectionPolicy		  inf ;
	/// 一つの閉包へ展開して保持する合計byte数上限
	std::uint64_t					  maximumClosureBytes ;
} ;

/** @brief 同じWiX内容の外側とドライバーへ適用する共通検査条件です */
struct OfficialWixInspectionPolicy {
	/// 元署名EXE、外側CAB、各MSIへ適用する上限です
	OfficialWixPackagePolicy package ;
	/// 内側CABと非実行INFの内容検査に使う条件です
	OfficialWixDriverPolicy	 driver ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 収集と端末が同じWiXドライバー内容を読むための有限な検査条件を返します
 * @param[in] acceptedClasses 元配布のINFに適用する明示クラスです。呼出し側が検査終了まで所有します
 * @return 外側と内側の固定上限と、指定クラスだけの非実行INF検査条件です
 * @note Windowsの信頼確認と導入許可は別です。返却値はacceptedClassesの参照を保持します
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialWixInspectionPolicy makeOfficialWixInspectionPolicy(
	std::span<const std::wstring_view> acceptedClasses) noexcept ;

/**
 * @brief 規約と同じ元EXEから得たAMD64ドライバーの検査結果を所有する
 */
struct OfficialWixDriverContent {
	/// 外側の規約と同じ元配布の検査済みMSI
	OfficialWixPackageContent				   package ;
	/// 一致した全ドライバーファイルを保護して保持する領域
	std::unique_ptr<OfficialDownloadWorkspace> driverWorkspace ;
	/// 全AMD64で一致し、元CATに属する選択INFと全参照
	OfficialDriverClosure					   closure ;
	/// 元配布内で照合した全AMD64 MSIの件数
	std::size_t								   matchingDatabaseCount{} ;
	/// 通常経路でSetupAPIの同一INF・CAT照合まで成立した場合true。キャッシュ限定の内容確認ではfalse
	bool									   windowsInfPolicyVerified{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元WiX配布の全AMD64 MSIから同一の署名付きドライバー内容を分離する
 * @param[in] request 同じ公式EXE、元Chain、規約、保護用途
 * @param[in] packagePolicy 元EXEと外側CABに使う有限上限
 * @param[in] selection 内側の元stream、元File対応と対象INF
 * @param[in] driverPolicy 内側MSI、CAB、INFと閉包の上限およびClass等の条件
 * @param[out] content 全照合とCAT検査が成立した場合だけ移す結果。失敗時は空
 * @return 成功0、取得、署名、宣言、実内容が不成立の場合はHRESULT
 * @pre 呼出workerがCOMを初期化する
 * @note キャッシュ限定の内容確認から通常のWindows署名合格を発行しない
 * @note 規約同意、端末適用性、登録の作用、導入資格は別途検査する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialWixDriverContent(
	const OfficialWixPackageRequest &request, const OfficialWixPackagePolicy &packagePolicy,
	const OfficialWixDriverSelection &selection, const OfficialWixDriverPolicy &driverPolicy,
	OfficialWixDriverContent &content) ;

} // namespace drivercrate
