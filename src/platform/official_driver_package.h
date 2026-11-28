//------------------------------------------------------------------------------
/**
 * @file official_driver_package.h
 * @brief 公式標準INF driver package検証定義
 * @version 01.72.00
 * @date 2026/09/03
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member／PnP照合追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  DriverVer日付取得追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  INF signature allowlist追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  参照file埋込み署名検証追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用Provider名検証mode追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要printer構造policy追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  選択的driver閉包policy追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows検証済みsignerの共通署名policyを追加
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  明示依存の存在観測を内容署名から分離
 * Ver.01.03.00 Shunji Ogawa  2026/10/04  無作用の空CoInstaller参照の限定受理を明記
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  保守専用の非実行参照棚卸しを導入構造と分離
 * Ver.01.05.00 Shunji Ogawa  2026/10/05  保守相対参照の先頭現在directory解決を明記
 * Ver.01.05.01 Shunji Ogawa  2026/10/05  空source時もINF自身のCAT member検証を要求する
 * Ver.01.06.00 Shunji Ogawa  2026/10/05  保守棚卸しの両標準INF識別子受理を明記
 * Ver.01.07.00 Shunji Ogawa  2026/10/05  保守内容限定の非圧縮EXE参照policyを追加
 * Ver.01.08.00 Shunji Ogawa  2026/10/05  選択導入処理の非実行作用・参照棚卸しを追加
 * Ver.01.09.00 Shunji Ogawa  2026/10/05  棚卸し専用の節・作用・参照容量の有限拡張を明記
 * Ver.01.10.00 Shunji Ogawa  2026/10/06  選択処理の未解釈範囲を非許可の不足観測へ分離
 * Ver.01.11.00 Shunji Ogawa  2026/10/07  保守専用の全Models構造とnull service・独立状態を追加
 * Ver.01.12.00 Shunji Ogawa  2026/10/07  明示seedの有限file参照と位置未確定の独立観測を追加
 * Ver.01.12.01 Shunji Ogawa  2026/10/07  named必須構造とnullの診断説明を整合
 * Ver.01.12.02 Shunji Ogawa  2026/10/07  展開済みbinaryのnamed固有導入先とsource限定照合を明記
 * Ver.01.12.03 Shunji Ogawa  2026/10/07  相対named13の元source位置と実Store／端末未確認の分離を明記
 * Ver.01.13.00 Shunji Ogawa  2026/10/13  元INFの必要構成と役割別関係の有限契約を追加
 * Ver.01.14.00 Shunji Ogawa  2026/10/13  私有node選択節と全潜在importの内容集合を分離
 * Ver.01.14.01 Shunji Ogawa  2026/10/13  必要SWC serviceの同INF参照許可と保守包括EXE policyを区別
 * Ver.01.15.00 Shunji Ogawa  2026/10/13  選択Needsの同HINF元source位置の読取契約を公開
 * Ver.01.16.00 Shunji Ogawa  2026/10/14  元Models/ID種別/ClassGUIDの非許可公開receiptを追加
 * Ver.01.17.00 Shunji Ogawa  2026/10/14  同Windows INF/CAT検査から実publisherの非許可metadataを追加
 * Ver.01.18.00 Shunji Ogawa  2026/11/03  標準Componentの原コピーとType1・System device serviceの境界を明記
 * Ver.01.19.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.20.00 Shunji Ogawa  2026/11/05  同INF付属内容と未評価Type1作用の境界を明記
 * Ver.01.21.00 Shunji Ogawa  2026/11/06  Windows管理driver付属DATAと原source位置の非実行読取を分離
 * Ver.01.22.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.23.00 Shunji Ogawa  2026/11/10  明示client targetと同INF hashのModels観測を結合
 * Ver.01.23.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.23.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.23.03 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.24.00 Shunji Ogawa  2026/11/15  非実行storage内容と必須null importを通常導入資格から分離
 * Ver.01.25.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.26.00 Shunji Ogawa  2026/11/16  選択storageの原Class対を同一factsに保持
 * Ver.01.27.00 Shunji Ogawa  2026/11/17  選択MTDの原COPY行とmember型を追加
 * Ver.01.27.01 Shunji Ogawa  2026/11/17  標準TapeDriveのClass名とGUIDの一意対を明記
 * Ver.01.28.00 Shunji Ogawa  2026/11/17  宣言Server scopeとpolicy・Models・identityを分離接続
 * Ver.01.29.00 Shunji Ogawa  2026/11/18  CopyINF由来の限定registry-only内容と通常導入拒否を分離
 * Ver.01.30.00 Shunji Ogawa  2026/11/19  収集元のプロパティページDLLと原callbackの照合要求を保持
 * Ver.01.31.00 Shunji Ogawa  2026/11/19  表示用の独自クラスを内容検査専用の結果に分離
 * Ver.01.32.00 Shunji Ogawa  2026/11/19  AMD64媒体表に共通の有効行を含める読取を追加
 * Ver.01.33.00 Shunji Ogawa  2026/11/19  端末の選択Models行を元署名INFへ読み取り照合
 * Ver.01.34.00 Shunji Ogawa  2026/11/19  現在OSが選ぶ元クラス登録の表示情報を保持
 * Ver.01.35.00 Shunji Ogawa  2026/11/20  収集の非実行作用調査の追加枠を明記
 * Ver.01.36.00 Shunji Ogawa  2026/11/20  収集でWindows標準INFへ委譲する元選択節を保持
 * Ver.01.37.00 Shunji Ogawa  2026/11/20  Windows標準Portsへ委譲する収集元プロパティページ節を保持
 * Ver.01.38.00 Shunji Ogawa  2026/11/20  標準NVMeを参照する収集元の空ファイル一覧を保持
 * Ver.01.39.00 Shunji Ogawa  2026/11/20  収集用メディアチェンジャーの署名と保護資源の確認を明記
 * Ver.01.40.00 Shunji Ogawa  2026/11/21  元SYSを持つHDCの収集検査対象を保持
 * Ver.01.41.00 Shunji Ogawa  2026/11/21  元SYSを持つHDCの導入節を収集と端末で共有
 * Ver.01.42.00 Shunji Ogawa  2026/11/21  自己媒体Portsの元選択と標準ページの登録を保持
 * Ver.01.43.00 Shunji Ogawa  2026/11/22  公式配布対象に結ぶModels全行の読取り証拠を追加
 * Ver.01.44.00 Shunji Ogawa  2026/11/22  元CAT所属を確認した収集INFだけにModelsの別計数を接続
 * Ver.01.45.00 Shunji Ogawa  2026/11/22  公式対象に結ぶ導入セクションの棚卸しを追加
 * Ver.01.46.00 Shunji Ogawa  2026/11/22  公式Net対象のイベントファイルの確認件数を追加
 * Ver.01.47.00 Shunji Ogawa  2026/11/22  元Modelsの有限枠を収集専用の原証拠と共用
 * Ver.01.48.00 Shunji Ogawa  2026/11/22  Windows選択nodeと一意な公式Models行の読取契約を追加
 * Ver.01.49.00 Shunji Ogawa  2026/11/22  公式Modelsの同じ行と実導入節の必要関係を結合
 * Ver.01.50.00 Shunji Ogawa  2026/11/22  公式Netの実選択作用とWindows標準DLLの証拠を保持
 * Ver.01.51.00 Shunji Ogawa  2026/11/22  公式収集の同梱Needsの元証拠を棚卸しに接続
 * Ver.01.52.00 Shunji Ogawa  2026/11/22  同梱Needsの検査結果を一つの元選択に保持
 * Ver.01.53.00 Shunji Ogawa  2026/11/22  実選択で確認した元SYSと付随媒体の全バイトを保持
 * Ver.01.54.00 Shunji Ogawa  2026/11/22  元直接CABの閉包確認を公式範囲の読取りへ結合
 * Ver.01.55.00 Shunji Ogawa  2026/11/22  選択SCSIAdapterの要求時起動補助サービス原行を保持
 * Ver.01.56.00 Shunji Ogawa  2026/11/23  ストレージ補助サービスの直接コピーとSystemイベント表記を定義
 * Ver.01.57.00 Shunji Ogawa  2026/11/23  ストレージの同梱INFへの空ドライバー委譲を元選択へ限定
 * Ver.01.58.00 Shunji Ogawa  2026/11/23  空ドライバー委譲を現在Modelsとノードの完全ID列に照合
 * Ver.01.59.00 Shunji Ogawa  2026/11/23  同じ選択が置く名前付きイベント資源の元コピーを保持
 * Ver.01.60.00 Shunji Ogawa  2026/11/23  ストレージの実選択を固定した元INFの現在Modelsに照合
 * Ver.01.60.01 Shunji Ogawa  2026/11/24  公式USB Bluetoothの同梱Needs入力の契約を明記
 * Ver.01.61.00 Shunji Ogawa  2026/11/24  混在シリアル媒体の元参照を私有収集へ分離
 * Ver.01.62.00 Shunji Ogawa  2026/11/24  収集専用クラス登録の元INFハッシュを保持
 * Ver.01.63.00 Shunji Ogawa  2026/11/24  同梱WinUSBの選択に属する元機器登録節を保持
 * Ver.01.64.00 Shunji Ogawa  2026/11/24  収集専用の共有Ports標準ページと元媒体を保持
 * Ver.01.65.00 Shunji Ogawa  2026/11/24  独自クラスの単一KMDF元媒体の収集用照合を追加
 * Ver.01.66.00 Shunji Ogawa  2026/11/27  必須SoftwareComponentの元Models選択契約を追加
 * Ver.01.67.00 Shunji Ogawa  2026/11/27  Display補助サービスの原構文証拠と読取契約を追加
 * Ver.01.68.00 Shunji Ogawa  2026/11/27  現用Displayの補助宣言と全イベント値を読取
 * Ver.01.69.00 Shunji Ogawa  2026/11/27  現用親の子宣言と子の実Models選択を照合
 * Ver.01.70.00 Shunji Ogawa  2026/11/27  必須SoftwareComponentのType 1元宣言と元実行物を保持
 * Ver.01.71.00 Shunji Ogawa  2026/11/27  必須SoftwareComponentの共有コピー元と指定先を保持
 * Ver.01.72.00 Shunji Ogawa  2026/11/27  Type 1の独立版を確認済みの元選択と再照合
 * </pre>
 *
 * @note 保護workspaceへ展開済みの標準INF packageを、現在のWindows x64に対する構造、適用ID、参照fileおよびcatalog署名の境界で検証します
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include "core/official_driver_rank.h"
#include "platform/inf_dependency_plan.h"
#include "platform/official_file_verifier.h"
#include "platform/official_zip.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
struct RequiredInfBindingDiagnostic ;

class OfficialDownloadWorkspace ;

/** @brief collectorの有限なModels metadata観測点です。導入許可を持ちません */
struct OfficialInfModelsPlatform {
	/// Windows majorです
	std::uint32_t majorVersion{10U} ;
	/// Windows minorです
	std::uint32_t minorVersion{} ;
	/// 明示buildです
	std::uint32_t buildNumber{} ;
	/// AMD64だけを採用します
	std::uint16_t processorArchitecture{9U} ;
	/// 明示観測はclient=1/DC=2/Server=3です。現host分類や導入許可ではありません
	std::uint8_t  productType{1U} ;
	/// 今回はsuite0です
	std::uint16_t suiteMask{} ;
	/**
	 * @brief 全target fieldを比較します
	 * @param[in] other 比較対象です
	 * @return 全field一致時trueです
	 */
	bool		  operator==( const OfficialInfModelsPlatform &other) const = default ;
} ;

/** @brief Windowsが選択した一Models節の公開IDだけを保持します */
struct OfficialInfPublishedModelSection {
	/// 原HINFが返したModels節名です。端末選択nodeではありません
	std::wstring			  modelSection ;
	/// 各Models行の第2 fieldに明示された公開Hardware IDです
	std::vector<std::wstring> hardwareIds ;
	/// 各Models行の第3 field以降に明示された公開Compatible IDです
	std::vector<std::wstring> compatibleIds ;
} ;

/** @brief 同INF原hash/Models/ClassGUIDの読取り結果です。署名や取得/導入許可を持ちません */
struct OfficialInfPublishedIdentity {
	/// 同INFの前後読取りで一致した小文字SHA-256です
	std::wstring								  infSha256 ;
	/// Versionの原ClassGUIDです。推測や端末情報を使いません
	std::wstring								  classGuid ;
	/// 最大128節の指定OS（未指定時は現OS）選択結果です。空/部分失敗を公開しません
	std::vector<OfficialInfPublishedModelSection> models ;
} ;

/** @brief 元ModelsのHardware欄にある公式配布対象の一つです */
struct OfficialInfScopedModelMatch {
	/// 元Models内の1から始まる行位置です
	std::uint32_t modelRow{} ;
	/// Windowsが展開した元Hardware IDです
	std::wstring  hardwareId ;
	/// 同じ元行の基本導入節名です
	std::wstring  installBase ;
} ;

/** @brief Windowsが選択した一Models節の全行の証拠と公式配布対象です */
struct OfficialInfScopedModelsSection {
	/// Manufacturerが宣言した実在の節名です
	std::wstring							 modelSection ;
	/// 型付きフィールドの読み取りを完了した元行数です
	std::uint32_t							 modelRows{} ;
	/// HardwareとCompatibleの種別を合わせた延べ元IDフィールド数です
	std::uint32_t							 idFields{} ;
	/// 基本導入節と型付きIDの全行を順序付きで固定した小文字SHA-256です
	std::wstring							 orderedRowsSha256 ;
	/// この節に一意に見つかった公式Hardware IDです。元行順を保持します
	std::vector<OfficialInfScopedModelMatch> matches ;
} ;

/** @brief 全読取りに成功した一つのINFの配布対象証拠です。署名や導入許可を表しません */
struct OfficialInfScopedModelsEvidence {
	/// 読取り前後に確認した元INFの小文字SHA-256です
	std::wstring								infSha256 ;
	/// Models選択に明示したOSです。空は現在OSです
	std::optional<OfficialInfModelsPlatform>	platform ;
	/// 公式対象を持たない節も含む、同じOSのWindows選択節です
	std::vector<OfficialInfScopedModelsSection> sections ;
} ;

/// 元INFと収集専用原証拠で共通に使うWindows選択節の上限
inline constexpr std::size_t   OFFICIAL_SCOPED_MODELS_MAX_SECTIONS = 128U ;
/// 選択節の合計行数の上限
inline constexpr std::uint32_t OFFICIAL_SCOPED_MODELS_MAX_ROWS = 16'384U ;
/// 全行のHardware／Compatible IDフィールド合計の上限
inline constexpr std::uint32_t OFFICIAL_SCOPED_MODELS_MAX_ID_FIELDS = 65'536U ;
/// 同じ公式応答の全対象ID数の上限
inline constexpr std::size_t   OFFICIAL_SCOPED_MODELS_MAX_TARGETS = 512U ;

/** @brief 同じ公式配布の選択INFだけに使う収集時の読取り要求です */
struct OfficialInfScopedModelsRequest {
	/// 明示OSです。nullは現在OSだけを示します
	const OfficialInfModelsPlatform *platform{} ;
	/// 同じ公式明細で確認した完全Hardware IDの全件です
	std::span<const std::wstring>	 hardwareIds ;
	/// 収集閉包では実元INFを展開した時点のハッシュへ固定する値です
	std::wstring_view				 infSha256 ;
	/// 同じarchiveの同期workerからの取消し照会です
	const std::function<bool()>		*cancellation{} ;
	/// 選択INFが指定した同配布内の元CATのハッシュです
	std::wstring_view				 catalogSha256 ;
	/// 閉包抽出中に元入力が直接CABだと確認した場合だけtrueです
	bool							 sameDirectCabinet{} ;
} ;

/** @brief Windows互換nodeが選ぶ元Models行の作用区分 */
enum class OfficialInfSelectedModelRole {
	/// 検査を完了していない
	UNASSESSED,
	/// 実ファイルを使用しない明示的な空サービス
	NULL_DRIVER,
	/// 同じ元コピーに結合したカーネルサービスを含む行
	KERNEL_DRIVER,
} ;

/** @brief INF構造検査の用途です。内容用途は導入資格へ変換しません */
enum class OfficialInfInspectionPurpose {
	/// 従来の通常driver構造検査です。既存Class policyを維持します
	STANDARD_DRIVER,
	/// collectorが明示選択した非実行内容だけです
	COLLECTOR_CONTENT,
	/// 同内容閉包のCopyINFから到達した必須importだけです
	REQUIRED_COLLECTOR_IMPORT,
	/// appが明示選択した元archiveをADMIN領域で独立再検査する用途です。導入権限ではありません
	DEVICE_STORAGE_CANDIDATE,
	/// 同storage原CopyINFから到達した必須importです。独立候補にはなりません
	REQUIRED_STORAGE_IMPORT,
	/// 端末で表示用の独自クラス登録を確認した内容結果です。導入計画に使用しません
	DECLARATIVE_CLASS_CONTENT,
} ;

/**
 * @brief 標準INF packageの構造検証上限と許可値を表す
 */
struct OfficialInfInspectionPolicy {
	/// 一INFから保持するPnP ID数上限
	std::size_t						   maximumHardwareIds ;
	/// 一INFから保持する参照file数上限
	std::size_t						   maximumSourceFiles ;
	/// 許可するINF class名群
	std::span<const std::wstring_view> acceptedClasses ;
	/// 許可するINF Provider名群
	std::span<const std::wstring_view> acceptedProviders ;
	/// 許可するVersion Signature値群
	std::span<const std::wstring_view> acceptedSignatures ;
	/// trueの場合はCATで保護された非空Provider名を受理し、allowlistを使用しない
	bool							   acceptAnyProvider{} ;
	/// trueの場合は一つ以上のSYS参照を必須にする
	bool							   requireDriverBinary{true} ;
	/// trueの場合はINFが参照しないprogramもarchive全体のpolicy違反とする
	bool							   rejectUnreferencedPrograms{true} ;
	/// trueは任意command実行・外部登録を拒否します。必要構成modeだけで同INFへ結合したCoInstaller内容を検査します
	bool							   rejectInstallActions{} ;
	/// trueの場合は未解決のInclude／Needs／AddComponentを方式未対応として拒否する
	bool							   rejectExternalDependencies{} ;
	/// trueは非実行内容検査の元EXE/MSI/CAB参照です。実行作用や導入許可は別の検査を必要とします
	bool							   allowReferencedExecutablesForContent{} ;
	/// trueは元CopyINF/AddComponent・必要Type1/コピー・device serviceとCoInstallerを有限解析します。導入許可ではありません
	bool							   allowRequiredDriverComponents{} ;
	/// trueは既知script/program参照も内容DATAとして検査します。実行とdriver scopeの合格を意味しません
	bool							   allowWindowsManagedDriverDataForContent{} ;
	/// 非実行内容と必須importだけの追加形式を通常導入policyから分離します
	OfficialInfInspectionPurpose	   purpose{OfficialInfInspectionPurpose::STANDARD_DRIVER} ;
	/// 審査済みシリアル媒体を受け取る私有収集の基本INFだけでtrue
	bool							   collectorSerialMedia{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元INFの全現在architecture source相対位置を非実行で読み取ります
 * @param[in] workspace 元INFを保持する保護領域です
 * @param[in] infRelativePath 同領域内の元INF相対位置です
 * @param[in] maximumFiles 元sourceの有限件数上限です
 * @param[out] paths 全成功時だけ同INF/同媒体に結合する安全相対pathです。失敗時は空です
 * @param[in] includeCommonFallback AMD64専用表から解決できない共通媒体行も列挙する場合true
 * @return 全取得成功0、欠損・過長・不正位置・容量超過のHRESULTです
 * @note 原圧縮sourceの探索準備だけです。実byte/CAT/導入可能性の証明ではありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialInfSourcePaths( const OfficialDownloadWorkspace &workspace,
													 std::wstring_view			infRelativePath,
													 std::size_t				maximumFiles,
													 std::vector<std::wstring> &paths,
													 bool includeCommonFallback = false) ;

//------------------------------------------------------------------------------
/**
 * @brief 同元CopyINFの内容検査用ClassをWindows readerから読みます
 * @param[in] workspace 原INFを所有する保護領域です
 * @param[in] infRelativePath 同領域内の元INFです
 * @param[out] className 非空Class/有効非zero GUID/既知Firmware範囲外を確認した原名です
 * @return 元読取成功0、不正・不明・既知FirmwareはHRESULTです
 * @note importの非実行内容だけです。root policy、適合または導入能力を変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialInfImportClass( const OfficialDownloadWorkspace &workspace,
													 std::wstring_view infRelativePath,
													 std::wstring	  &className) ;

/** @brief 選択DDInstall.Componentsの元宣言です。IDはworker内だけで保持します */
struct OfficialInfComponentReference {
	/// 同INFで一意な元AddComponent名です
	std::wstring			  name ;
	/// SWC接頭辞を加えた元ComponentIDsです。名称から推測しません
	std::vector<std::wstring> hardwareIds ;
	/**
	 * @brief 元宣言の全値を比較します
	 * @param[in] other 比較中だけ借用する元宣言です
	 * @return 全fieldが一致する場合trueです
	 */
	bool operator==( const OfficialInfComponentReference &other) const = default ;
} ;

/** @brief 収集元INFの全該当所有先から同じ原コピーへ結んだ必須export検査です */
struct OfficialInfPropertyPage {
	/// 当該INFの宣言sourceに含まれるworkspace相対位置です
	std::wstring sourceRelativePath ;
	/// 同じDLLが公開する必要がある元の大文字小文字を保った名前です
	std::wstring callback ;
} ;

/** @brief 正式Portsの自己媒体とWindows標準ページを結ぶ元選択の読み取り結果 */
struct OfficialInfNativePortsPage {
	/// 全元Modelsが指定する同じ未修飾DDInstall名
	std::wstring	   basicSection ;
	/// AMD64 Modelsから一意に解決した元DDInstall
	std::wstring	   installSection ;
	/// 元DDInstallが直接所有する標準ページの登録節
	std::wstring	   registrySection ;
	/// 元選択の関連カーネルサービスへ結ぶ元SYSの媒体相対位置
	std::wstring	   driverSource ;
	/**
	 * @brief 元Models、登録節、媒体位置が再検査でも同じか確認する
	 * @param[in] other 比較対象の独立した読取り結果
	 * @return すべての元値が一致する場合true
	 */
	[[nodiscard]] bool operator==( const OfficialInfNativePortsPage &other) const = default ;
} ;

/** @brief 複数のPorts導入節が共有する標準ページと元媒体の収集専用証拠 */
struct OfficialInfCollectorSharedPortsPage {
	/// 全元選択が直接所有する同じ標準ページ登録節
	std::wstring registrySection ;
	/// 全元サービスが使用するAMD64 SYSの媒体相対位置
	std::wstring driverSource ;
} ;

/**
 * @brief 混在シリアル媒体の自前SYSとWindowsへの依存を元選択節から保持する
 * @note 構造を確認した参照であり、同梱側の署名・実ファイル・作用の成立は別に確認する
 */
struct OfficialInfCollectorSerialMedia {
	/// 元サービスと二つの選択が参照した同じAMD64 SYSの媒体相対位置
	std::wstring						   driverSource ;
	/// 各選択の実DDInstall、HW、Servicesをこの順に保持する
	std::vector<std::vector<std::wstring>> groups ;
} ;

/** @brief 同じNVMe元基本節で参照された空のファイル一覧です */
struct OfficialInfInboxNvmeLists {
	/// 元CopyFilesが直接指定する実在の空節です
	std::wstring copy ;
	/// 元DelFilesが直接指定する実在の空節です
	std::wstring remove ;
} ;

/**
 * @brief 現在のWindows x64に適用可能な一つの標準INFの検証済み構造を表す
 */
struct OfficialInfPackage {
	/// Workspace基準のINF相対path
	std::wstring							   infRelativePath ;
	/// INFと同じdirectoryにあるCAT相対path
	std::wstring							   catalogRelativePath ;
	/// 元INFから確認したClass名
	std::wstring							   className ;
	/// Allowlistと一致したINF Provider
	std::wstring							   providerName ;
	/// DriverVer directiveの日付field
	std::wstring							   driverDate ;
	/// DriverVer directiveのversion field
	std::wstring							   driverVersion ;
	/// 選択Models sectionにある一意のPnP ID群
	std::vector<std::wstring>				   hardwareIds ;
	/// 現在architecture用の参照file相対path群
	std::vector<std::wstring>				   sourceFiles ;
	/// 動作検査を要求したpolicyでInclude／Needs／AddComponentを観測した場合true。未検査時のfalseは不在証明ではない
	bool									   hasExternalDependencies{} ;
	/// 元Classから分類した役割です。役割別検証を省略する許可ではありません
	DriverPlanRole							   role{DriverPlanRole::BASE_DRIVER} ;
	/// 元VersionのClassGUIDです。役割INFでは正式GUIDを必須にします
	std::wstring							   classGuid ;
	/// Extensionの元ExtensionIdをWindows GUIDへ解析した正規表記です。他の役割では空です
	std::wstring							   extensionId ;
	/// 私有native nodeの基本名を現OSへ解決した実在DDInstallです。内容検査単独では空です
	std::wstring							   selectedInstallSection ;
	/// 同じcompatible nodeの未修飾基本名です。内容検査単独では空で、導入権限にはなりません
	std::wstring							   selectedBasicSection ;
	/// 同じcompatible nodeのWindows rankです。非選択importでは空で、独自rank判定に使用しません
	std::optional<std::uint32_t>			   selectedNativeRank ;
	/// 全節の潜在CopyINF再帰importへ渡す安全なpackage相対pathです。機能必要性とは別です
	std::vector<std::wstring>				   requiredInfPaths ;
	/// 元CopyINFのうち原containerで見つからない相対名。内容署名成功と依存解決を混同しない
	std::vector<std::wstring>				   unresolvedCopyInfPaths ;
	/// 同deviceで選択したDDInstallのCopyINFだけです。未選択節の参照を実行集合へ混ぜません
	std::vector<std::wstring>				   activeRequiredInfPaths ;
	/// 元選択DDInstall.Componentsが宣言する必要子です
	std::vector<OfficialInfComponentReference> requiredComponents ;
	/// 全明示節のInclude/Needsを検出した状態です。元OS/storeとpackageの充足は別検査です
	bool									   unresolvedIncludeNeeds{} ;
	/// 内容だけで受理した元program/archive参照が同INFの正式copy/serviceへ未結合の場合true。実行や不適合を意味しない
	bool									   hasUnassessedProgramReferences{} ;
	/// 実構造検査が設定した用途です。非実行内容を通常bindingへ渡せません
	OfficialInfInspectionPurpose inspectionPurpose{OfficialInfInspectionPurpose::STANDARD_DRIVER} ;
	/// 全潜在節を検査した正式Systemのfileなし必須null importだけがtrueです
	bool						 requiredNullCompanion{} ;
	/// CopyINF由来collector内容だけの限定HKR DWORD形式です。nullや導入資格ではありません
	bool						 requiredRegistryOnlyCompanion{} ;
	/// 明示選択collector rootだけの署名後照合要求です。実行や導入の資格を持ちません
	std::optional<OfficialInfPropertyPage>			   collectorPropertyPage ;
	/// 自己媒体Portsの元構造です。元CATとWindows標準DLLの独立照合を後段で行います
	std::optional<OfficialInfNativePortsPage>		   nativePortsPage ;
	/// 元書庫とWindows標準ページを別に検査する共有Portsの収集専用証拠
	std::optional<OfficialInfCollectorSharedPortsPage> collectorSharedPortsPage ;
	/// 自前媒体と同梱SerialEnumeratorが両方必要な私有収集の元参照
	std::optional<OfficialInfCollectorSerialMedia>	   collectorSerialMedia ;
	/// 元DDInstall実名を先頭に同じ選択の付随節を並べた収集専用の依存検査要求です
	std::vector<std::vector<std::wstring>>			   collectorInboxInstallGroups ;
	/// 元SYSを持つHDCの基本・HW・Servicesを全AMD64選択について保持
	std::vector<std::vector<std::wstring>>			   nativeHdcInstallGroups ;
	/// 元基本節が直接参照する標準Portsプロパティページ登録節です。適用外では空です
	std::wstring									   collectorInboxPropertyPageSection ;
	/// 公式対象の元HW節が所有する同梱WinUSB用のGUID登録節。適用外では空
	std::wstring									   collectorInboxWinUsbRegistrySection ;
	/// 収集専用NVMe元構造の照合を通過した空リストです。署名検査の後で再確認します
	std::optional<OfficialInfInboxNvmeLists>		   collectorInboxNvmeLists ;
	/// 署名済み元Modelsの証拠と公式Hardware欄の一致です。通常の導入用は空です
	std::optional<OfficialInfScopedModelsEvidence>	   scopedModels ;
	/// 追加のクラス登録を認めた収集INFのSHA-256。展開記録とCAT検査で照合する。従来形式では空
	std::wstring									   collectorClassInfSha256 ;
} ;

/** @brief 選択INFが対象クラスの初回登録時に指定する表示情報 */
struct OfficialInfDeclarativeClassRegistration {
	/// 読み取り前後で確認した選択元INFのハッシュ
	std::wstring	   infSha256 ;
	/// 元INFとWindowsの両方で確認した対象クラスGUID
	std::wstring	   classGuid ;
	/// Windowsが現在OS用に解決した元ClassInstall32節
	std::wstring	   section ;
	/// 同節から登録するクラスの表示名
	std::wstring	   displayName ;
	/// 元INFが使用する場合だけ存在する負の内蔵アイコン番号
	std::optional<int> builtInIcon ;
	/**
	 * @brief 同じ元INFクラス登録の再観測と比較する
	 * @param[in] other 別時点または別選択で得たクラス登録
	 * @return 元ハッシュ、GUID、節、表示名、アイコンが同じ場合true
	 */
	bool operator==( const OfficialInfDeclarativeClassRegistration &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 選択済みWindows nodeの元Models行と必要時の初回クラス登録を同じ保護INFから確認する
 * @param[in] workspace 元の内容検査済みファイルを所有する領域
 * @param[in] package 端末で確認した独自クラスの内容検査結果
 * @param[in] expectedSha256 元Models全体を確認したINFのハッシュ
 * @param[in] modelsSection 選択時に照合済みの現在OS用Models節
 * @param[in] basicSection Windows互換nodeが返したDDInstall基本名
 * @param[in] nodeIds 同nodeのHardware IDと順序付きCompatible ID。順番は元Modelsのフィールド順
 * @param[out] role 成功時の選択行の作用。失敗時はUNASSESSED
 * @param[out] classRegistration 任意の出力先。実ドライバーの元クラス登録を確認した場合だけ値を設定する
 * @return 同じ元行と作用を確認した場合0、曖昧・欠損・改変等はHRESULT
 * @note 読み取り照合だけを行う。導入資格や公開データを発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialInfSelectedModelRole(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::wstring_view expectedSha256, const std::wstring &modelsSection,
	const std::wstring &basicSection, std::span<const std::wstring> nodeIds,
	OfficialInfSelectedModelRole						   &role,
	std::optional<OfficialInfDeclarativeClassRegistration> *classRegistration = nullptr) ;

/** @brief 選択service原文の一行です。省略fieldを追加せず、原順と大小文字を保持します */
struct StorageServiceDirective {
	/// 元service-install内の0起点行です
	std::uint32_t			  ordinal{} ;
	/// 元Windows readerのdirective名です
	std::wstring			  key ;
	/// 全fieldです。明示空と不在を区別します
	std::vector<std::wstring> fields ;
	/**
	 * @brief 同原値の全fieldをfresh再構築値へ比較します
	 * @param[in] other 同用途の独立した比較元です。同期中だけ借用します
	 * @return 省略状態/全値/順序が一致する場合trueです
	 */
	bool					  operator==( const StorageServiceDirective &other) const = default ;
} ;

/** @brief 選択INFの一コピー行と同CAT memberを結ぶ非権限原値です */
struct SelectedStorageCopyFact {
	/// 元選択が参照するコピー節です。直接コピーの場合は元DDInstall節です
	std::wstring			  section ;
	/// コピー節または直接コピーの元DDInstall節の0起点行番号です
	std::uint32_t			  ordinal{} ;
	/// 原行の省略を補わない全fieldです
	std::vector<std::wstring> fields ;
	/// 同CAT内のsource相対pathです
	std::wstring			  source ;
	/// Windowsが原DestinationDirsから解決した完全targetです
	std::wstring			  target ;
	/// 原DestinationDirsのDIRIDです
	int						  dirid{} ;
	/// 同CAT memberのSHA-256です
	std::wstring			  sha256 ;
	/// 同CAT memberの完全byte数です
	std::uint64_t			  bytes{} ;
	/**
	 * @brief 元コピーの全fieldを再構築した値と比較します
	 * @param[in] other 同原入力から再構築した比較値です
	 * @return 原行と全memberが一致する場合trueです
	 */
	bool					  operator==( const SelectedStorageCopyFact &other) const = default ;
} ;

/**
 * @brief 同じSCSIAdapter選択の補助サービスと一意な署名付きEXEコピーを保持します
 * @note 元イベント参照と原Securityは保持します。作用の妥当性や端末への導入資格を表しません
 */
struct SelectedStorageAuxiliaryServiceFacts {
	/// 元Services節内でのAddServiceの0起点行です
	std::uint32_t						   addServiceOrdinal{} ;
	/// 元AddService全fieldです。第4欄はイベント節、六欄形式の第5・6欄はログとイベント源です
	std::vector<std::wstring>			   addServiceFields ;
	/// 関連カーネルサービスとは別の元サービス名です
	std::wstring						   name ;
	/// 元サービス構成の節名です
	std::wstring						   installSection ;
	/// 元ServiceTypeです。WIN32_OWN_PROCESSを保持します
	std::uint32_t						   type{} ;
	/// 元StartTypeです。System32ではDEMAND_START、Driver StoreではAUTO_STARTです
	std::uint32_t						   start{} ;
	/// 元ErrorControlです
	std::uint32_t						   errorControl{} ;
	/// Windows readerが展開した元ServiceBinaryの完全値です
	std::wstring						   binary ;
	/// 選択DDInstallの一意なEXEコピー原行と同CAT memberです
	SelectedStorageCopyFact				   copy ;
	/// 名前付きSystemイベントが使う同CATのデータ専用DLLコピーです。元宣言がなければ空です
	std::optional<SelectedStorageCopyFact> eventMessageCopy ;
	/// 元サービス節の順序と全fieldを保持します
	std::vector<StorageServiceDirective>   directives ;
	/// 元SecurityのSDDLです。Securityを省略したDriver Storeの自動起動では空です
	std::wstring						   security ;
	/**
	 * @brief 同じ原選択から構築した補助サービスの全事実を比較します
	 * @param[in] other 元順序と完全なコピーを含む比較元です
	 * @return 原行、節名、Security、コピーと署名結合の値が一致する場合trueです
	 */
	bool operator==( const SelectedStorageAuxiliaryServiceFacts &other) const = default ;
} ;

/** @brief 元選択と一意コピーへ結合した非権限storage service factsです */
struct SelectedStorageServiceFacts {
	/// 元選択の正式Class名を原値で保持します
	std::wstring										className ;
	/// 同じ元INFの正式Class GUIDを原値で保持します
	std::wstring										classGuid ;
	/// MTD選択の全コピー原行と同CAT memberです
	std::vector<SelectedStorageCopyFact>				mtdCopies ;
	/// 同元INFの完全な相対位置です
	std::wstring										infRelativePath ;
	/// 元native選択に結合した実DDInstall節です
	std::wstring										selectedInstallSection ;
	/// 元AddService宣言の所有節です
	std::wstring										servicesSection ;
	/// 元AddServiceの0起点行です
	std::uint32_t										addServiceOrdinal{} ;
	/// 元AddServiceの省略を含む全fieldです
	std::vector<std::wstring>							addServiceFields ;
	/// 元associated serviceの正確な名前です
	std::wstring										name ;
	/// 元service-install節です
	std::wstring										installSection ;
	/// 重複/欠損を拒否して読んだ元AddService flagsです
	std::uint32_t										flags{} ;
	/// 元ServiceTypeです
	std::uint32_t										type{} ;
	/// BOOT0/SYSTEM1/DEMAND3を保持する元StartTypeです
	std::uint32_t										start{} ;
	/// 元ErrorControlです
	std::uint32_t										errorControl{} ;
	/// Windows readerが返した全binary pathです。引数を切り捨てません
	std::wstring										binary ;
	/// 同選択CopyFilesの一意source相対位置です
	std::wstring										binarySource ;
	/// Windowsが解決した元copy先の完全位置です
	std::wstring										binaryTarget ;
	/// 元CAT memberの完全SHA-256です
	std::wstring										binarySha256 ;
	/// 元CAT memberの完全byte数です
	std::uint64_t										binaryBytes{} ;
	/// 元service節の後続行も含む全行です。未知directiveも保持します
	std::vector<StorageServiceDirective>				directives ;
	/// 不在と明示空を区別する原groupです
	std::optional<std::wstring>							group ;
	/// 不在と明示空、原順を保持する全依存です
	std::optional<std::vector<std::wstring>>			dependencies ;
	/// modern BootFlags directiveの明示値です。旧registry形式とは別です
	std::optional<std::uint32_t>						bootFlags ;
	/// SCSIAdapterの元選択に結合した非関連補助サービスです。従来の単一サービスでは空です
	std::optional<SelectedStorageAuxiliaryServiceFacts> auxiliary ;
	/**
	 * @brief 同原値の全fieldをfresh再構築値へ比較します
	 * @param[in] other 同用途の独立した比較元です。同期中だけ借用します
	 * @return 省略状態/全値/順序が一致する場合trueです
	 */
	bool operator==( const SelectedStorageServiceFacts &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同原選択storageの関連サービスと、該当する場合はSCSIAdapterの補助サービスを読み取ります
 * @param[in] workspace 端末検査またはHDC収集検査が所有する保護領域
 * @param[in] entries 同原CAT検査済み閉包の全hash/sizeです
 * @param[in] selected 元native nodeまたはHDCのAMD64 Modelsから解決した選択関係
 * @param[out] facts SYSと該当する補助EXE・イベント用DLLの元コピーと型が成立した場合だけ保持します。失敗時は空です
 * @return 元全fieldと該当する補助EXEの署名確認に成功した場合0、その他はHRESULTです
 * @note 署名確認はキャッシュ内で行います。サービスの作用と端末上の導入資格は後段で検査します
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSelectedStorageServiceFacts(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &selected, SelectedStorageServiceFacts &facts) ;

//------------------------------------------------------------------------------
/**
 * @brief ストレージの実選択節を、Windows同梱INFへの空ドライバー委譲の原宣言に照合する
 * @param[in] workspace CAT検査済み元INFを保護する領域。同期中だけ借用する
 * @param[in] entries 元閉包のSHA-256とサイズを持つ一覧。同期中だけ借用する
 * @param[in] selected 元のWindows互換ノードに結ぶストレージの選択関係
 * @param[in] modelsSection 同じ元署名レコードの現在OS用Models節
 * @param[in] nodeIds 同じWindows互換ノードの順序付きHardware IDとCompatible ID
 * @param[out] matched 選択節とサービス節の委譲だけが完全に一致した場合true。失敗と通常の選択はfalse
 * @return 照合完了0、委譲を宣言する節の不正や読取り失敗はHRESULT
 * @pre 呼出し側は同じ原閉包のCAT署名と端末の選択関係を確認する
 * @note Windows側の参照先、実端末への適用、導入資格は呼出し側で別に判定する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSelectedStorageNullDriverDelegation(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &selected, const std::wstring &modelsSection,
	std::span<const std::wstring> nodeIds, bool &matched) ;

//------------------------------------------------------------------------------
/**
 * @brief ストレージのWindows実選択を固定した元INFの現在OS用Modelsの一行へ照合する
 * @param[in] workspace 原閉包の管理者保護領域
 * @param[in] entries 元閉包のファイルと原サイズ・SHA-256
 * @param[in] package 内容検査済みの元ストレージ基本INF
 * @param[in] modelsSection 元署名レコードの現在OS用Models節
 * @param[in] basicSection Windowsの実選択ノードが返した未修飾DDInstall
 * @param[in] nodeIds 同ノードの主Hardware IDと元順の全Compatible ID
 * @return 同じ原バイトと一意な元行が成立すれば0、失敗時はHRESULT
 * @pre 呼出し側で同じ元閉包のCAT署名と元レコードの端末範囲を確認する
 * @note 読取りだけを行う。端末の順位、作用、変更の資格は別に確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialStorageInfModelSelection(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &package, std::wstring_view modelsSection,
	std::wstring_view basicSection, std::span<const std::wstring> nodeIds) ;

//------------------------------------------------------------------------------
/**
 * @brief 同保護元INFの私有node基本名から選択節の機能関係だけを解析します
 * @param[in] workspace 元byte検査済みINFを所有し、同期終了まで生存する保護領域です
 * @param[in] entries 全潜在importを含む元hash付きinventoryです。呼出し中だけ借用します
 * @param[in] original 同保護元INFの内容検査metadataです。選択成功や導入権限は表しません
 * @param[in] selectedBasicSection 同device/native nodeで確認した未修飾基本名です。空・NUL・過長は禁止です
 * @param[out] selected 成功時だけ全importと選択機能関係を保持するcopyです。失敗時は空です
 * @return 現OS Models所属/Windows装飾選択/実節/機能関係の確認0、その他は元HRESULTです
 * @pre originalとselectedは異なるobjectです。同じ元byteの再確認を呼出し側で行います
 * @note Worker内のread-only解析です。呼出し側の全byte再検査と同issuer bindingを代替しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSelectedOfficialInfRelations(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &original, std::wstring_view selectedBasicSection,
	OfficialInfPackage &selected) ;

//------------------------------------------------------------------------------
/**
 * @brief 親の必須SoftwareComponentを現OSの元Modelsが示す一つの導入節へ結ぶ
 * @param[in] workspace 検査済みの元INFを所有する保護領域
 * @param[in] entries 元の署名済み閉包に属するファイル一覧
 * @param[in] original 内容検査済みの子INF。実deviceの観測値ではない
 * @param[in] componentIds 元親の選択節が宣言したSWCのHardware ID
 * @param[out] selected 一意な節の関係を持つ元metadata。失敗時は空
 * @return 一つの基本節を確認した場合0、選択不能・曖昧・元読取失敗はHRESULT
 * @pre originalとselectedは別object。呼出し側が親のCopyINF、元byte、CATを検証する
 * @note 未作成の子にWindows rankや導入資格を発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectRequiredOfficialInfComponentSelection(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &original, std::span<const std::wstring> componentIds,
	OfficialInfPackage &selected) ;

/** @brief 元Displayの選択節から確認した補助サービス。端末の所有や導入許可を含まない */
struct OfficialDisplayAuxiliaryService {
	/// 元AddServiceが指定したサービス名
	std::wstring										serviceName ;
	/// 同じ選択節がコピーするEXEの保護領域相対名
	std::wstring										binarySource ;
	/// 元INFが指定したApplicationイベント源
	std::wstring										eventSource ;
	/// 同じイベント源の表示用リソースに限った元DLL参照
	std::wstring										messageFile ;
	/// 元イベントで明示されたカテゴリ表示用DLL参照。未指定は空
	std::wstring										categoryMessageFile ;
	/// 元イベントで指定された一意な名前とDWORD値
	std::vector<std::pair<std::wstring, std::uint32_t>> eventValues ;
	/// 元Win32補助の起動順グループ。未指定は空
	std::wstring										loadOrderGroup ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現用Displayの実選択節で同名補助サービスとイベント源の元宣言を読む
 * @param[in] storeInf 既存の公開INFと同一原byteを確認し、読取期間中に固定したStore INFの絶対位置
 * @param[in] installedSection 現用デバイスから得た実DDInstall節。装飾があれば含む
 * @param[in] associatedService 同じ現用デバイスのWindows関連サービス名
 * @param[in] intended 候補が更新する補助サービス名とイベント源を保持する同選択の構文証拠
 * @param[out] declaration 成功時の現用構成。binarySourceには同じStoreパッケージ内のDIRID 13相対位置を保持。失敗時は空
 * @param[out] components 指定時は同じ現用親が宣言する子の集合。失敗時は空
 * @return 同一の現用関連サービスと同名補助・イベント源を確認して0、欠損・未知・不一致はHRESULT
 * @note 読み取った現用宣言とSCM、イベント源、ファイル署名、他デバイスの所有関係は後段で照合する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegisteredDisplayAuxiliaryDeclaration(
	const std::wstring &storeInf, std::wstring_view installedSection,
	std::wstring_view associatedService, const OfficialDisplayAuxiliaryService &intended,
	OfficialDisplayAuxiliaryService			   &declaration,
	std::vector<OfficialInfComponentReference> *components = nullptr) ;

//------------------------------------------------------------------------------
/**
 * @brief 現用SoftwareComponentが主Hardware IDで記録済みの実節を選ぶか確認する
 * @param[in] storeInf 同時読取で固定した現用SoftwareComponentのStore INF絶対位置
 * @param[in] hardwareId 同じpresent子から正式に観測した唯一のSWC Hardware ID
 * @param[in] basicSection 現用デバイスのDriverInfSection。記録によっては装飾込み
 * @param[in] installedSection 現用デバイスが保持する装飾込みの実節
 * @return 署名元候補の正式クラス、現在OSの主Modelsと現用実節が一致して0、その他はHRESULT
 * @note 互換IDだけで結び付けない。INFの元署名と現在属性の前後一致は呼出側で確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyRegisteredSoftwareComponentModel(
	const std::wstring &storeInf, std::wstring_view hardwareId, std::wstring_view basicSection,
	std::wstring_view installedSection) ;

/** @brief 元SoftwareComponentがWindows共有ディレクトリに配置する1ファイル */
struct OfficialSoftwareComponentSharedCopy {
	/// 署名閉包内の同じ元相対位置
	std::wstring  source ;
	/// Windowsが同じINFの宛先節から解決した絶対位置
	std::wstring  target ;
	/// 元DestinationDirsの識別子
	int			  dirid{} ;
	/// 元CopyFiles行の指定を省略時の0も含めて保持
	std::uint32_t flags{} ;
	/// 元閉包のファイル全体のバイト数
	std::uint64_t bytes{} ;
	/// 元閉包のファイル全体のSHA-256
	std::wstring  sha256 ;
	/**
	 * @brief 同じ署名選択から読み直した一コピーを比較する
	 * @param[in] other 別の読取りで得た元コピー
	 * @return 元位置、宛先、フラグと元内容が同じ場合true
	 */
	bool		  operator==( const OfficialSoftwareComponentSharedCopy &other) const = default ;
} ;

/** @brief 選択したSoftwareComponentのType 1構文と同じ元EXEの読取り証拠 */
struct OfficialType1Registration {
	/// 選択した同じ元INFの閉包内相対位置
	std::wstring									 infRelativePath ;
	/// 同じ元INF全体のSHA-256
	std::wstring									 infSha256 ;
	/// 同じ元Modelsから特定した装飾前の選択節
	std::wstring									 basicSection ;
	/// Windowsが選択した装飾付きのDDInstall節
	std::wstring									 installSection ;
	/// Windowsが元AddSoftwareから展開した固有ソフトウェア名
	std::wstring									 softwareName ;
	/// 元フラグが1ならtrue。Windowsの処理単位を示し、EXEの作用範囲は表さない
	bool											 perDevice{} ;
	/// DriverVerから独立した元SoftwareVersionの表記
	std::wstring									 softwareVersion ;
	/// 元SoftwareBinaryのINF相対位置
	std::wstring									 softwareBinary ;
	/// 同一選択がDIRID 13へコピーするEXEの保護領域相対位置
	std::wstring									 binarySource ;
	/// 元閉包と同じEXE全体のSHA-256
	std::wstring									 binarySha256 ;
	/// 元閉包と同じEXEのバイト数
	std::uint64_t									 binaryBytes{} ;
	/// WindowsがINFから展開した元の引数値を順に保持。実行時変数は未展開
	std::vector<std::wstring>						 arguments ;
	/// 同じ選択がDriver Store以外のWindows位置へコピーする元ファイル
	std::vector<OfficialSoftwareComponentSharedCopy> sharedCopies ;
	/**
	 * @brief 読み直した元宣言と全関連バイトを比較する
	 * @param[in] other 別の読取りで得た元選択の証拠
	 * @return 元INFと選択節、宣言、元実行物、共有コピーが等しい場合true
	 */
	bool operator==( const OfficialType1Registration &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元の選択済みSoftwareComponentから一つのType 1 EXE宣言を読み取る
 * @param[in] workspace 同期読取り中に元ファイルを保持する保護領域
 * @param[in] entries 元INFとEXE・共有コピー元のサイズとSHA-256を含む検査済み閉包
 * @param[in] selected 同元INFから検査済みの実DDInstallと必要関係
 * @param[out] registration 一意な宣言、元EXEと共有コピーの証拠。失敗時は空
 * @return 一意な元宣言と同名DIRID 13コピー、元INFとEXEの照合が成立すれば0、その他はHRESULT
 * @pre 呼出側が元閉包のCATと親子の選択関係を確認する
 * @note この証拠は宣言されたWindowsの処理単位と引数を示す。内部動作、端末上の所有、実行資格は別に検査する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSelectedOfficialType1Registration(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &selected, OfficialType1Registration &registration) ;

//------------------------------------------------------------------------------
/**
 * @brief 選択元INFのWindows管理driver package範囲を非実行で再検査します
 * @param[in] workspace 全内容検査済み元fileを所有する保護領域です
 * @param[in] entries 全原参照のsize/hash付き閉包です。CAT検証は呼出側が別に要求します
 * @param[in] selected native compatible nodeから選んだ原DDInstall関係です
 * @param[out] diagnostic 任意の最初の固定拒否です。合否に使いません
 * @param[out] displayService 必要なDisplay補助サービスの構文証拠。nullptrの場合は当該形式を拒否。失敗時は空
 * @param[in] reviewedDisplayChild 同じ選択Displayの所有と作用先が確認済みの必須子の元宣言。通常はnullptr
 * @return 選択copy/source/Windows宛先/関連service/softwareの結合成功0、それ以外はHRESULTです
 * @note 本関数は実行能力を持ちません。元byte/CAT再検証後の私有factoryから使用します。vendor内部作用やDisplay Type1のWindows実行対応を証明せず、元未評
 *       価flagも変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSelectedWindowsDriverPackageScope(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &selected, RequiredInfBindingDiagnostic *diagnostic = nullptr,
	std::optional<OfficialDisplayAuxiliaryService> *displayService		 = nullptr,
	const OfficialType1Registration				   *reviewedDisplayChild = nullptr) ;

/**
 * @brief INFのPnP IDと現在deviceのPnP IDとの照合結果を表す
 */
enum class OfficialInfDeviceMatch {
	/// 現在deviceへ完全一致するPnP IDがない
	NONE,
	/// Compatible IDへ完全一致した
	COMPATIBLE_ID,
	/// Hardware IDへ完全一致した
	HARDWARE_ID,
} ;

/** @brief 保守専用参照棚卸しの到達段階。署名や導入許可を表さない */
enum class OfficialInfReferenceStage {
	/// 入力境界またはINF読取
	OPEN,
	/// Version節とCAT位置
	VERSION,
	/// SourceDisksFilesと媒体位置
	SOURCES,
	/// 全sectionのCopyINFと外部依存
	DEPENDENCIES,
	/// 参照棚卸し完了。参照先のbyte取得・署名検証は別途必要
	INVENTORIED,
} ;

/**
 * @brief 保守PC専用の参照棚卸し。導入用packageと互換ではない
 * @note 全sectionの過大近似であり、現在deviceの選択sectionを確定しない
 */
struct OfficialInfReferenceInventory {
	/// 成功段階または最初の失敗段階。失敗時の他fieldは空
	OfficialInfReferenceStage stage{OfficialInfReferenceStage::OPEN} ;
	/// 保護workspace基準の元INF位置
	std::wstring			  infRelativePath ;
	/// 対応CAT位置。元inventoryに存在することだけを確認する
	std::wstring			  catalogRelativePath ;
	/// Version節のclass表示。導入class許可ではない
	std::wstring			  className ;
	/// 共通とamd64の全source参照。内容hashは未検証
	std::vector<std::wstring> sourceFiles ;
	/// 同じdirectoryまたは子directoryの全CopyINF参照。欠落先も保持する
	std::vector<std::wstring> copyInfPaths ;
	/// Include／Needs／AddComponentを観測した場合true。依存充足を表さない
	bool					  hasExternalDependencies{} ;
	/// 既存の全section導入動作検査結果。0でも導入許可ではない
	NativeError				  installActionsError{} ;
} ;

/** @brief 選択された導入処理の宣言種類。実行対応や許可を表さない */
enum class OfficialInfInstallEffectKind {
	/// 既知の標準directiveの存在。安全性や参照充足の認定ではない
	STANDARD_DIRECTIVE,
	/// 非空CoInstaller節またはCoInstallers32登録
	COINSTALLER,
	/// 任意commandを記載するdirective
	COMMAND_EXECUTION,
	/// DLL登録・解除を記載するdirective
	DLL_REGISTRATION,
	/// 別INFの取込みを記載するdirective
	COPY_INF,
	/// registryの自動起動位置に対する宣言
	REGISTRY_AUTORUN,
	/// Include・Needs・AddComponentの明示依存
	EXPLICIT_DEPENDENCY,
	/// 未解釈のdirective。作用なしに読み替えない
	UNKNOWN_DIRECTIVE,
} ;

/** @brief 選択処理から観測した一宣言。値やcommand本文は保持しない */
struct OfficialInfInstallEffect {
	/// worker内だけの宣言元section名
	std::wstring				 section ;
	/// worker内だけのdirective名。registry行は検出した種類名だけ
	std::wstring				 directive ;
	/// 宣言の種類。実行の有無は未検査
	OfficialInfInstallEffectKind kind{OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE} ;
} ;

/** @brief 明示参照の種類。依存解決結果ではない */
enum class OfficialInfInstallReferenceKind {
	/// 同じINF内の処理またはdata section
	LOCAL_SECTION,
	/// Includeに記載された別INF
	INCLUDE_INF,
	/// CopyINFに記載された別INF
	COPY_INF,
	/// CopyFilesの直接file参照
	DIRECT_FILE,
} ;

/** @brief 一つの明示参照とmetadataの存在観測。実byte・依存充足は未検査 */
struct OfficialInfInstallReference {
	/// worker内だけの参照元section名
	std::wstring					section ;
	/// worker内だけの参照directive名
	std::wstring					directive ;
	/// worker内だけのsection名または安全なworkspace相対file名
	std::wstring					target ;
	/// 参照先の種類
	OfficialInfInstallReferenceKind kind{OfficialInfInstallReferenceKind::LOCAL_SECTION} ;
	/// 同じINF節またはpackage内entryが存在する場合true。充足・署名の証明ではない
	bool							targetPresent{} ;
} ;

/** @brief 選択棚卸しが解釈していない範囲。導入拒否や全構文の完全性ではない */
enum class OfficialInfInstallCoverageKind {
	/// Property・INI・ProfileItems等の参照先を走査していない
	UNFOLLOWED_SECTION_REFERENCES,
	/// AddService第4 fieldのevent-log節を走査していない
	UNFOLLOWED_SERVICE_EVENTLOG,
	/// AddSoftwareの独立software導入範囲を評価していない
	SOFTWARE_INSTALLATION_NOT_ASSESSED,
	/// 未知directiveの意味を解釈していない
	UNKNOWN_DIRECTIVE,
	/// 非空data節の本文を処理指示として解釈していない
	DATA_ROWS_NOT_INTERPRETED,
	/// 非空registry節の全作用範囲を評価していない
	REGISTRY_SCOPE_NOT_ASSESSED,
} ;

/** @brief 一宣言または非空節に結合した解析不足。本文・値は保持しない */
struct OfficialInfInstallCoverageGap {
	/// worker内だけの元節。値や実IDではない
	std::wstring				   section ;
	/// worker内だけの元directive。節本文全体の場合は空
	std::wstring				   directive ;
	/// 不足種類。空集合も完全性や導入許可を表さない
	OfficialInfInstallCoverageKind kind{OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE} ;
} ;

/**
 * @brief 現OSのModelsから選んだ一導入名の有限棚卸し。導入型へ変換しない
 * @note PnP ID・registry値・command本文を保持せず、全class固有作用を解釈したと主張しない
 */
struct OfficialInfInstallInventory {
	/// 保護workspace内の元INF相対path。worker内だけで保持する
	std::wstring							   infRelativePath ;
	/// 解析前後に一致したINF hash。公式由来やCAT署名の証明ではない
	std::wstring							   infSha256 ;
	/// Models第1 fieldで確認した元の導入名
	std::wstring							   baseInstallSection ;
	/// Windowsが現在OS／x64に選び、実在を確認したDDInstall名
	std::wstring							   selectedInstallSection ;
	/// 一度だけ走査したsection名群。共有・循環参照の再走査を止める
	std::vector<std::wstring>				   visitedSections ;
	/// 有限範囲で観測した宣言。未知を含む
	std::vector<OfficialInfInstallEffect>	   effects ;
	/// 明示参照辺。欠落・共有・循環も保持し、充足としない
	std::vector<OfficialInfInstallReference>   references ;
	/// 最大4,096の未解釈観測。空でも全classの完全性を認定しない
	std::vector<OfficialInfInstallCoverageGap> coverageGaps ;
	/// Models選択を除く処理範囲の走査行数。最大4,096
	std::size_t								   scannedLines{} ;
} ;

/** @brief 保守検査の独立した到達状態。未検査を不適合にしない */
enum class MaintenanceInspectionState {
	/// この軸を検査していない
	NOT_CHECKED,
	/// この軸の検査を通過した。導入許可ではない
	PASSED,
	/// 実施した検査に失敗した。driver不正の包括的断定ではない
	FAILED,
	/// この方式を扱えない。driverが存在しないとは言わない
	UNSUPPORTED,
} ;

/** @brief 保守検査の一軸と元診断値 */
struct MaintenanceInspectionFinding {
	/// 未検査・合格・検査失敗・方式未対応
	MaintenanceInspectionState state{MaintenanceInspectionState::NOT_CHECKED} ;
	/// 検査失敗または方式未対応のHRESULT。それ以外は0
	NativeError				   error{} ;
} ;

/** @brief 保守専用の内容構造。署名・driver-only・適合・実行方式の認定ではない */
enum class MaintenanceInfContentKind {
	/// 構造を確定できない、または由来未確認の依存だけを観測した
	UNKNOWN,
	/// Package内fileの宣言または用途参照を観測した
	PACKAGE_FILES,
	/// 限定したempty associated service構造を観測した。全file参照確認は別軸
	NULL_DRIVER,
	/// 同OSのinbox由来を別検査で確認した依存構造。名前だけで設定しない
	INBOX_DEPENDENCY,
	/// nullとfile参照・依存、または複数の異なる選択構造を観測した
	MIXED,
} ;

/** @brief 全必要file参照を実byteへ結合した検査の状態 */
enum class MaintenanceInfReferenceCoverage {
	/// 全参照閉包をまだ検査していない。空参照集合を不在証明にしない
	NOT_CHECKED,
	/// 全必要参照の対応位置とbyteを結合した。作用・署名・適合の合格ではない
	COMPLETE,
	/// 検査済みで未追跡用途・欠落・対応位置未確定が残る
	INCOMPLETE,
} ;

/** @brief 同一OS観測での明示依存のsummary。全payload署名と独立する */
enum class MaintenanceInfDependencyState {
	/// 依存棚卸しまたは照会が未実施
	NOT_CHECKED,
	/// 全到達節の棚卸しで明示依存なしを確認した
	NONE,
	/// 明示参照を観測したが、byte・由来・署名の確認は完了していない
	OBSERVED,
	/// 照会済みで欠落・曖昧・循環・不正参照が残る
	UNRESOLVED,
	/// 同OS観測の全明示辺とseedのbyte・由来・INF署名を確認した
	RESOLVED_CURRENT_OS,
} ;

/** @brief 外へ射影できる数・enum・診断値だけの依存summary */
struct MaintenanceInfDependencySummary {
	/// 未実施を不在または解決へ昇格しない独立状態
	MaintenanceInfDependencyState state{MaintenanceInfDependencyState::NOT_CHECKED} ;
	/// 最初の未解決理由。未照会時はNOT_CHECKED
	InfDependencyReason			  reason{InfDependencyReason::NOT_CHECKED} ;
	/// 元の照会・検証HRESULT。観測だけの場合は0
	NativeError					  error{} ;
	/// 棚卸しで観測した明示参照数。0単独では不在証明ではない
	std::size_t					  observedReferenceCount{} ;
	/// 署名まで検証した対象INF数。全payloadの検査数ではない
	std::size_t					  resolvedInfCount{} ;
} ;

/** @brief 保守構造で未対応または不正になった具体的な理由 */
enum class MaintenanceInfStructureReason {
	/// 内容Classが解析policyの集合外
	CLASS_NOT_SUPPORTED,
	/// 必須AddService fieldまたはnamed service-install項目が欠落・明示空
	MISSING_SERVICE_FIELD,
	/// 展開後もtokenが残り数値を確定できない
	UNRESOLVED_FLAGS_TOKEN,
	/// 全fieldが符号なし十進／0x十六進の数値でない
	INVALID_FLAGS_NUMBER,
	/// 数値がuint32_tの範囲を超える
	FLAGS_OVERFLOW,
	/// 終端込みのfield必要長が4,096文字を超える
	FLAGS_TOO_LONG,
	/// Windowsが扱う数値表現でも今回の厳密形式と一致しない
	FLAGS_FORMAT_NOT_SUPPORTED,
	/// 限定nullの2、namedの0／2以外で作用未評価のbit組合せ
	FLAGS_NOT_SUPPORTED,
	/// Namedのidentityに未展開token等があり限定構造を確定できない
	NAMED_SERVICE_NOT_ASSESSED,
	/// 一選択に複数のassociated serviceがある
	MULTIPLE_ASSOCIATED_SERVICES,
	/// Empty serviceにも非空のservice-install／event-log参照がある
	NULL_SERVICE_SECTION_REFERENCE,
	/// 対応外節・後続作用field・必須参照不在、または必須項目の不正／未対応
	SERVICE_DECLARATION_NOT_SUPPORTED,
	/// 未解釈directiveを作用なしへ読み替えない
	UNKNOWN_DIRECTIVE,
} ;

/** @brief 元節・directiveへ結合したworker内だけの具体的診断 */
struct MaintenanceInfStructureIssue {
	/// 元INF内の宣言節名。UIや通常logへ出さない
	std::wstring				  section ;
	/// 宣言名。値やcommand本文は保持しない
	std::wstring				  directive ;
	/// 未対応・不正を区別する理由
	MaintenanceInfStructureReason reason{MaintenanceInfStructureReason::UNKNOWN_DIRECTIVE} ;
	/// 個別の到達状態とHRESULT。全体読取失敗と区別する
	MaintenanceInspectionFinding  finding ;
} ;

/** @brief AddServiceを非実行で読んだ構造。空名とfield欠落を区別する */
struct MaintenanceInfServiceStructure {
	/// 元の宣言節。worker内だけで保持する
	std::wstring				 section ;
	/// Fieldが存在して空の場合もそのまま保持するservice名
	std::wstring				 serviceName ;
	/// Keyを除く元field数。欠落と明示空の区別に使う
	std::uint32_t				 fieldCount{} ;
	/// 全数値解析に成功した場合だけのflags。失敗を0や2へ補完しない
	std::optional<std::uint32_t> flags ;
	/// 非空の場合だけ辿る明示service-install節名
	std::wstring				 serviceInstallSection ;
	/// 非空の場合だけ辿る明示event-log節名
	std::wstring				 eventLogSection ;
	/// 数値と必須named構造または限定nullの結果。完全な実行意味・署名・導入許可ではない
	MaintenanceInspectionFinding parser ;
} ;

/** @brief 全file参照検査へ引き継ぐ具体的な未検査用途 */
struct MaintenanceInfFileUse {
	/// 宣言元節。source宣言もVersionもworker内だけで保持する
	std::wstring section ;
	/// CopyFiles／ServiceBinary／LayoutFile等の具体的な宣言名
	std::wstring directive ;
	/// 展開済み用途field。対応位置・由来・実byteはまだ未検査
	std::wstring target ;
} ;

/** @brief 保守file参照の位置観測。実byte・署名の証拠とは互換でない */
enum class MaintenanceInfFileLocation {
	/// 位置を検査していない
	NOT_CHECKED,
	/// 固定member一覧へ一意に結合した。実byteと署名は別途必要
	LOCATED,
	/// 明示位置を照会したがmemberがない
	MISSING,
	/// 位置またはfile用途の解釈が未対応
	UNSUPPORTED,
} ;

/** @brief 元宣言と具体的な不足を保持するworker内file参照 */
struct MaintenanceInfFileReference {
	/// 元の明示節名
	std::wstring			   section ;
	/// 元directiveまたは未解釈用途の名称
	std::wstring			   directive ;
	/// 元の展開後参照。UIとlogへ出力しない
	std::wstring			   target ;
	/// 安全なpackage相対位置。位置未確定では空
	std::wstring			   relativePath ;
	/// 位置だけの観測。LOCATEDも署名成功ではない
	MaintenanceInfFileLocation location{MaintenanceInfFileLocation::NOT_CHECKED} ;
	/// 不在・位置未対応の元HRESULT。LOCATEDでは0
	NativeError				   error{} ;
} ;

/** @brief 一INFの明示seedからの有限参照閉包。導入用packageではない */
struct MaintenanceInfReferences {
	/// 固定元INFのpackage相対位置
	std::wstring							 infRelativePath ;
	/// 全読取前後に一致した元INFのSHA-256
	std::wstring							 infSha256 ;
	/// 宣言CATの安全位置。依存資料の未宣言では空。rootの必須CATは構造入口で要求する
	std::wstring							 catalogRelativePath ;
	/// 明示seedと到達local節の元参照・作用不足
	OfficialInfInstallInventory				 inventory ;
	/// INF／CAT・source・具体file用途と位置未確定の全観測
	std::vector<MaintenanceInfFileReference> files ;
	/// 位置が固定memberへ結べたsource群。実byte・CAT memberは別途必要
	std::vector<std::wstring>				 sourceFiles ;
	/// source不在と明示空を区別する。falseだけを無参照証明にしない
	bool									 sourceSectionPresent{} ;
	/// 全必要参照の位置棚卸し。依存先／署名／作用の完全性ではない
	MaintenanceInfReferenceCoverage referenceCoverage{MaintenanceInfReferenceCoverage::NOT_CHECKED} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 一INFの明示seedからlocal file用途と同節依存を同期・有限に棚卸しする
 * @param[in] workspace 呼出し全期間固定される保護所有領域
 * @param[in] entries 閉じたarchive member一覧。未抽出memberも位置照合に使う
 * @param[in] infRelativePath 読取前後に元byteへ一致させる最大4 MiBのINF
 * @param[in] seeds 原明示節群。0～1,024。suffix補完と別節Include借用をしない
 * @param[in] policy 既存の内容参照数と非圧縮EXE限定条件。導入policyへ転用しない
 * @param[out] references 全体成功時の位置観測。全体読取・path・容量失敗では空
 * @return 観測成功0、重大な読取・入力・容量・元byte差のHRESULT
 * @pre 入力と出力はaliasしない。workerから同期呼出しし、同時にworkspaceを変更しない
 * @note 一INF4 MiB、1,024節／4,096行・参照／64 field。依存先の解決と署名は別検査。展開済みbinaryは到達named list固有DestinationDirsと
 *       明示sourceへ限定照合する。親default文脈のない直接copy／defaultは位置未対応のまま保持する。DIRID13は同名とSourceDisksFiles／
 *       DestinationDirs subdir一致を追加要求する。同HINFの成功したdot-relative named13全targetは全候補・元source行の一意性も要求する
 *       LOCATEDとcoverageは固定package内の元source位置だけで、実byte／CATは後段で検証する。実Driver Store導入先の充足・端末適合・rank／grantと導入
 *       許可は未確認のまま分離する
 * @see docs/adr/0313-maintenance-expanded-service-binary-source-binding.md
 * @see docs/adr/0314-maintenance-unstaged-dirid13-source-content-separation.md
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectMaintenanceInfReferences(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view infRelativePath, std::span<const std::wstring> seeds,
	const OfficialInfInspectionPolicy &policy, MaintenanceInfReferences &references) ;

/** @brief 現在OSの一DDInstall選択と付随節の保守構造 */
struct MaintenanceInfInstallStructure {
	/// 既存棚卸しと同じ有限graph型。PnP ID・command本文を持たない
	OfficialInfInstallInventory					inventory ;
	/// 対応Services等から観測した全AddService構造
	std::vector<MaintenanceInfServiceStructure> services ;
	/// 未対応・不正を元宣言へ結合した具体的診断
	std::vector<MaintenanceInfStructureIssue>	issues ;
	/// 全file参照検査へ渡す具体的な用途観測。空でも完全性を認定しない
	std::vector<MaintenanceInfFileUse>			fileUses ;
	/// この選択の構造種別。依存のinbox由来を推測しない
	MaintenanceInfContentKind					contentKind{MaintenanceInfContentKind::UNKNOWN} ;
	/// 同じ元選択の全外部Needsを署名済みWindows同梱の作用に照合した場合だけtrue
	bool										wifiBusNeedsVerified{} ;
	/// 構造の解析到達だけの結果。必要byteと署名検査は別
	MaintenanceInspectionFinding				parser ;
} ;

/** @brief 署名済み収集閉包が同じ元選択の外部Needsを再検査する同期関数型です */
using ScopedInboxNeedsVerifier = std::function<NativeError( const OfficialInfInstallInventory &)> ;

/** @brief 保守worker専用の一INF構造。導入package・閉包へ変換しない */
struct MaintenanceInfStructure {
	/// 保護workspace基準の元INF位置。worker内だけで保持する
	std::wstring								infRelativePath ;
	/// 解析前後で一致した元INF SHA-256。署名・公式由来の証明ではない
	std::wstring								infSha256 ;
	/// 固定entriesに存在するCAT位置。実byteと署名は未検査
	std::wstring								catalogRelativePath ;
	/// Version節のClass。内容解析対象であり導入許可ではない
	std::wstring								className ;
	/// Version節の非空Provider名。署名者ではない
	std::wstring								providerName ;
	/// DriverVerの日付field
	std::wstring								driverDate ;
	/// DriverVerのversion field
	std::wstring								driverVersion ;
	/// 検査したModelsのPnP ID。公式対象に限定した場合はそのHardware IDだけを保持する
	std::vector<std::wstring>					hardwareIds ;
	/// 公式Hardware IDに対応する導入セクションだけを起点にした場合true
	bool										officialHardwareScope{} ;
	/// 元SYSと収集側Windows標準DLLの両方を検証した公式Netの導入起点数
	std::size_t									networkEventFileInstallCount{} ;
	/// 検査範囲の全一意DDInstall名の構造。失敗行も保持する
	std::vector<MaintenanceInfInstallStructure> installs ;
	/// Version LayoutFile等の具体的な未追跡file用途
	std::vector<MaintenanceInfFileUse>			fileUses ;
	/// 現OS用SourceDisksFiles節が存在する場合true。無参照証明ではない
	bool										sourceSectionPresent{} ;
	/// 現OS用sourceの宣言名。対応位置と実byteは未検査
	std::vector<std::wstring>					sourceFileNames ;
	/// 全現在OS選択を併合した内容構造
	MaintenanceInfContentKind					contentKind{MaintenanceInfContentKind::UNKNOWN} ;
	/// 全体読取後の個別構造解析結果。署名・依存充足ではない
	MaintenanceInspectionFinding				parser ;
	/// 全必要file参照の独立検査。構造解析だけではNOT_CHECKED
	MaintenanceInfReferenceCoverage referenceCoverage{MaintenanceInfReferenceCoverage::NOT_CHECKED} ;
	/// Root INFと確認したlocal参照の署名結果。構造解析だけではNOT_CHECKED
	MaintenanceInspectionFinding	rootIntegrity ;
	/// 同節の明示依存観測と独立証拠のsummary。閉包検査は別工程
	MaintenanceInfDependencySummary dependency ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現OSの全DDInstallまたは元Modelsで検証した公式範囲を有限に解析する
 * @param[in] workspace 同期借用する保護領域。呼出し中の変更は禁止する
 * @param[in] entries 固定済みの最大32,768 entry。INFは一意で最大4 MiB
 * @param[in] infRelativePath 安全な一INF相対path。worker外へ保存しない
 * @param[in] policy 有限ID／source上限と内容Class・Provider・構文識別子のpolicy
 * @param[out] structure 全体読取・元byte再照合に成功した場合だけ観測を保持する
 * @param[in] scopedModels 署名済み収集閉包の同一INFのModels証拠。通常の全起点はnull
 * @param[in] cancellation 同収集workerの同期取消し照会。通常の読取りはnull
 * @param[in] inboxNeeds 公式NetまたはUSB Bluetoothの元選択を同じ署名済み閉包へ結ぶ検査。それ以外はnull
 * @return 全観測完了0。全体入力・読取・容量・改変・例外失敗ではHRESULTと空結果
 * @note 不正宣言と未評価の作用は元診断を保持する。全起点で1,024節訪問・4,096行・各4,096項目を共有し、一行を64値に制限する
 *       収集内容の用途では一意な節名と用途を1,024に保ち、延べ節訪問を2,048、HKRバイナリ行の全値を128まで許容する
 *       SetupAPIが展開した値を読み、依存閉包の充足・署名・端末適合・導入許可は発行しない
 * @see docs/adr/0534-bounded-collection-inf-registry-inventory.md
 * @see docs/adr/0311-maintenance-inf-structure-and-install-policy-separation.md
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectMaintenanceInfStructure(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view infRelativePath, const OfficialInfInspectionPolicy &policy,
	MaintenanceInfStructure				  &structure,
	const OfficialInfScopedModelsEvidence *scopedModels = nullptr,
	const std::function<bool()>			  *cancellation = nullptr,
	const ScopedInboxNeedsVerifier		  *inboxNeeds	= nullptr) ;

//------------------------------------------------------------------------------
/**
 * @brief 現OSのModelsに属する導入名とその作用・参照を実行せず棚卸しする
 * @param[in] workspace 同期借用する保護領域。呼出し中の変更は禁止する
 * @param[in] entries 有限の元package一覧。対象INFは一意で実size一致を要求する
 * @param[in] infRelativePath 最大4 MiBの一INFの安全な相対path
 * @param[in] baseInstallSection 現OS用Modelsの第1 fieldと一致する最大254文字の導入名
 * @param[out] inventory 全観測と元byte再照合に成功した場合のみ保持し、失敗時は空
 * @return 有限棚卸し成功0、入力・選択・容量・改変・SetupAPI失敗のHRESULT
 * @note worker内でblockingする。署名・端末適合・依存充足・導入作用の許可を発行しない。最大1,024節・4,096行・作用4,096・参照4,096・一行64 field。別
 *       INFを開かず通常作用拒否を変更しない
 * @see docs/adr/0264-selected-inf-install-inventory.md
 * @see docs/adr/0266-selected-inf-inventory-capacity-expansion.md
 * @see docs/adr/0268-selected-inf-reference-context-and-coverage.md
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialInfInstallInventory(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view infRelativePath, std::wstring_view baseInstallSection,
	OfficialInfInstallInventory &inventory) ;

//------------------------------------------------------------------------------
/**
 * @brief 実行せずに保守用の全sourceとCopyINFを列挙する
 * @param[in] workspace INF実byteを所有する同期借用の保護領域
 * @param[in] entries 検証済み元archive metadata。未取得sourceを含められる
 * @param[in] infRelativePath 読取済みINFの安全な相対path
 * @param[out] inventory 成功時だけ参照集合を保持し、失敗時は到達stage以外を空にする
 * @return 棚卸し成功時0、最初の構文・path・容量違反のHRESULT
 * @note PnP IDを保持せず、署名・用途・適用性・導入を承認しない。Version構文識別子は$Windows NT$と$Chicago$を受理する。暗号署名の代わりにしない
 *       BlockingするためUI threadで呼ばない。CopyINFの再帰と実byte検証は呼出し側が必要。媒体・source subdir・CopyINFの先頭現在directory表記だけを
 *       除き、残りは既存path境界で検証する
 * @see docs/adr/0244-maintenance-inf-reference-inventory.md
 * @see docs/adr/0246-maintenance-relative-references-and-direct-content.md
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialInfReferences( const OfficialDownloadWorkspace	&workspace,
													   std::span<const OfficialZipEntry> entries,
													   std::wstring_view infRelativePath,
													   OfficialInfReferenceInventory &inventory) ;

//------------------------------------------------------------------------------
/**
 * @brief 展開済み標準INF packageの構造と現在OSへの適用sectionを検証する。展開済み標準INF packageを検証する。SetupAPIの構文とplatform選択結果を
 *        使用し、CAT署名前にpackageの有限性、driver-only境界、参照file存在を確認する
 * @param[in] workspace ZIP展開fileを所有する保護workspace
 * @param[in] entries ZIP検証で確定した全通常file。Directory entryは含めない。 ZIP検証済みの全通常file
 * @param[in] infRelativePath 検証対象INFのworkspace基準相対path。 検証するINF相対path
 * @param[in] policy 件数上限、許可class、ProviderおよびINF signature。 件数上限、許可class／Provider／signature
 * @param[out] package 成功時の検証済み構造。失敗時は空にする。 成功時だけ更新する検証済み構造
 * @param[in] scopedModels 同じ公式配布からの展開INFとCATを固定した収集用入力です。通常はnullです
 * @return 成功時は0、INF構文、適用section、参照fileまたはpolicy違反時はHRESULT。 全構造検証成功時は0、最初の違反はHRESULT
 * @note 本関数はfileを変更せず、catalog署名とmember hashは別の署名検証で確認する。TapeDrive名又は正式GUIDには一意な正式対を要求する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialInfPackage(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view infRelativePath, const OfficialInfInspectionPolicy &policy,
	OfficialInfPackage &package, const OfficialInfScopedModelsRequest *scopedModels = nullptr) ;

//------------------------------------------------------------------------------
/**
 * @brief 展開した元INFのVersionから同階層のCAT相対パスを取得します
 * @param[in] workspace 同じ元INFの所有領域です
 * @param[in] infRelativePath 所有済みINFの相対パスです
 * @param[out] catalogRelativePath Versionが指定した同階層の元CATです
 * @return 全読取り成功時0、欠損や不正パスはHRESULTです
 * @note このパスは展開対象の選択だけに使用し、署名やINFの所属を証明しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialInfCatalogPath( const OfficialDownloadWorkspace &workspace,
													 std::wstring_view infRelativePath,
													 std::wstring	  &catalogRelativePath) ;

//------------------------------------------------------------------------------
/**
 * @brief 元packageと一致する現OS公開IDを同HINFから原節名/種別付きで読み取ります
 * @param[in] workspace 保護された元INFを所有するworkspaceです
 * @param[in] package 通常構造検査で得た元INF相対pathと全ID列です
 * @param[out] identity 成功時だけ同INF前後hash/原ClassGUID/全Models節です。失敗時は空です
 * @param[out] diagnostic 同失敗だけの任意診断です。null可、成功時は空です
 * @return 有限な原metadataの全一致時0、欠損/上限/改変時は元HRESULTです
 * @note Read-onlyのmetadataです。CAT/member/公式性/実端末照合/取得同意を代替しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialInfPublishedIdentity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	OfficialInfPublishedIdentity &identity, InfFailureDiagnostic *diagnostic = nullptr) ;

//------------------------------------------------------------------------------
/**
 * @brief 同所有INFのhashを固定し、collectorの明示client/Server観測点でModelsを読みます
 * @param[in] workspace 元保護workspaceです
 * @param[in] package 元構造検査済みpackageです
 * @param[in] platform 10.0/AMD64/suite0で、clientはproduct1/build19045または26100、Serverはproduct2/3/build14393/17763/20348/26100です
 * @param[in] expectedInfSha256 同じ現OS構造検査から得た元INF hashです
 * @param[out] identity 成功した同targetの元Modelsです。失敗時は空です
 * @return 実Windows読取り成功0、不明target/改変/未観測は元HRESULTです
 * @note App現在OS入口/適用性/rank/CAT検証を代替せずfallbackしません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialInfPublishedIdentityForPlatform(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const OfficialInfModelsPlatform &platform, std::wstring_view expectedInfSha256,
	OfficialInfPublishedIdentity &identity) ;

//------------------------------------------------------------------------------
/**
 * @brief 元INFの全Models行と完全一致した公式Hardware IDの位置を有限に読みます
 * @param[in] workspace 元INFを保持する保護領域です
 * @param[in] infRelativePath 同領域内に展開した元INFの相対パスです
 * @param[in] expectedInfSha256 同じ原本に結び付いた小文字SHA-256です
 * @param[in] platform collectorの明示OSです。nullは現在OSです
 * @param[in] hardwareScope 公式配布元で確認した全Hardware IDです
 * @param[out] evidence 全行と全公式対象を検査した証拠です。失敗時は空です
 * @param[in] cancellation 同期処理中の取消し照会です。空は取消しなしです
 * @return 全対象が一意に成立した場合は0、読取や上限の失敗はHRESULTです
 * @note 読取りだけを行います。署名・参照閉包・適用性・導入の既存検査は別に必要です
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialInfScopedModels(
	const OfficialDownloadWorkspace &workspace, std::wstring_view infRelativePath,
	std::wstring_view expectedInfSha256, const OfficialInfModelsPlatform *platform,
	std::span<const std::wstring> hardwareScope, OfficialInfScopedModelsEvidence &evidence,
	const std::function<bool()> &cancellation = {}) ;

//------------------------------------------------------------------------------
/**
 * @brief 現OSが選ぶ元Modelsの全行から、Windows nodeの厳密な一行を署名済みの元位置に結びます
 * @param[in] workspace 同じ元INFを保持する保護領域です
 * @param[in] package 上流で署名済み原証拠と結合した同INFの基本driverです
 * @param[in] modelsSection 同証拠の選択対象が指定する元Models節です
 * @param[in] basicSection Windows nodeが返した未修飾DDInstall基本名です
 * @param[in] nodeIds 同nodeの先頭Hardware IDとそれに続く全Compatible IDです。順序を維持します
 * @param[out] selected 元証拠の一意な行です。失敗時は空です
 * @return 同じ元INFの前後hashと現OSの全証拠・対象行が一致した場合は0、失敗はHRESULTです
 * @pre selectedは入力の領域を参照しません
 * @note 読取り専用です。端末の現在Hardware ID、Windowsの順位や実行権限は呼出し側で検証します
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialInfScopedModelSelection(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::wstring_view modelsSection, std::wstring_view basicSection,
	std::span<const std::wstring> nodeIds, OfficialInfScopedModelMatch &selected) ;

//------------------------------------------------------------------------------
/**
 * @brief 公式配布の元Models行を再確認し、同じWindows選択の必要関係を読み取ります
 * @param[in] workspace 元署名を検査した閉包の管理者保護領域です
 * @param[in] entries 元署名の全ファイルと全潜在importを保持する一覧です
 * @param[in] original 元Modelsの証拠を保持する基本INFです
 * @param[in] modelsSection 署名レコードが指定する元Models節です
 * @param[in] basicSection Windowsの同nodeが返した未修飾DDInstall基本節です
 * @param[in] nodeIds 同nodeが返したHardware IDと元順の全Compatible IDです
 * @param[out] matchedRow 実選択と一致する公式対象の元行です
 * @param[out] selected 成功時だけ元用途、実導入節と必要関係を保持します
 * @return 元行と同じ元INFの選択関係が一致した場合0、拒否または読取失敗はHRESULTです
 * @pre originalとselectedは異なるobjectです。呼出し側が同じ元署名と閉包を確認します
 * @note 現在の端末と順位、必要ファイルの作用、導入権限は別に確認します
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSelectedScopedInfRelations(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &original, std::wstring_view modelsSection,
	std::wstring_view basicSection, std::span<const std::wstring> nodeIds,
	OfficialInfScopedModelMatch &matchedRow, OfficialInfPackage &selected) ;

//------------------------------------------------------------------------------
/**
 * @brief INFと対応catalogのWindows driver署名およびsigner allowlistを検証する。INFと対応catalogの署名を検証する
 *        SetupVerifyInfFileをWindows driver署名の正本とし、返されたcatalogとsignerをProvider固定allowlistへ完全一致させる
 * @param[in] workspace Package fileを所有する保護workspace
 * @param[in] package 構造検証済みのINF package
 * @param[in] acceptedSigners 許可するWindows driver signer表示名群。 許可するdriver signer表示名群
 * @return 署名とcatalog名とsignerが一致した場合は0、それ以外はHRESULT。 署名、catalog名、signer一致時は0、それ以外はHRESULT
 * @note SetupVerifyInfFileはblockingし得るためProvider worker threadから呼び出す
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialInfCatalogSignature(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::span<const std::wstring_view> acceptedSigners) ;

//------------------------------------------------------------------------------
/**
 * @brief INF署名、signer、およびINFと全参照fileのcatalog member hashを検証する。INF package全体のcatalog整合性を検証する
 *        SetupAPIでINF signerを確定した後、INF自身と全参照fileを同じCATのmemberとして検証し、部分検証を候補化しない。静的参照検査でsourceが0件と確定した場合も、
 *        INF自身のmember検証を省略しない
 * @param[in] workspace Package fileを所有する保護workspace
 * @param[in] package 構造検証済みのINF package
 * @param[in] acceptedSigners 許可するWindows driver signer表示名群。 許可するdriver signer表示名群
 * @return 全署名・hash検証成功時は0、最初に失敗した検証のHRESULT。 署名と全member hashが有効なら0、それ以外はHRESULT
 * @note 本関数の成功後だけ、現在deviceとのlocal PnP ID照合へ進める
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialInfPackageIntegrity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::span<const std::wstring_view> acceptedSigners) ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsが検証したsignerと同一CATの全memberを共通経路で検査する
 * @param[in] workspace INF閉包を所有する保護領域
 * @param[in] package 構造と全参照fileを検査したINF
 * @return SetupVerifyInfFile成功、非空signer、同一CAT、全member合格時0、それ以外はHRESULT
 * @note Maker表示名をsignerと比較しない。Windows署名失敗やtrust未確立を成功へ変換しない。静的参照検査でsourceが0件と確定した場合も、INF自身を必ずCATへ照合
 *       する。収集用の標準メディアチェンジャーでは同CATのAMD64 SYSとWindowsの保護イベント資源を確認する
 * @note 混在シリアルの私有収集では、元SYSを同じ保護領域で固定し、CAT照合後にAMD64形式を確認する
 * @note Blockingするためworkerから呼ぶ。成功は導入policy・実device適合・公式由来を保証しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyWindowsInfPackageIntegrity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package) ;

//------------------------------------------------------------------------------
/**
 * @brief 公式CABの表示クラスと単一KMDFドライバーの参照を確認する
 * @param[in] workspace 同じ元INFと署名済みCATメンバーの保護領域
 * @param[in] entries 展開時ハッシュを固定した元CABの全ファイル
 * @param[in] package 同じ公式Modelsと全CATメンバーを検査済みの基本INF
 * @return 明示OSの全公式対象が同じSYSと表示クラスへ結合した場合true
 * @pre 同じ閉包の署名と全CAT所属の検査に成功していること
 * @note Windows側のファイルやレジストリを更新せず、収集用の内容確認だけを行う
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool verifyScopedDeclarativeKernelReferences(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &package) ;

//------------------------------------------------------------------------------
/**
 * @brief 公式Net対象のイベント参照を署名済みSYSと収集側Windows標準DLLへ結ぶ
 * @param[in] workspace 同一元INFとCATメンバーの保護領域
 * @param[in] entries 全元ファイルのハッシュを固定した抽出一覧
 * @param[in] package 同じ公式Modelsと全CATメンバーを検査した基本INF
 * @param[in,out] effects 同一INFの公式対象の作用棚卸し。成功した起点数を保持する
 * @return 対象外または全対象の参照検査完了は0、元の読取・形式・信頼失敗はHRESULT
 * @pre 同じ閉包のverifyWindowsInfPackageIntegrityに成功していること
 * @note 収集側Windowsの証拠を得る。端末固有のDLLや他の作用・参照は別に検査する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyScopedNetworkEventFiles( const OfficialDownloadWorkspace	 &workspace,
														std::span<const OfficialZipEntry> entries,
														const OfficialInfPackage		 &package,
														MaintenanceInfStructure			 &effects) ;

/** @brief 元の一コピーの媒体と全バイトを保持する比較用証拠です */
struct OfficialScopedNetworkSourceFile {
	/// 元CATに属する署名閉包内のファイル位置
	std::wstring	   relativePath ;
	/// 元媒体の完全SHA-256
	std::wstring	   sha256 ;
	/// 照合した元媒体の全byte数
	std::uint64_t	   bytes{} ;
	/**
	 * @brief 同じ用途の元ファイルを再検証後の元位置と全バイトへ照合する
	 * @param[in] other 再取得した同じ用途の証拠
	 * @return 位置、SHA-256、サイズの全値一致時true
	 */
	[[nodiscard]] bool operator==( const OfficialScopedNetworkSourceFile &other) const = default ;
} ;

/** @brief 同じ署名済みNetの一実選択と、現在のWindowsで確認したファイル作用です */
struct OfficialScopedNetworkEffects {
	/// 選択関係と全作用を読み取った同一INFのSHA-256です
	std::wstring								 infSha256 ;
	/// 公式Modelsで確定済みのWindows nodeの基本導入節です
	std::wstring								 basicSection ;
	/// 現在OSで実在する装飾済み導入節です
	std::wstring								 installSection ;
	/// 実選択の唯一の関連カーネルサービスです
	std::wstring								 serviceName ;
	/// 元SYSと、該当時の補助データ・無線拡張DLLを用途順に保持します
	std::vector<OfficialScopedNetworkSourceFile> sourceFiles ;
	/// 同じイベント登録が使う現在OSの標準DLLとその署名・保護情報です
	WindowsSystemFileTrust						 eventResource ;
	/**
	 * @brief 同一選択の再読取り結果を全項目で比較します
	 * @param[in] other 再検査した同じ選択の効果です
	 * @return 元INF・実節・媒体と標準DLLが完全一致する場合trueです
	 */
	[[nodiscard]] bool operator==( const OfficialScopedNetworkEffects &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ公式Netの実選択が参照する媒体、サービスとWindowsイベント資源を照合します
 * @param[in] workspace 元の署名閉包を保持する管理者保護領域です
 * @param[in] entries 同じ閉包の元サイズと元ハッシュの一覧です
 * @param[in] selected 元行と同じWindows選択節を確認したINFです
 * @param[out] effects 全作用と現在の標準DLLを確認した場合だけの比較用結果です
 * @param[in] inboxNeeds 同一元CABと現在のWindowsへ外部Needsを照合する同期検査です。同梱依存のない経路はnullです
 * @return 実選択の媒体・サービス・イベント参照が一致した場合0、元拒否はHRESULTです
 * @pre 呼出し側で元署名レコード・元閉包の全CATと端末の選択行を確認します
 * @note 読取り専用です。未検証の必要役割、Windows依存や導入権限を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifySelectedScopedNetworkInfEffects(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &selected, OfficialScopedNetworkEffects &effects,
	const ScopedInboxNeedsVerifier *inboxNeeds = nullptr) ;

//------------------------------------------------------------------------------
/**
 * @brief 同保護INF/CATの全memberを検査して実Windows signer名だけを返します
 * @param[in] workspace 同原閉包を所有する保護領域です
 * @param[in] package 同原INFとCATを示す構造検査済みmetadataです
 * @param[out] publisher 同Windows署名/全member成功時だけ実DigitalSignerです。失敗時空です
 * @return 同exact CAT、Windows署名、全member成功0、失敗は元HRESULTです
 * @note INF Providerを代入せず、公式性/実端末適合/導入許可を発行しません。Workerでblockingします
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readWindowsInfPackagePublisher( const OfficialDownloadWorkspace &workspace,
														 const OfficialInfPackage		 &package,
														 std::wstring &publisher) ;

//------------------------------------------------------------------------------
/**
 * @brief INFが参照する全fileのAuthenticode署名とpublisherを検証する。INF参照fileの埋込み署名を検証する。固定SHA-256で拘束したarchive内の実行
 *        binaryを個別検証し、未署名fileまたは異なるpublisherを一件でも受理しない
 * @param[in] workspace Package fileを所有する保護workspace
 * @param[in] package 構造検証済みでsourceFilesが確定したINF package。 構造検証済みのINF package
 * @param[in] requiredRelativePaths 署名とINF参照を必須にするworkspace相対path群。 署名を必須にする相対path群
 * @param[in] acceptedSigners 許可する埋込み署名publisher表示名群。 許可する署名publisher表示名群
 * @return 全指定fileのINF参照、署名、publisherが有効なら0、最初の失敗はHRESULT。 全参照fileの署名とpublisherが有効なら0
 * @note CAT member hashを置換する一般fallbackではなく、固定archive hashと併用する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialInfEmbeddedFileSignatures(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::span<const std::wstring_view> requiredRelativePaths,
	std::span<const std::wstring_view> acceptedSigners) ;

//------------------------------------------------------------------------------
/**
 * @brief INFの検証済みPnP IDを現在deviceのHardware IDとCompatible IDへ照合する。INFを現在deviceのPnP IDへ照合する。PnP IDは
 *        worker内だけで大文字小文字を除く完全一致に使用し、部分一致、prefix一致、空IDによる適用範囲拡張を行わない
 * @param[in] package 構造検証済みのINF package
 * @param[in] deviceHardwareIds 現在deviceからworker内で取得したHardware ID群。 現在deviceのHardware ID群
 * @param[in] deviceCompatibleIds 現在deviceからworker内で取得したCompatible ID群。 現在deviceのCompatible ID群
 * @return Hardware ID、Compatible IDの優先順で得た完全一致結果。該当なしはNone
 * @note IDはnetwork、UI、logへ渡さず、呼出し中のlocal matchingだけに使用する
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialInfDeviceMatch matchOfficialInfToDevice(
	const OfficialInfPackage &package, std::span<const std::wstring_view> deviceHardwareIds,
	std::span<const std::wstring_view> deviceCompatibleIds) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 同じHINF/source IDの完全source/media応答を共有します
 * @param[in] inf 同期借用する一INF handleです
 * @param[in] fileName 元basenameです
 * @param[out] sourceDirectory 完全取得した元subdirです
 * @param[out] mediaDirectory installation-root相対の元媒体です
 * @return 完全取得0、欠損・曖昧・部分応答・root-only policy拒否のHRESULTです
 * @note 保護領域とCAT/member検査は呼出し側で別途必要です
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialInfSourceDirectories( void *inf, const std::wstring &fileName,
														   std::wstring &sourceDirectory,
														   std::wstring &mediaDirectory) ;
} // namespace drivercrate
