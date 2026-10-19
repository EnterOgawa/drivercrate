//------------------------------------------------------------------------------
/**
 * @file official_driver_package.h
 * @brief 公式標準INF driver package検証定義。
 * @version 01.17.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member／PnP照合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  DriverVer日付取得追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  INF signature allowlist追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  参照file埋込み署名検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用Provider名検証mode追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要printer構造policy追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  選択的driver閉包policy追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows検証済みsignerの共通署名policyを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  明示依存の存在観測を内容署名から分離。
 * Ver.01.03.00 Shunji Ogawa  2026/10/04  無作用の空CoInstaller参照の限定受理を明記。
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  保守専用の非実行参照棚卸しを導入構造と分離。
 * Ver.01.05.00 Shunji Ogawa  2026/10/05  保守相対参照の先頭現在directory解決を明記。
 * Ver.01.05.01 Shunji Ogawa  2026/10/05  空source時もINF自身のCAT member検証を要求する。
 * Ver.01.06.00 Shunji Ogawa  2026/10/05  保守棚卸しの両標準INF識別子受理を明記。
 * Ver.01.07.00 Shunji Ogawa  2026/10/05  保守内容限定の非圧縮EXE参照policyを追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/05  選択導入処理の非実行作用・参照棚卸しを追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/05  棚卸し専用の節・作用・参照容量の有限拡張を明記。
 * Ver.01.10.00 Shunji Ogawa  2026/10/06  選択処理の未解釈範囲を非許可の不足観測へ分離。
 * Ver.01.11.00 Shunji Ogawa  2026/10/07  保守専用の全Models構造とnull service・独立状態を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/07  明示seedの有限file参照と位置未確定の独立観測を追加。
 * Ver.01.12.01 Shunji Ogawa  2026/10/07  named必須構造とnullの診断説明を整合。
 * Ver.01.12.02 Shunji Ogawa  2026/10/07  展開済みbinaryのnamed固有導入先とsource限定照合を明記。
 * Ver.01.12.03 Shunji Ogawa  2026/10/07  相対named13の元source位置と実Store／端末未確認の分離を明記。
 * Ver.01.13.00 Shunji Ogawa  2026/10/13  元INFの必要構成と役割別関係の有限契約を追加。
 * Ver.01.14.00 Shunji Ogawa  2026/10/13  私有node選択節と全潜在importの内容集合を分離。
 * Ver.01.14.01 Shunji Ogawa  2026/10/13  必要SWC serviceの同INF参照許可と保守包括EXE policyを区別。
 * Ver.01.15.00 Shunji Ogawa  2026/10/13  選択Needsの同HINF元source位置の読取契約を公開。
 * Ver.01.16.00 Shunji Ogawa  2026/10/14  元Models/ID種別/ClassGUIDの非許可公開receiptを追加。
 * Ver.01.17.00 Shunji Ogawa  2026/10/14  同Windows INF/CAT検査から実publisherの非許可metadataを追加。
 * </pre>
 *
 * @note 保護workspaceへ展開済みの標準INF packageを、現在のWindows x64に対する構造、適用ID、参照fileおよびcatalog署名の境界で検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include "platform/inf_dependency_plan.h"
#include "platform/official_zip.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/** @brief 現OSでWindowsが選択した一Models節の公開IDだけを保持します。 */
struct OfficialInfPublishedModelSection {
	/// 原HINFが返したModels節名です。端末選択nodeではありません。
	std::wstring			  modelSection ;
	/// 各Models行の第2 fieldに明示された公開Hardware IDです。
	std::vector<std::wstring> hardwareIds ;
	/// 各Models行の第3 field以降に明示された公開Compatible IDです。
	std::vector<std::wstring> compatibleIds ;
} ;

/** @brief 同INF原hash/Models/ClassGUIDの読取り結果です。署名や取得/導入許可を持ちません。 */
struct OfficialInfPublishedIdentity {
	/// 同INFの前後読取りで一致した小文字SHA-256です。
	std::wstring								  infSha256 ;
	/// Versionの原ClassGUIDです。推測や端末情報を使いません。
	std::wstring								  classGuid ;
	/// 最大128節の現OS選択結果です。空/部分失敗を公開しません。
	std::vector<OfficialInfPublishedModelSection> models ;
} ;

/**
 * @brief 標準INF packageの構造検証上限と許可値を表す。
 */
struct OfficialInfInspectionPolicy {
	/// 一INFから保持するPnP ID数上限。
	std::size_t						   maximumHardwareIds ;
	/// 一INFから保持する参照file数上限。
	std::size_t						   maximumSourceFiles ;
	/// 許可するINF class名群。
	std::span<const std::wstring_view> acceptedClasses ;
	/// 許可するINF Provider名群。
	std::span<const std::wstring_view> acceptedProviders ;
	/// 許可するVersion Signature値群。
	std::span<const std::wstring_view> acceptedSignatures ;
	/// trueの場合はCATで保護された非空Provider名を受理し、allowlistを使用しない。
	bool							   acceptAnyProvider{} ;
	/// trueの場合は一つ以上のSYS参照を必須にする。
	bool							   requireDriverBinary{true} ;
	/// trueの場合はINFが参照しないprogramもarchive全体のpolicy違反とする。
	bool							   rejectUnreferencedPrograms{true} ;
	/// trueの場合は任意command実行、外部INF登録と非空・未知CoInstaller動作を拒否する。明示空参照だけは許可する。
	bool							   rejectInstallActions{} ;
	/// trueの場合は未解決のInclude／Needs／AddComponentを方式未対応として拒否する。
	bool							   rejectExternalDependencies{} ;
	/// trueは保守内容検査だけの非圧縮EXE参照です。通常はfalseで、必要SWCは同INF service/copy/sourceを別検査します。
	bool							   allowReferencedExecutablesForContent{} ;
	/// trueは元CopyINF/AddComponentを有限driver構成解析へ渡します。導入許可ではありません。
	bool							   allowRequiredDriverComponents{} ;
} ;

/** @brief 選択DDInstall.Componentsの元宣言です。IDはworker内だけで保持します。 */
struct OfficialInfComponentReference {
	/// 同INFで一意な元AddComponent名です。
	std::wstring			  name ;
	/// SWC接頭辞を加えた元ComponentIDsです。名称から推測しません。
	std::vector<std::wstring> hardwareIds ;
	/** @brief 元宣言の全値を比較します。
	 * @param[in] other 比較中だけ借用する元宣言です。
	 * @return 全fieldが一致する場合trueです。
	 */
	bool operator==( const OfficialInfComponentReference &other) const = default ;
} ;

/**
 * @brief 現在のWindows x64に適用可能な一つの標準INFの検証済み構造を表す。
 */
struct OfficialInfPackage {
	/// Workspace基準のINF相対path。
	std::wstring							   infRelativePath ;
	/// INFと同じdirectoryにあるCAT相対path。
	std::wstring							   catalogRelativePath ;
	/// Allowlistと一致したINF Class。
	std::wstring							   className ;
	/// Allowlistと一致したINF Provider。
	std::wstring							   providerName ;
	/// DriverVer directiveの日付field。
	std::wstring							   driverDate ;
	/// DriverVer directiveのversion field。
	std::wstring							   driverVersion ;
	/// 選択Models sectionにある一意のPnP ID群。
	std::vector<std::wstring>				   hardwareIds ;
	/// 現在architecture用の参照file相対path群。
	std::vector<std::wstring>				   sourceFiles ;
	/// 動作検査を要求したpolicyでInclude／Needs／AddComponentを観測した場合true。未検査時のfalseは不在証明ではない。
	bool									   hasExternalDependencies{} ;
	/// 元Classから分類した役割です。役割別検証を省略する許可ではありません。
	DriverPlanRole							   role{DriverPlanRole::BASE_DRIVER} ;
	/// 元VersionのClassGUIDです。役割INFでは正式GUIDを必須にします。
	std::wstring							   classGuid ;
	/// Extensionの元ExtensionIdをWindows GUIDへ解析した正規表記です。他の役割では空です。
	std::wstring							   extensionId ;
	/// 私有native nodeの基本名を現OSへ解決した実在DDInstallです。内容検査単独では空です。
	std::wstring							   selectedInstallSection ;
	/// 同じcompatible nodeの未修飾基本名です。内容検査単独では空で、導入権限にはなりません。
	std::wstring							   selectedBasicSection ;
	/// 同じcompatible nodeのWindows rankです。非選択importでは空で、独自rank判定に使用しません。
	std::optional<std::uint32_t>			   selectedNativeRank ;
	/// 全節の潜在CopyINF再帰importへ渡す安全なpackage相対pathです。機能必要性とは別です。
	std::vector<std::wstring>				   requiredInfPaths ;
	/// 同deviceで選択したDDInstallのCopyINFだけです。未選択節の参照を実行集合へ混ぜません。
	std::vector<std::wstring>				   activeRequiredInfPaths ;
	/// 元選択DDInstall.Componentsが宣言する必要子です。
	std::vector<OfficialInfComponentReference> requiredComponents ;
	/// 全明示節のInclude/Needsを検出した状態です。元OS/storeとpackageの充足は別検査です。
	bool									   unresolvedIncludeNeeds{} ;
} ;

/**
 * @brief 同保護元INFの私有node基本名から選択節の機能関係だけを解析します。
 * @param[in] workspace 元byte検査済みINFを所有し、同期終了まで生存する保護領域です。
 * @param[in] entries 全潜在importを含む元hash付きinventoryです。呼出し中だけ借用します。
 * @param[in] original 同保護元INFの内容検査metadataです。選択成功や導入権限は表しません。
 * @param[in] selectedBasicSection 同device/native nodeで確認した未修飾基本名です。空・NUL・過長は禁止です。
 * @param[out] selected 成功時だけ全importと選択機能関係を保持するcopyです。失敗時は空です。
 * @return 現OS Models所属/Windows装飾選択/実節/機能関係の確認0、その他は元HRESULTです。
 * @pre originalとselectedは異なるobjectです。同じ元byteの再確認を呼出し側で行います。
 * @note Worker内のread-only解析です。呼出し側の全byte再検査と同issuer bindingを代替しません。
 */
[[nodiscard]] NativeError inspectSelectedOfficialInfRelations(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &original, std::wstring_view selectedBasicSection,
	OfficialInfPackage &selected) ;

/**
 * @brief INFのPnP IDと現在deviceのPnP IDとの照合結果を表す。
 */
enum class OfficialInfDeviceMatch {
	/// 現在deviceへ完全一致するPnP IDがない。
	NONE,
	/// Compatible IDへ完全一致した。
	COMPATIBLE_ID,
	/// Hardware IDへ完全一致した。
	HARDWARE_ID,
} ;

/** @brief 保守専用参照棚卸しの到達段階。署名や導入許可を表さない。 */
enum class OfficialInfReferenceStage {
	/// 入力境界またはINF読取。
	OPEN,
	/// Version節とCAT位置。
	VERSION,
	/// SourceDisksFilesと媒体位置。
	SOURCES,
	/// 全sectionのCopyINFと外部依存。
	DEPENDENCIES,
	/// 参照棚卸し完了。参照先のbyte取得・署名検証は別途必要。
	INVENTORIED,
} ;

/**
 * @brief 保守PC専用の参照棚卸し。導入用packageと互換ではない。
 * @note 全sectionの過大近似であり、現在deviceの選択sectionを確定しない。
 */
struct OfficialInfReferenceInventory {
	/// 成功段階または最初の失敗段階。失敗時の他fieldは空。
	OfficialInfReferenceStage stage{OfficialInfReferenceStage::OPEN} ;
	/// 保護workspace基準の元INF位置。
	std::wstring			  infRelativePath ;
	/// 対応CAT位置。元inventoryに存在することだけを確認する。
	std::wstring			  catalogRelativePath ;
	/// Version節のclass表示。導入class許可ではない。
	std::wstring			  className ;
	/// 共通とamd64の全source参照。内容hashは未検証。
	std::vector<std::wstring> sourceFiles ;
	/// 同じdirectoryまたは子directoryの全CopyINF参照。欠落先も保持する。
	std::vector<std::wstring> copyInfPaths ;
	/// Include／Needs／AddComponentを観測した場合true。依存充足を表さない。
	bool					  hasExternalDependencies{} ;
	/// 既存の全section導入動作検査結果。0でも導入許可ではない。
	NativeError				  installActionsError{} ;
} ;

/** @brief 選択された導入処理の宣言種類。実行対応や許可を表さない。 */
enum class OfficialInfInstallEffectKind {
	/// 既知の標準directiveの存在。安全性や参照充足の認定ではない。
	STANDARD_DIRECTIVE,
	/// 非空CoInstaller節またはCoInstallers32登録。
	COINSTALLER,
	/// 任意commandを記載するdirective。
	COMMAND_EXECUTION,
	/// DLL登録・解除を記載するdirective。
	DLL_REGISTRATION,
	/// 別INFの取込みを記載するdirective。
	COPY_INF,
	/// registryの自動起動位置に対する宣言。
	REGISTRY_AUTORUN,
	/// Include・Needs・AddComponentの明示依存。
	EXPLICIT_DEPENDENCY,
	/// 未解釈のdirective。作用なしに読み替えない。
	UNKNOWN_DIRECTIVE,
} ;

/** @brief 選択処理から観測した一宣言。値やcommand本文は保持しない。 */
struct OfficialInfInstallEffect {
	/// worker内だけの宣言元section名。
	std::wstring				 section ;
	/// worker内だけのdirective名。registry行は検出した種類名だけ。
	std::wstring				 directive ;
	/// 宣言の種類。実行の有無は未検査。
	OfficialInfInstallEffectKind kind{OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE} ;
} ;

/** @brief 明示参照の種類。依存解決結果ではない。 */
enum class OfficialInfInstallReferenceKind {
	/// 同じINF内の処理またはdata section。
	LOCAL_SECTION,
	/// Includeに記載された別INF。
	INCLUDE_INF,
	/// CopyINFに記載された別INF。
	COPY_INF,
	/// CopyFilesの直接file参照。
	DIRECT_FILE,
} ;

/** @brief 一つの明示参照とmetadataの存在観測。実byte・依存充足は未検査。 */
struct OfficialInfInstallReference {
	/// worker内だけの参照元section名。
	std::wstring					section ;
	/// worker内だけの参照directive名。
	std::wstring					directive ;
	/// worker内だけのsection名または安全なworkspace相対file名。
	std::wstring					target ;
	/// 参照先の種類。
	OfficialInfInstallReferenceKind kind{OfficialInfInstallReferenceKind::LOCAL_SECTION} ;
	/// 同じINF節またはpackage内entryが存在する場合true。充足・署名の証明ではない。
	bool							targetPresent{} ;
} ;

/** @brief 選択棚卸しが解釈していない範囲。導入拒否や全構文の完全性ではない。 */
enum class OfficialInfInstallCoverageKind {
	/// Property・INI・ProfileItems等の参照先を走査していない。
	UNFOLLOWED_SECTION_REFERENCES,
	/// AddService第4 fieldのevent-log節を走査していない。
	UNFOLLOWED_SERVICE_EVENTLOG,
	/// AddSoftwareの独立software導入範囲を評価していない。
	SOFTWARE_INSTALLATION_NOT_ASSESSED,
	/// 未知directiveの意味を解釈していない。
	UNKNOWN_DIRECTIVE,
	/// 非空data節の本文を処理指示として解釈していない。
	DATA_ROWS_NOT_INTERPRETED,
	/// 非空registry節の全作用範囲を評価していない。
	REGISTRY_SCOPE_NOT_ASSESSED,
} ;

/** @brief 一宣言または非空節に結合した解析不足。本文・値は保持しない。 */
struct OfficialInfInstallCoverageGap {
	/// worker内だけの元節。値や実IDではない。
	std::wstring				   section ;
	/// worker内だけの元directive。節本文全体の場合は空。
	std::wstring				   directive ;
	/// 不足種類。空集合も完全性や導入許可を表さない。
	OfficialInfInstallCoverageKind kind{OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE} ;
} ;

/**
 * @brief 現OSのModelsから選んだ一導入名の有限棚卸し。導入型へ変換しない。
 * @note PnP ID・registry値・command本文を保持せず、全class固有作用を解釈したと主張しない。
 */
struct OfficialInfInstallInventory {
	/// 保護workspace内の元INF相対path。worker内だけで保持する。
	std::wstring							   infRelativePath ;
	/// 解析前後に一致したINF hash。公式由来やCAT署名の証明ではない。
	std::wstring							   infSha256 ;
	/// Models第1 fieldで確認した元の導入名。
	std::wstring							   baseInstallSection ;
	/// Windowsが現在OS／x64に選び、実在を確認したDDInstall名。
	std::wstring							   selectedInstallSection ;
	/// 一度だけ走査したsection名群。共有・循環参照の再走査を止める。
	std::vector<std::wstring>				   visitedSections ;
	/// 有限範囲で観測した宣言。未知を含む。
	std::vector<OfficialInfInstallEffect>	   effects ;
	/// 明示参照辺。欠落・共有・循環も保持し、充足としない。
	std::vector<OfficialInfInstallReference>   references ;
	/// 最大4,096の未解釈観測。空でも全classの完全性を認定しない。
	std::vector<OfficialInfInstallCoverageGap> coverageGaps ;
	/// Models選択を除く処理範囲の走査行数。最大4,096。
	std::size_t								   scannedLines{} ;
} ;

/** @brief 保守検査の独立した到達状態。未検査を不適合にしない。 */
enum class MaintenanceInspectionState {
	/// この軸を検査していない。
	NOT_CHECKED,
	/// この軸の検査を通過した。導入許可ではない。
	PASSED,
	/// 実施した検査に失敗した。driver不正の包括的断定ではない。
	FAILED,
	/// この方式を扱えない。driverが存在しないとは言わない。
	UNSUPPORTED,
} ;

/** @brief 保守検査の一軸と元診断値。 */
struct MaintenanceInspectionFinding {
	/// 未検査・合格・検査失敗・方式未対応。
	MaintenanceInspectionState state{MaintenanceInspectionState::NOT_CHECKED} ;
	/// 検査失敗または方式未対応のHRESULT。それ以外は0。
	NativeError				   error{} ;
} ;

/** @brief 保守専用の内容構造。署名・driver-only・適合・実行方式の認定ではない。 */
enum class MaintenanceInfContentKind {
	/// 構造を確定できない、または由来未確認の依存だけを観測した。
	UNKNOWN,
	/// Package内fileの宣言または用途参照を観測した。
	PACKAGE_FILES,
	/// 限定したempty associated service構造を観測した。全file参照確認は別軸。
	NULL_DRIVER,
	/// 同OSのinbox由来を別検査で確認した依存構造。名前だけで設定しない。
	INBOX_DEPENDENCY,
	/// nullとfile参照・依存、または複数の異なる選択構造を観測した。
	MIXED,
} ;

/** @brief 全必要file参照を実byteへ結合した検査の状態。 */
enum class MaintenanceInfReferenceCoverage {
	/// 全参照閉包をまだ検査していない。空参照集合を不在証明にしない。
	NOT_CHECKED,
	/// 全必要参照の対応位置とbyteを結合した。作用・署名・適合の合格ではない。
	COMPLETE,
	/// 検査済みで未追跡用途・欠落・対応位置未確定が残る。
	INCOMPLETE,
} ;

/** @brief 同一OS観測での明示依存のsummary。全payload署名と独立する。 */
enum class MaintenanceInfDependencyState {
	/// 依存棚卸しまたは照会が未実施。
	NOT_CHECKED,
	/// 全到達節の棚卸しで明示依存なしを確認した。
	NONE,
	/// 明示参照を観測したが、byte・由来・署名の確認は完了していない。
	OBSERVED,
	/// 照会済みで欠落・曖昧・循環・不正参照が残る。
	UNRESOLVED,
	/// 同OS観測の全明示辺とseedのbyte・由来・INF署名を確認した。
	RESOLVED_CURRENT_OS,
} ;

/** @brief 外へ射影できる数・enum・診断値だけの依存summary。 */
struct MaintenanceInfDependencySummary {
	/// 未実施を不在または解決へ昇格しない独立状態。
	MaintenanceInfDependencyState state{MaintenanceInfDependencyState::NOT_CHECKED} ;
	/// 最初の未解決理由。未照会時はNOT_CHECKED。
	InfDependencyReason			  reason{InfDependencyReason::NOT_CHECKED} ;
	/// 元の照会・検証HRESULT。観測だけの場合は0。
	NativeError					  error{} ;
	/// 棚卸しで観測した明示参照数。0単独では不在証明ではない。
	std::size_t					  observedReferenceCount{} ;
	/// 署名まで検証した対象INF数。全payloadの検査数ではない。
	std::size_t					  resolvedInfCount{} ;
} ;

/** @brief 保守構造で未対応または不正になった具体的な理由。 */
enum class MaintenanceInfStructureReason {
	/// 内容Classが解析policyの集合外。
	CLASS_NOT_SUPPORTED,
	/// 必須AddService fieldまたはnamed service-install項目が欠落・明示空。
	MISSING_SERVICE_FIELD,
	/// 展開後もtokenが残り数値を確定できない。
	UNRESOLVED_FLAGS_TOKEN,
	/// 全fieldが符号なし十進／0x十六進の数値でない。
	INVALID_FLAGS_NUMBER,
	/// 数値がuint32_tの範囲を超える。
	FLAGS_OVERFLOW,
	/// 終端込みのfield必要長が4,096文字を超える。
	FLAGS_TOO_LONG,
	/// Windowsが扱う数値表現でも今回の厳密形式と一致しない。
	FLAGS_FORMAT_NOT_SUPPORTED,
	/// 限定nullの2、namedの0／2以外で作用未評価のbit組合せ。
	FLAGS_NOT_SUPPORTED,
	/// Namedのidentityに未展開token等があり限定構造を確定できない。
	NAMED_SERVICE_NOT_ASSESSED,
	/// 一選択に複数のassociated serviceがある。
	MULTIPLE_ASSOCIATED_SERVICES,
	/// Empty serviceにも非空のservice-install／event-log参照がある。
	NULL_SERVICE_SECTION_REFERENCE,
	/// 対応外節・後続作用field・必須参照不在、または必須項目の不正／未対応。
	SERVICE_DECLARATION_NOT_SUPPORTED,
	/// 未解釈directiveを作用なしへ読み替えない。
	UNKNOWN_DIRECTIVE,
} ;

/** @brief 元節・directiveへ結合したworker内だけの具体的診断。 */
struct MaintenanceInfStructureIssue {
	/// 元INF内の宣言節名。UIや通常logへ出さない。
	std::wstring				  section ;
	/// 宣言名。値やcommand本文は保持しない。
	std::wstring				  directive ;
	/// 未対応・不正を区別する理由。
	MaintenanceInfStructureReason reason{MaintenanceInfStructureReason::UNKNOWN_DIRECTIVE} ;
	/// 個別の到達状態とHRESULT。全体読取失敗と区別する。
	MaintenanceInspectionFinding  finding ;
} ;

/** @brief AddServiceを非実行で読んだ構造。空名とfield欠落を区別する。 */
struct MaintenanceInfServiceStructure {
	/// 元の宣言節。worker内だけで保持する。
	std::wstring				 section ;
	/// Fieldが存在して空の場合もそのまま保持するservice名。
	std::wstring				 serviceName ;
	/// Keyを除く元field数。欠落と明示空の区別に使う。
	std::uint32_t				 fieldCount{} ;
	/// 全数値解析に成功した場合だけのflags。失敗を0や2へ補完しない。
	std::optional<std::uint32_t> flags ;
	/// 非空の場合だけ辿る明示service-install節名。
	std::wstring				 serviceInstallSection ;
	/// 非空の場合だけ辿る明示event-log節名。
	std::wstring				 eventLogSection ;
	/// 数値と必須named構造または限定nullの結果。完全な実行意味・署名・導入許可ではない。
	MaintenanceInspectionFinding parser ;
} ;

/** @brief 全file参照検査へ引き継ぐ具体的な未検査用途。 */
struct MaintenanceInfFileUse {
	/// 宣言元節。source宣言もVersionもworker内だけで保持する。
	std::wstring section ;
	/// CopyFiles／ServiceBinary／LayoutFile等の具体的な宣言名。
	std::wstring directive ;
	/// 展開済み用途field。対応位置・由来・実byteはまだ未検査。
	std::wstring target ;
} ;

/** @brief 保守file参照の位置観測。実byte・署名の証拠とは互換でない。 */
enum class MaintenanceInfFileLocation {
	/// 位置を検査していない。
	NOT_CHECKED,
	/// 固定member一覧へ一意に結合した。実byteと署名は別途必要。
	LOCATED,
	/// 明示位置を照会したがmemberがない。
	MISSING,
	/// 位置またはfile用途の解釈が未対応。
	UNSUPPORTED,
} ;

/** @brief 元宣言と具体的な不足を保持するworker内file参照。 */
struct MaintenanceInfFileReference {
	/// 元の明示節名。
	std::wstring			   section ;
	/// 元directiveまたは未解釈用途の名称。
	std::wstring			   directive ;
	/// 元の展開後参照。UIとlogへ出力しない。
	std::wstring			   target ;
	/// 安全なpackage相対位置。位置未確定では空。
	std::wstring			   relativePath ;
	/// 位置だけの観測。LOCATEDも署名成功ではない。
	MaintenanceInfFileLocation location{MaintenanceInfFileLocation::NOT_CHECKED} ;
	/// 不在・位置未対応の元HRESULT。LOCATEDでは0。
	NativeError				   error{} ;
} ;

/** @brief 一INFの明示seedからの有限参照閉包。導入用packageではない。 */
struct MaintenanceInfReferences {
	/// 固定元INFのpackage相対位置。
	std::wstring							 infRelativePath ;
	/// 全読取前後に一致した元INFのSHA-256。
	std::wstring							 infSha256 ;
	/// 宣言CATの安全位置。依存資料の未宣言では空。rootの必須CATは構造入口で要求する。
	std::wstring							 catalogRelativePath ;
	/// 明示seedと到達local節の元参照・作用不足。
	OfficialInfInstallInventory				 inventory ;
	/// INF／CAT・source・具体file用途と位置未確定の全観測。
	std::vector<MaintenanceInfFileReference> files ;
	/// 位置が固定memberへ結べたsource群。実byte・CAT memberは別途必要。
	std::vector<std::wstring>				 sourceFiles ;
	/// source不在と明示空を区別する。falseだけを無参照証明にしない。
	bool									 sourceSectionPresent{} ;
	/// 全必要参照の位置棚卸し。依存先／署名／作用の完全性ではない。
	MaintenanceInfReferenceCoverage referenceCoverage{MaintenanceInfReferenceCoverage::NOT_CHECKED} ;
} ;

/**
 * @brief 一INFの明示seedからlocal file用途と同節依存を同期・有限に棚卸しする。
 * @param[in] workspace 呼出し全期間固定される保護所有領域。
 * @param[in] entries 閉じたarchive member一覧。未抽出memberも位置照合に使う。
 * @param[in] infRelativePath 読取前後に元byteへ一致させる最大4 MiBのINF。
 * @param[in] seeds 原明示節群。0～1,024。suffix補完と別節Include借用をしない。
 * @param[in] policy 既存の内容参照数と非圧縮EXE限定条件。導入policyへ転用しない。
 * @param[out] references 全体成功時の位置観測。全体読取・path・容量失敗では空。
 * @return 観測成功0、重大な読取・入力・容量・元byte差のHRESULT。
 * @pre 入力と出力はaliasしない。workerから同期呼出しし、同時にworkspaceを変更しない。
 * @note 一INF4 MiB、1,024節／4,096行・参照／64 field。依存先の解決と署名は別検査。
 * 展開済みbinaryは到達named list固有DestinationDirsと明示sourceへ限定照合する。
 * 親default文脈のない直接copy／defaultは位置未対応のまま保持する。
 * DIRID13は同名とSourceDisksFiles／DestinationDirs subdir一致を追加要求する。
 * 同HINFの成功したdot-relative named13全targetは全候補・元source行の一意性も要求する。
 * LOCATEDとcoverageは固定package内の元source位置だけで、実byte／CATは後段で検証する。
 * 実Driver Store導入先の充足・端末適合・rank／grantと導入許可は未確認のまま分離する。
 * @see docs/adr/0313-maintenance-expanded-service-binary-source-binding.md
 * @see docs/adr/0314-maintenance-unstaged-dirid13-source-content-separation.md
 */
[[nodiscard]] NativeError inspectMaintenanceInfReferences(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view infRelativePath, std::span<const std::wstring> seeds,
	const OfficialInfInspectionPolicy &policy, MaintenanceInfReferences &references) ;

/** @brief 現在OSの一DDInstall選択と付随節の保守構造。 */
struct MaintenanceInfInstallStructure {
	/// 既存棚卸しと同じ有限graph型。PnP ID・command本文を持たない。
	OfficialInfInstallInventory					inventory ;
	/// 対応Services等から観測した全AddService構造。
	std::vector<MaintenanceInfServiceStructure> services ;
	/// 未対応・不正を元宣言へ結合した具体的診断。
	std::vector<MaintenanceInfStructureIssue>	issues ;
	/// 全file参照検査へ渡す具体的な用途観測。空でも完全性を認定しない。
	std::vector<MaintenanceInfFileUse>			fileUses ;
	/// この選択の構造種別。依存のinbox由来を推測しない。
	MaintenanceInfContentKind					contentKind{MaintenanceInfContentKind::UNKNOWN} ;
	/// 構造の解析到達だけの結果。必要byteと署名検査は別。
	MaintenanceInspectionFinding				parser ;
} ;

/** @brief 保守worker専用の一INF構造。導入package・閉包へ変換しない。 */
struct MaintenanceInfStructure {
	/// 保護workspace基準の元INF位置。worker内だけで保持する。
	std::wstring								infRelativePath ;
	/// 解析前後で一致した元INF SHA-256。署名・公式由来の証明ではない。
	std::wstring								infSha256 ;
	/// 固定entriesに存在するCAT位置。実byteと署名は未検査。
	std::wstring								catalogRelativePath ;
	/// Version節のClass。内容解析対象であり導入許可ではない。
	std::wstring								className ;
	/// Version節の非空Provider名。署名者ではない。
	std::wstring								providerName ;
	/// DriverVerの日付field。
	std::wstring								driverDate ;
	/// DriverVerのversion field。
	std::wstring								driverVersion ;
	/// 現OS／x64用ModelsのPnP ID。workerのlocal照合だけへ渡す。
	std::vector<std::wstring>					hardwareIds ;
	/// 現OS／x64用Modelsにある全一意DDInstall名の構造。失敗行も保持する。
	std::vector<MaintenanceInfInstallStructure> installs ;
	/// Version LayoutFile等の具体的な未追跡file用途。
	std::vector<MaintenanceInfFileUse>			fileUses ;
	/// 現OS用SourceDisksFiles節が存在する場合true。無参照証明ではない。
	bool										sourceSectionPresent{} ;
	/// 現OS用sourceの宣言名。対応位置と実byteは未検査。
	std::vector<std::wstring>					sourceFileNames ;
	/// 全現在OS選択を併合した内容構造。
	MaintenanceInfContentKind					contentKind{MaintenanceInfContentKind::UNKNOWN} ;
	/// 全体読取後の個別構造解析結果。署名・依存充足ではない。
	MaintenanceInspectionFinding				parser ;
	/// 全必要file参照の独立検査。構造解析だけではNOT_CHECKED。
	MaintenanceInfReferenceCoverage referenceCoverage{MaintenanceInfReferenceCoverage::NOT_CHECKED} ;
	/// Root INFと確認したlocal参照の署名結果。構造解析だけではNOT_CHECKED。
	MaintenanceInspectionFinding	rootIntegrity ;
	/// 同節の明示依存観測と独立証拠のsummary。閉包検査は別工程。
	MaintenanceInfDependencySummary dependency ;
} ;

/**
 * @brief 現OSの全DDInstallと付随節を有限に保守構造へ解析する。
 * @param[in] workspace 同期借用する保護領域。呼出し中の変更は禁止する。
 * @param[in] entries 固定済みの最大32,768 entry。INFは一意で最大4 MiB。
 * @param[in] infRelativePath 安全な一INF相対path。worker外へ保存しない。
 * @param[in] policy 有限ID／source上限と内容Class・Provider・構文識別子のpolicy。
 * @param[out] structure 全体読取・元byte再照合に成功した場合だけ観測を保持する。
 * @return 全観測完了0。全体入力・読取・容量・改変・例外失敗ではHRESULTと空結果。
 * @note 個別未対応はUNSUPPORTED／ERROR_NOT_SUPPORTED、不正flagsはFAILED／ERROR_INVALID_DATA等を
 * 各選択へ残す。最大1,024節・4,096行・4,096各項目・一行64 fieldをINF全体で消費する。
 * SetupAPIが展開したflagsだけを厳密解析し、元Strings値の非切捨てまで認定しない。
 * 依存閉包・全file coverage・署名・端末適合・導入許可は発行せず、workerでblockingする。
 * @see docs/adr/0311-maintenance-inf-structure-and-install-policy-separation.md
 */
[[nodiscard]] NativeError inspectMaintenanceInfStructure( const OfficialDownloadWorkspace &workspace,
														 std::span<const OfficialZipEntry> entries,
														 std::wstring_view infRelativePath,
														 const OfficialInfInspectionPolicy &policy,
														 MaintenanceInfStructure &structure) ;

/**
 * @brief 現OSのModelsに属する導入名とその作用・参照を実行せず棚卸しする。
 * @param[in] workspace 同期借用する保護領域。呼出し中の変更は禁止する。
 * @param[in] entries 有限の元package一覧。対象INFは一意で実size一致を要求する。
 * @param[in] infRelativePath 最大4 MiBの一INFの安全な相対path。
 * @param[in] baseInstallSection 現OS用Modelsの第1 fieldと一致する最大254文字の導入名。
 * @param[out] inventory 全観測と元byte再照合に成功した場合のみ保持し、失敗時は空。
 * @return 有限棚卸し成功0、入力・選択・容量・改変・SetupAPI失敗のHRESULT。
 * @note worker内でblockingする。署名・端末適合・依存充足・導入作用の許可を発行しない。
 * 最大1,024節・4,096行・作用4,096・参照4,096・一行64 field。別INFを開かず通常作用拒否を変更しない。
 * @see docs/adr/0264-selected-inf-install-inventory.md
 * @see docs/adr/0266-selected-inf-inventory-capacity-expansion.md
 * @see docs/adr/0268-selected-inf-reference-context-and-coverage.md
 */
[[nodiscard]] NativeError inspectOfficialInfInstallInventory(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view infRelativePath, std::wstring_view baseInstallSection,
	OfficialInfInstallInventory &inventory) ;

/**
 * @brief 実行せずに保守用の全sourceとCopyINFを列挙する。
 * @param[in] workspace INF実byteを所有する同期借用の保護領域。
 * @param[in] entries 検証済み元archive metadata。未取得sourceを含められる。
 * @param[in] infRelativePath 読取済みINFの安全な相対path。
 * @param[out] inventory 成功時だけ参照集合を保持し、失敗時は到達stage以外を空にする。
 * @return 棚卸し成功時0、最初の構文・path・容量違反のHRESULT。
 * @note PnP IDを保持せず、署名・用途・適用性・導入を承認しない。
 * Version構文識別子は$Windows NT$と$Chicago$を受理する。暗号署名の代わりにしない。
 * BlockingするためUI threadで呼ばない。CopyINFの再帰と実byte検証は呼出し側が必要。
 * 媒体・source subdir・CopyINFの先頭現在directory表記だけを除き、残りは既存path境界で検証する。
 * @see docs/adr/0244-maintenance-inf-reference-inventory.md
 * @see docs/adr/0246-maintenance-relative-references-and-direct-content.md
 */
[[nodiscard]] NativeError inspectOfficialInfReferences( const OfficialDownloadWorkspace	&workspace,
													   std::span<const OfficialZipEntry> entries,
													   std::wstring_view infRelativePath,
													   OfficialInfReferenceInventory &inventory) ;

/**
 * @brief 展開済み標準INF packageの構造と現在OSへの適用sectionを検証する。
 * 展開済み標準INF packageを検証する。
 * SetupAPIの構文とplatform選択結果を使用し、CAT署名前にpackageの有限性、driver-only境界、参照file存在を確認する。
 * @param[in] workspace ZIP展開fileを所有する保護workspace。
 * @param[in] entries ZIP検証で確定した全通常file。Directory entryは含めない。 ZIP検証済みの全通常file。
 * @param[in] infRelativePath 検証対象INFのworkspace基準相対path。 検証するINF相対path。
 * @param[in] policy 件数上限、許可class、ProviderおよびINF signature。 件数上限、許可class／Provider／signature。
 * @param[out] package 成功時の検証済み構造。失敗時は空にする。 成功時だけ更新する検証済み構造。
 * @return 成功時は0、INF構文、適用section、参照fileまたはpolicy違反時はHRESULT。 全構造検証成功時は0、最初の違反はHRESULT。
 * @note 本関数はfileを変更せず、catalog署名とmember hashは別の署名検証で確認する。
 */
[[nodiscard]] NativeError inspectOfficialInfPackage( const OfficialDownloadWorkspace	 &workspace,
													std::span<const OfficialZipEntry> entries,
													std::wstring_view infRelativePath,
													const OfficialInfInspectionPolicy &policy,
													OfficialInfPackage				  &package) ;

/**
 * @brief 元packageと一致する現OS公開IDを同HINFから原節名/種別付きで読み取ります。
 * @param[in] workspace 保護された元INFを所有するworkspaceです。
 * @param[in] package 通常構造検査で得た元INF相対pathと全ID列です。
 * @param[out] identity 成功時だけ同INF前後hash/原ClassGUID/全Models節です。失敗時は空です。
 * @return 有限な原metadataの全一致時0、欠損/上限/改変時は元HRESULTです。
 * @note Read-onlyのmetadataです。CAT/member/公式性/実端末照合/取得同意を代替しません。
 */
[[nodiscard]] NativeError readOfficialInfPublishedIdentity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	OfficialInfPublishedIdentity &identity) ;

/**
 * @brief INFと対応catalogのWindows driver署名およびsigner allowlistを検証する。
 * INFと対応catalogの署名を検証する。
 * SetupVerifyInfFileをWindows driver署名の正本とし、返されたcatalogとsignerをProvider固定allowlistへ完全一致させる。
 * @param[in] workspace Package fileを所有する保護workspace。
 * @param[in] package 構造検証済みのINF package。
 * @param[in] acceptedSigners 許可するWindows driver signer表示名群。 許可するdriver signer表示名群。
 * @return 署名とcatalog名とsignerが一致した場合は0、それ以外はHRESULT。 署名、catalog名、signer一致時は0、それ以外はHRESULT。
 * @note SetupVerifyInfFileはblockingし得るためProvider worker threadから呼び出す。
 */
[[nodiscard]] NativeError verifyOfficialInfCatalogSignature(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::span<const std::wstring_view> acceptedSigners) ;

/**
 * @brief INF署名、signer、およびINFと全参照fileのcatalog member hashを検証する。
 * INF package全体のcatalog整合性を検証する。
 * SetupAPIでINF signerを確定した後、INF自身と全参照fileを同じCATのmemberとして検証し、部分検証を候補化しない。
 * 静的参照検査でsourceが0件と確定した場合も、INF自身のmember検証を省略しない。
 * @param[in] workspace Package fileを所有する保護workspace。
 * @param[in] package 構造検証済みのINF package。
 * @param[in] acceptedSigners 許可するWindows driver signer表示名群。 許可するdriver signer表示名群。
 * @return 全署名・hash検証成功時は0、最初に失敗した検証のHRESULT。 署名と全member hashが有効なら0、それ以外はHRESULT。
 * @note 本関数の成功後だけ、現在deviceとのlocal PnP ID照合へ進める。
 */
[[nodiscard]] NativeError verifyOfficialInfPackageIntegrity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::span<const std::wstring_view> acceptedSigners) ;

/**
 * @brief Windowsが検証したsignerと同一CATの全memberを共通経路で検査する。
 * @param[in] workspace INF閉包を所有する保護領域。
 * @param[in] package 構造と全参照fileを検査したINF。
 * @return SetupVerifyInfFile成功、非空signer、同一CAT、全member合格時0、それ以外はHRESULT。
 * @note Maker表示名をsignerと比較しない。Windows署名失敗やtrust未確立を成功へ変換しない。
 * 静的参照検査でsourceが0件と確定した場合も、INF自身を必ずCATへ照合する。
 * Blockingするためworkerから呼ぶ。成功は導入policy・実device適合・公式由来を保証しない。
 */
[[nodiscard]] NativeError verifyWindowsInfPackageIntegrity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package) ;

/** @brief 同保護INF/CATの全memberを検査して実Windows signer名だけを返します。
 * @param[in] workspace 同原閉包を所有する保護領域です。
 * @param[in] package 同原INFとCATを示す構造検査済みmetadataです。
 * @param[out] publisher 同Windows署名/全member成功時だけ実DigitalSignerです。失敗時空です。
 * @return 同exact CAT、Windows署名、全member成功0、失敗は元HRESULTです。
 * @note INF Providerを代入せず、公式性/実端末適合/導入許可を発行しません。Workerでblockingします。
 */
[[nodiscard]] NativeError readWindowsInfPackagePublisher( const OfficialDownloadWorkspace &workspace,
														 const OfficialInfPackage		 &package,
														 std::wstring &publisher) ;

/**
 * @brief INFが参照する全fileのAuthenticode署名とpublisherを検証する。
 * INF参照fileの埋込み署名を検証する。
 * 固定SHA-256で拘束したarchive内の実行binaryを個別検証し、未署名fileまたは異なるpublisherを一件でも受理しない。
 * @param[in] workspace Package fileを所有する保護workspace。
 * @param[in] package 構造検証済みでsourceFilesが確定したINF package。 構造検証済みのINF package。
 * @param[in] requiredRelativePaths 署名とINF参照を必須にするworkspace相対path群。 署名を必須にする相対path群。
 * @param[in] acceptedSigners 許可する埋込み署名publisher表示名群。 許可する署名publisher表示名群。
 * @return 全指定fileのINF参照、署名、publisherが有効なら0、最初の失敗はHRESULT。 全参照fileの署名とpublisherが有効なら0。
 * @note CAT member hashを置換する一般fallbackではなく、固定archive hashと併用する。
 */
[[nodiscard]] NativeError verifyOfficialInfEmbeddedFileSignatures(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::span<const std::wstring_view> requiredRelativePaths,
	std::span<const std::wstring_view> acceptedSigners) ;

/**
 * @brief INFの検証済みPnP IDを現在deviceのHardware IDとCompatible IDへ照合する。
 * INFを現在deviceのPnP IDへ照合する。
 * PnP IDはworker内だけで大文字小文字を除く完全一致に使用し、部分一致、prefix一致、空IDによる適用範囲拡張を行わない。
 * @param[in] package 構造検証済みのINF package。
 * @param[in] deviceHardwareIds 現在deviceからworker内で取得したHardware ID群。 現在deviceのHardware ID群。
 * @param[in] deviceCompatibleIds 現在deviceからworker内で取得したCompatible ID群。 現在deviceのCompatible ID群。
 * @return Hardware ID、Compatible IDの優先順で得た完全一致結果。該当なしはNone。
 * @note IDはnetwork、UI、logへ渡さず、呼出し中のlocal matchingだけに使用する。
 */
[[nodiscard]] OfficialInfDeviceMatch matchOfficialInfToDevice(
	const OfficialInfPackage &package, std::span<const std::wstring_view> deviceHardwareIds,
	std::span<const std::wstring_view> deviceCompatibleIds) noexcept ;

/** @brief 同じHINF/source IDの完全source/media応答を共有します。
 * @param[in] inf 同期借用する一INF handleです。
 * @param[in] fileName 元basenameです。
 * @param[out] sourceDirectory 完全取得した元subdirです。
 * @param[out] mediaDirectory installation-root相対の元媒体です。
 * @return 完全取得0、欠損・曖昧・部分応答・root-only policy拒否のHRESULTです。
 * @note 保護領域とCAT/member検査は呼出し側で別途必要です。
 */
[[nodiscard]] NativeError readOfficialInfSourceDirectories( void *inf, const std::wstring &fileName,
														   std::wstring &sourceDirectory,
														   std::wstring &mediaDirectory) ;
} // namespace drivercrate
