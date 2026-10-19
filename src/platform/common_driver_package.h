//------------------------------------------------------------------------------
/**
 * @file common_driver_package.h
 * @brief 由来と独立したdriver packageの共通検査定義。
 * @version 01.07.00
 * @date 2026/09/15
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  新規作成。
 * Ver.01.01.00 Shunji Ogawa  2026/10/05  保守内容検査の四軸と導入非互換型を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/07  保守構造と依存・参照coverage・root署名を独立状態へ分離。
 * Ver.01.02.01 Shunji Ogawa  2026/10/07  接続済み保守状態と互換boolの意味を明記。
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  検証済み追加役割の不変計画と非authority契約を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  全import内容とdevice別選択関係の不変計画を定義。
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  監視側の明示一INFへ同じ通常閉包/署名検査を接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  必要INF bindingの任意数値診断を定義。
 * Ver.01.07.00 Shunji Ogawa  2026/10/15  実選択graphの検証済みNeeds件数を私有計画へ保持。
 * </pre>
 *
 * @note Path、hash、INF内IDはworker専用です。署名と静的内容の合格を実device適合と混同しません。
 * @see docs/adr/0151-common-package-content-and-origin-separation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/candidate_assessment.h"
#include "core/update_types.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"
#include "platform/official_driver_package.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 導入用workspace・path・PnP IDを持たない一INFの保守結果。 */
struct MaintenanceInfInspection {
	/// 抽出できた元INFのSHA-256。未抽出時は空。
	std::wstring					infSha256 ;
	/// 外側0または一段nestedの1。
	std::uint32_t					archiveDepth{} ;
	/// 保守構造parserの結果。参照・署名・導入経路の合否ではない。
	MaintenanceInspectionFinding	parser ;
	/// Windows署名とINF・全参照CAT memberの結果。
	MaintenanceInspectionFinding	integrity ;
	/// 現在端末への適合。保守検査では未検査に固定する。
	MaintenanceInspectionFinding	applicability ;
	/// 従来導入policyの静的通過結果。合格でも導入は許可しない。
	MaintenanceInspectionFinding	installRoute ;
	/// 同一保守閉包の内容構造種別。署名・適合・導入能力を付与しない。
	MaintenanceInfContentKind		contentKind{MaintenanceInfContentKind::UNKNOWN} ;
	/// 全必要file参照の位置coverage。byte・署名・由来とは独立し、未解析時はNOT_CHECKED。
	MaintenanceInfReferenceCoverage referenceCoverage{MaintenanceInfReferenceCoverage::NOT_CHECKED} ;
	/// Root INFと確認したlocal参照の独立した署名結果。未解析時はNOT_CHECKED。
	MaintenanceInspectionFinding	rootIntegrity ;
	/// 明示依存の独立summary。旧boolだけで不在を認定しない。
	MaintenanceInfDependencySummary dependency ;
	/// 新summaryの棚卸し済み明示参照数が非零ならtrue。未検査のfalseは不在ではない。
	bool							hasExternalDependencies{} ;
	/// 新summaryがNOT_CHECKED以外ならtrue。由来・署名・依存充足の成功ではない。
	bool							dependenciesChecked{} ;
	/// この閉包の展開byte数。署名失敗でも予算へ加える。
	std::uint64_t					inspectedBytes{} ;
} ;

/** @brief 保守専用archive評価。導入用の共通検査結果と互換でない。 */
struct MaintenanceDriverPackageInspection {
	/// 全体失敗時は0の入力session。
	ScanSessionId						  scanSessionId{} ;
	/// 元archiveの内容identity。公式由来証明ではない。
	std::wstring						  archiveSha256 ;
	/// 元archiveのbyte数。
	std::uint64_t						  archiveBytes{} ;
	/// 全体破損・予算・取消し等のHRESULT。部分結果は破棄する。
	NativeError							  error{} ;
	/// 解析完了またはINF抽出未対応の結果。
	MaintenanceInspectionFinding		  parser ;
	/// 直下・一段nestedの全通常file数。
	std::size_t							  inventoryFileCount{} ;
	/// 解析に使った全閉包byte合計。
	std::uint64_t						  inspectedBytes{} ;
	/// 全個別結果。失敗行も分母へ含める。
	std::vector<MaintenanceInfInspection> infs ;
} ;

/**
 * @brief 非実行で保守用の解析・内容署名・適合未検査・導入方式を分離する。
 * @param[in] input 呼出し中有効な保護archiveの固定identity。
 * @param[in] format ZIPまたはCAB。EXEの実行へfallbackしない。
 * @param[out] inspection 完了時は失敗行も保持する。全体失敗時はerrorだけを残す。
 * @param[in] cancellation 空またはworker内の非blocking取消し照会。
 * @return 全体評価完了0、破損・上限・取消し・例外時はHRESULT。
 * @note 128 INF・一段nested・有限展開量を維持する。適合照合・導入・stagingを行わない。
 * parser・root／全署名・参照位置・依存を独立に保持し、従来静的routeを別評価する。
 * 既存のcandidate生成・再検証APIへ渡せる型を返さない。
 * @see docs/adr/0258-maintenance-package-verdict-separation.md
 */
[[nodiscard]] NativeError inspectMaintenanceDriverPackage(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	MaintenanceDriverPackageInspection &inspection, const std::function<bool()> &cancellation = {}) ;

/** @brief 個別INFが内容検査で到達した段階。 */
enum class CommonInfInspectionState {
	/// 静的閉包を作れなかった。未対応構文と欠落等の診断値を別に持つ。
	CLOSURE_REJECTED,
	/// 静的閉包は作れたがWindows署名またはCAT member検証に失敗した。
	SIGNATURE_REJECTED,
	/// 静的閉包、Windows署名、全CAT memberを検査済み。
	VERIFIED,
} ;

/** @brief 一つのINFの検査結果と成功閉包を単独所有する。 */
struct CommonInfInspection {
	/// 本検査を所有する0ではないscan session。
	ScanSessionId							   scanSessionId{} ;
	/// Worker内だけに保持する対象INF相対path。
	std::wstring							   infRelativePath ;
	/// 空または一段nested archive相対path。
	std::wstring							   nestedArchivePath ;
	/// 個別到達段階。
	CommonInfInspectionState				   state{CommonInfInspectionState::CLOSURE_REJECTED} ;
	/// 個別失敗のHRESULT。VERIFIEDの場合だけ0。
	NativeError								   error{} ;
	/// VERIFIEDの場合だけ保持する閉包所有領域。
	std::unique_ptr<OfficialDownloadWorkspace> workspace ;
	/// VERIFIEDの場合だけ保持する静的内容。
	OfficialDriverClosure					   closure ;
	/// 全節の潜在CopyINFから到達し、同保護workspaceで全CAT/memberを検査したimport内容です。
	std::vector<OfficialInfPackage>			   requiredInfPackages ;
} ;

class DriverStoreProvider ;
class SignedIndexCandidateBindingSession ;
class RequiredDriverComponentPlan ;
/** @brief 必要INF bindingの拒否を元の数値だけで保持する任意診断です。権限を持ちません。 */
struct RequiredInfBindingDiagnostic {
	/// 内部到達段階です。未開始は0です。
	std::uint32_t stage{} ;
	/// 実graphの全参照が解決した場合trueです。
	bool		  referencesResolved{} ;
	/// 実graphのroot証拠が全検証済みの場合trueです。
	bool		  rootEvidenceVerified{} ;
	/// 元graphの未解決参照件数です。
	std::size_t	  unresolvedReferenceCount{} ;
	/// 最初の未解決参照の有限reason値です。未観測は0です。
	std::uint32_t firstReferenceReason{} ;
	/// 実root署名の元HRESULTです。未観測または合格は0です。
	NativeError	  rootSignatureError{} ;
	/// 最初の依存署名の元HRESULTです。未観測または合格は0です。
	NativeError	  firstDependencySignatureError{} ;
	/// 最初の依存由来の元HRESULTです。未観測または合格は0です。
	NativeError	  firstDependencyProvenanceError{} ;
	/// 選択文脈と全fieldを検査したNeedsの累積HKR設定行数です。
	std::size_t	  verifiedRegistryRowCount{} ;
} ;
/**
 * @brief 実検査した元基本INF閉包から必要役割の関係を構築します。
 * @param[in] inspected 元保護byteと全署名を保持する同workerの内容検査です。
 * @param[in] selectedPackages baseと全importの元順copyです。選択機能関係は私有native nodeから解析します。
 * @param[out] plan 成功時だけ元閉包へ結合した不変計画です。失敗時は空です。
 * @param[out] diagnostic 任意の数値診断です。nullなら採取せず合否へ使用しません。
 * @return 内容と関係の一意な確認0、未対応・欠損・曖昧・循環は元HRESULTです。
 * @note 計画は内容関係だけで、同意・復旧・PnP・私有install bindingを代替しません。
 */
[[nodiscard]] NativeError makeRequiredDriverComponentPlan(
	const CommonInfInspection &inspected, std::span<const OfficialInfPackage> selectedPackages,
	std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	RequiredInfBindingDiagnostic					   *diagnostic = nullptr) ;

/** @brief 公開index/DTOから必要memberを追加できない不変内容計画です。導入能力を持ちません。 */
class RequiredDriverComponentPlan final {
public:
	/** @brief 必要関係を持たない空計画を作ります。factoryだけが内容を結合します。 */
	RequiredDriverComponentPlan() = default ;
	/** @brief 非秘密の役割件数だけを返します。
	 * @param[in] role 観測する追加役割です。
	 * @return 一計画内0～7の確認済みmember数です。
	 */
	[[nodiscard]] std::size_t count( DriverPlanRole role) const noexcept ;

private:
	friend class DriverStoreProvider ;
	friend class SignedIndexCandidateBindingSession ;
	friend NativeError makeRequiredDriverComponentPlan(
		const CommonInfInspection &inspected, std::span<const OfficialInfPackage> selectedPackages,
		std::shared_ptr<const RequiredDriverComponentPlan> &plan, RequiredInfBindingDiagnostic *) ;
	/** @brief 元CopyINFとAddComponentに一意に結合した役割memberです。 */
	struct Member {
		/// 同CommonInfInspection.requiredInfPackagesの0起点位置です。
		std::size_t				  packageOrdinal{} ;
		/// 元class/GUIDで確認した追加役割です。
		DriverPlanRole			  role{DriverPlanRole::EXTENSION} ;
		/// 必要SWCを作る元packageです。0はbase、以降はrequiredInfPackagesの1起点位置です。
		std::size_t				  parentPackageOrdinal{} ;
		/// 当該元AddComponentの検証済みSWC IDです。Extensionでは空です。
		std::vector<std::wstring> componentHardwareIds ;
	} ;
	/// 内容検査の非零scan sessionです。
	ScanSessionId					session_{} ;
	/// 元基本INFの相対pathです。worker内だけで保持します。
	std::wstring					basePath_ ;
	/// 元AddComponentの子、次に元閉包のExtensionを置く不変集合です。適用順の保証ではありません。
	std::vector<Member>				members_ ;
	/// 元順の全import copyです。selectedInstallSectionとactive関係は私有nodeへ結合します。
	std::vector<OfficialInfPackage> selectedPackages_ ;
	/// 実選択節のnative依存・全効果を検証したNeeds辺数です。八graphの累積最大32768です。
	std::size_t						verifiedNeedsEdgeCount_{} ;
} ;

/** @brief 全INF検査の結果。全体失敗と個別INF拒否を分離する。 */
struct CommonDriverPackageInspection {
	/// 入力を固定したscan session。全体失敗では0。
	ScanSessionId					 scanSessionId{} ;
	/// 外側入力の同一性hash。公式由来の証明ではない。
	std::wstring					 archiveSha256 ;
	/// 外側入力のbyte数。
	std::uint64_t					 archiveBytes{} ;
	/// 全体失敗のHRESULT。個別拒否だけなら0。
	NativeError						 error{} ;
	/// 直下と一段内側を検査した通常fileの総数。
	std::size_t						 inventoryFileCount{} ;
	/// 成功閉包の保持byte合計。
	std::uint64_t					 retainedBytes{} ;
	/// 成功と失敗を含む最大128 INF。PathとIDをUIへ渡さない。
	std::vector<CommonInfInspection> infs ;
} ;

/**
 * @brief 明示されたlocal archive一件を保護領域へ有限複製する。
 * @param[in] selectedPath 利用者が選択したlocal drive上の絶対ZIP／CAB path。
 * @param[in] scanSessionId 0ではないscan session。
 * @param[in,out] workspace 未初期化領域。複製fileをscope終了まで所有する。
 * @param[out] input 成功時の固定内容identity。失敗時は空。
 * @param[out] format 成功時の形式。失敗時は使用しない。
 * @return 通常file、有限copy、実size／hash固定に成功した場合0、それ以外はHRESULT。
 * @note 128 MiB上限、1 MiB以下のchunkでcopyする。Networkも入力fileの実行も行わない。
 */
[[nodiscard]] NativeError copyLocalDriverArchive( std::wstring_view			  selectedPath,
												 ScanSessionId				  scanSessionId,
												 OfficialDownloadWorkspace	 &workspace,
												 DriverArchiveInput			 &input,
												 OfficialDriverArchiveFormat &format) ;

/**
 * @brief 固定済み入力の全INFを個別の保護閉包とWindows署名で検査する。
 * @param[in] input 呼出し中有効な保護archive identity。由来判定は含まない。
 * @param[in] format ZIPまたはCAB。実行形式を拒否する。
 * @param[out] inspection 全体成功時は全個別結果。全体失敗時はerrorだけを保持する。
 * @param[in] cancellation 空またはworker内で呼ぶ非blocking取消し照会。
 * @return 全INFの検査完了時0、入力・全体上限・取消し・例外時はHRESULT。
 * @note 個別拒否でも残りを検査する。全体失敗では部分合格を破棄する。導入・stagingは行わない。
 */
[[nodiscard]] NativeError inspectCommonDriverPackage(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	CommonDriverPackageInspection &inspection, const std::function<bool()> &cancellation = {}) ;

/**
 * @brief 監視側が固定した外側一INFだけを既存通常policyで内容検査します。
 * @param[in] input 同operationが所有する固定archiveの原identityです。
 * @param[in] format 元copyが判別したZIP/CABINETです。
 * @param[in] selectedInf 実inventoryへ完全一致させる原相対INF名です。空/別形式を拒否します。
 * @param[out] inspection 一INFの成功/拒否と全外側inventory件数です。全packageの完了ではありません。
 * @param[in] cancellation 同workerの協調停止です。
 * @return 一INFの評価完了0、入力/全体破損/取消し時は元HRESULTです。
 * @note 旧全INF入口を変更しません。未選択INFは未検査で、取得/公式性/端末適用性/導入を認定しません。
 */
[[nodiscard]] NativeError inspectSelectedCommonDriverPackage(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	std::wstring_view selectedInf, CommonDriverPackageInspection &inspection,
	const std::function<bool()> &cancellation = {}) ;

/**
 * @brief 成功閉包の全file、metadata、署名を同一policyで再検証する。
 * @param[in] inspected 保護領域を保持するVERIFIED結果。
 * @return 全fileのsize／hash、INF metadata、Windows署名一致時0、それ以外はHRESULT。
 * @note 導入許可やdevice bindingの検査を代替しない。Workerから呼ぶ。
 */
[[nodiscard]] NativeError reverifyCommonDriverInf( const CommonInfInspection &inspected) ;

/**
 * @brief 内容合格INFとWindows適合観測を候補の八軸へ結合する。
 * @param[in] scanSessionId 内容検査と一致するscan session。
 * @param[in] candidate 結合先のopaque IDを持つ表示候補。
 * @param[in] inspected 本workerが実検査したVERIFIED閉包。
 * @param[in] evidenceId Scan内で当該検査へ一意に割り当てた0ではない証拠ID。
 * @param[in] origin 取得層が確認した由来finding。LocalはUSER_PROVIDEDのままとする。
 * @param[in] applicabilityError Windows適合観測のHRESULT。未実施を0で渡さない。
 * @param[in] candidateRank Windowsの一致nodeのrank。非適用・失敗時は空。
 * @param[out] assessment 全成功時の八軸。入力不正では空。
 * @return 証拠とidentityを結合できた場合true。実行可能を意味しない。
 * @note 現在driverとの順位比較とexecutor接続は行わず、導入可能へ昇格させない。
 */
[[nodiscard]] bool		  makeCommonInfCandidateAssessment(
		   ScanSessionId scanSessionId, const UpdateCandidate &candidate,
		   const CommonInfInspection &inspected, std::uint64_t evidenceId,
		   const CandidateAssessmentFinding &origin, NativeError applicabilityError,
		   std::optional<std::uint32_t> candidateRank, CandidateAssessment &assessment) ;

} // namespace drivercrate
