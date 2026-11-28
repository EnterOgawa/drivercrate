//------------------------------------------------------------------------------
/**
 * @file common_driver_package.h
 * @brief 由来と独立したdriver packageの共通検査定義
 * @version 01.26.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/05  保守内容検査の四軸と導入非互換型を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/07  保守構造と依存・参照coverage・root署名を独立状態へ分離
 * Ver.01.02.01 Shunji Ogawa  2026/10/07  接続済み保守状態と互換boolの意味を明記
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  検証済み追加役割の不変計画と非authority契約を追加
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  全import内容とdevice別選択関係の不変計画を定義
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  監視側の明示一INFへ同じ通常閉包/署名検査を接続
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  必要INF bindingの任意数値診断を定義
 * Ver.01.07.00 Shunji Ogawa  2026/10/15  実選択graphの検証済みNeeds件数を私有計画へ保持
 * Ver.01.08.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.09.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.09.01 Shunji Ogawa  2026/11/03  拡大recordと有限保持quotaを通常経路へ整合
 * Ver.01.10.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.10.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.10.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.10.03 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.10.04 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.11.00 Shunji Ogawa  2026/11/15  非実行collector内容を通常binding非互換型へ分離
 * Ver.01.12.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.12.01 Shunji Ogawa  2026/11/17  標準TapeDriveとcollector追加Classの用途を明記
 * Ver.01.13.00 Shunji Ogawa  2026/11/19  端末の独自クラス内容を読み取り専用で再検証
 * Ver.01.14.00 Shunji Ogawa  2026/11/22  一件の公式配布対象を収集内容検査へ接続
 * Ver.01.15.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスを必要とする選択の端末照合を分離
 * Ver.01.16.00 Shunji Ogawa  2026/11/22  公式Netの同梱再検査用に元アーカイブ一覧を保持
 * Ver.01.17.00 Shunji Ogawa  2026/11/23  自動起動ストレージの現用機器読取りを接続
 * Ver.01.18.00 Shunji Ogawa  2026/11/23  WiXの保護済み単一ストレージINFを端末用に再検査
 * Ver.01.19.00 Shunji Ogawa  2026/11/23  署名済みEXEと内側ZIPを収集内容検査へ接続
 * Ver.01.20.00 Shunji Ogawa  2026/11/23  私有収集の元memberを非実行内容検査へ接続
 * Ver.01.21.00 Shunji Ogawa  2026/11/23  審査済みの必須System補助INFを私有収集へ接続
 * Ver.01.22.00 Shunji Ogawa  2026/11/24  混在シリアルの審査済みZIPを私有収集内容へ接続
 * Ver.01.23.00 Shunji Ogawa  2026/11/24  署名付きPEで確認する必須補助INFの種類を定義
 * Ver.01.24.00 Shunji Ogawa  2026/11/27  基本INFに結合した付随参照の判定を定義
 * Ver.01.25.00 Shunji Ogawa  2026/11/27  登録元での付随INF不在の再確認契約を追加
 * Ver.01.26.00 Shunji Ogawa  2026/11/27  選択Displayの補助サービス所有を内容計画へ結合
 * </pre>
 *
 * @note Path、hash、INF内IDはworker専用です。署名と静的内容の合格を実device適合と混同しません
 * @see docs/adr/0151-common-package-content-and-origin-separation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/candidate_assessment.h"
#include "core/update_types.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"
#include "platform/official_driver_package.h"
#include "platform/inf_dependency_native.h"

#include <cstddef>
#include <span>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

namespace drivercrate {
struct OfficialReviewedNsisZip ;

/** @brief 導入用workspace・path・PnP IDを持たない一INFの保守結果 */
struct MaintenanceInfInspection {
	/// 抽出できた元INFのSHA-256。未抽出時は空
	std::wstring					infSha256 ;
	/// 外側0または一段nestedの1
	std::uint32_t					archiveDepth{} ;
	/// 保守構造parserの結果。参照・署名・導入経路の合否ではない
	MaintenanceInspectionFinding	parser ;
	/// Windows署名とINF・全参照CAT memberの結果
	MaintenanceInspectionFinding	integrity ;
	/// 現在端末への適合。保守検査では未検査に固定する
	MaintenanceInspectionFinding	applicability ;
	/// 従来導入policyの静的通過結果。合格でも導入は許可しない
	MaintenanceInspectionFinding	installRoute ;
	/// 同一保守閉包の内容構造種別。署名・適合・導入能力を付与しない
	MaintenanceInfContentKind		contentKind{MaintenanceInfContentKind::UNKNOWN} ;
	/// 全必要file参照の位置coverage。byte・署名・由来とは独立し、未解析時はNOT_CHECKED
	MaintenanceInfReferenceCoverage referenceCoverage{MaintenanceInfReferenceCoverage::NOT_CHECKED} ;
	/// Root INFと確認したlocal参照の独立した署名結果。未解析時はNOT_CHECKED
	MaintenanceInspectionFinding	rootIntegrity ;
	/// 明示依存の独立summary。旧boolだけで不在を認定しない
	MaintenanceInfDependencySummary dependency ;
	/// 新summaryの棚卸し済み明示参照数が非零ならtrue。未検査のfalseは不在ではない
	bool							hasExternalDependencies{} ;
	/// 新summaryがNOT_CHECKED以外ならtrue。由来・署名・依存充足の成功ではない
	bool							dependenciesChecked{} ;
	/// この閉包の展開byte数。署名失敗でも予算へ加える
	std::uint64_t					inspectedBytes{} ;
} ;

/** @brief 保守専用archive評価。導入用の共通検査結果と互換でない */
struct MaintenanceDriverPackageInspection {
	/// 全体失敗時は0の入力session
	ScanSessionId						  scanSessionId{} ;
	/// 元archiveの内容identity。公式由来証明ではない
	std::wstring						  archiveSha256 ;
	/// 元archiveのbyte数
	std::uint64_t						  archiveBytes{} ;
	/// 全体破損・予算・取消し等のHRESULT。部分結果は破棄する
	NativeError							  error{} ;
	/// 解析完了またはINF抽出未対応の結果
	MaintenanceInspectionFinding		  parser ;
	/// 直下・一段nestedの全通常file数
	std::size_t							  inventoryFileCount{} ;
	/// 解析に使った全閉包byte合計
	std::uint64_t						  inspectedBytes{} ;
	/// 全個別結果。失敗行も分母へ含める
	std::vector<MaintenanceInfInspection> infs ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 非実行で保守用の解析・内容署名・適合未検査・導入方式を分離する
 * @param[in] input 呼出し中有効な保護archiveの固定identity
 * @param[in] format ZIPまたはCAB。EXEの実行へfallbackしない
 * @param[out] inspection 完了時は失敗行も保持する。全体失敗時はerrorだけを残す
 * @param[in] cancellation 空またはworker内の非blocking取消し照会
 * @return 全体評価完了0、破損・上限・取消し・例外時はHRESULT
 * @note 128 INF・一段nested・有限展開量を維持する。適合照合・導入・stagingを行わない。parser・root／全署名・参照位置・依存を独立に保持し、従来静的routeを別
 *       評価する。既存のcandidate生成・再検証APIへ渡せる型を返さない
 * @see docs/adr/0258-maintenance-package-verdict-separation.md
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectMaintenanceDriverPackage(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	MaintenanceDriverPackageInspection &inspection, const std::function<bool()> &cancellation = {}) ;

/** @brief 個別INFが内容検査で到達した段階 */
enum class CommonInfInspectionState {
	/// 静的閉包を作れなかった。未対応構文と欠落等の診断値を別に持つ
	CLOSURE_REJECTED,
	/// 静的閉包は作れたがWindows署名またはCAT member検証に失敗した
	SIGNATURE_REJECTED,
	/// 静的閉包、Windows署名、全CAT memberを検査済み
	VERIFIED,
} ;

/** @brief 一つのINFの検査結果と成功閉包を単独所有する */
struct CommonInfInspection {
	/// 本検査を所有する0ではないscan session
	ScanSessionId							   scanSessionId{} ;
	/// Worker内だけに保持する対象INF相対path
	std::wstring							   infRelativePath ;
	/// 空または一段nested archive相対path
	std::wstring							   nestedArchivePath ;
	/// 個別到達段階
	CommonInfInspectionState				   state{CommonInfInspectionState::CLOSURE_REJECTED} ;
	/// 個別失敗のHRESULT。VERIFIEDの場合だけ0
	NativeError								   error{} ;
	/// VERIFIEDの場合だけ保持する閉包所有領域
	std::shared_ptr<OfficialDownloadWorkspace> workspace ;
	/// VERIFIEDの場合だけ保持する静的内容
	OfficialDriverClosure					   closure ;
	/// 全節の潜在CopyINFから到達し、同保護workspaceで全CAT/memberを検査したimport内容です
	std::vector<OfficialInfPackage>			   requiredInfPackages ;
} ;

class DriverStoreProvider ;
class SignedIndexCandidateBindingSession ;
class RequiredDriverComponentPlan ;
/** @brief binding拒否の固定位置です。合否の入力には使いません */
enum class InfBindingReject : std::uint32_t {
	/// 未観測です
	NONE,
	/// 明示依存を単一INF入口で受理できません
	SINGLE_DEPENDENCY,
	/// native architectureがx64ではありません
	ARCHITECTURE,
	/// binding入力が不正です
	INPUT,
	/// 元INFの属性またはpathを取得できません
	INF_FILE,
	/// 最初の現在device状態を読めません
	CURRENT_BEFORE,
	/// 現在driverのrankを読めません
	CURRENT_RANK,
	/// 候補driver nodeを一意に読めません
	CANDIDATE_NODE,
	/// 後の現在device状態を読めません
	CURRENT_AFTER,
	/// 元binding状態が変化しました
	BINDING_STATE,
	/// 元内容閉包を再検証できません
	CONTENT_REVERIFY,
	/// 選択節の関係を解析できません
	SELECTED_RELATIONS,
	/// 選択CopyINFの元importがありません
	COPY_INF_MISSING,
	/// 必要計画の入力が不正です
	PLAN_INPUT,
	/// 独立roleを基本driverとして扱えません
	BASE_ROLE,
	/// 選択roleの構成が未対応です
	FUNCTIONAL_ROLE,
	/// 依存graphまたはNeeds効果を検証できません
	DEPENDENCY,
	/// Windowsコピー先を元sourceへ結合できません
	WINDOWS_COPY,
	/// DIRID13の原sourceと宛先subdirectoryが異なります
	DIRID13_SOURCE,
	/// 実選択scopeの先頭の固定拒否位置です。続く値は同関数の原拒否順です
	WINDOWS_SCOPE_FIRST = 200,
	/// 候補の補助サービスと現在の所有・共用の照合が成立しなかった
	DISPLAY_OWNERSHIP = 208,
	/// Displayの指定適用と必要子の反映を確認する経路がまだ接続されていない
	DISPLAY_REFLECTION_PENDING = 209,
} ;
/** @brief 必要INF bindingの拒否を元の数値だけで保持する任意診断です。権限を持ちません */
struct RequiredInfBindingDiagnostic {
	/// 単一INF1/必要構成2の元呼出し経路です
	std::uint32_t	 path{} ;
	/// 最初の具体的な拒否位置です。後続で上書きしません
	InfBindingReject rejection{InfBindingReject::NONE} ;
	/// 拒否時の元architecture/role等の数値です
	std::uint32_t	 observed{} ;
	/**
	 * @brief 原errorを変えず最初の拒否位置だけを記録します
	 * @param[in] error 元の非zero HRESULTです。0は記録しません
	 * @param[in] location 固定された元拒否位置です
	 * @param[in] value 原観測enumまたは件数です
	 * @return 未変更の元errorです
	 */
	NativeError		 reject( const NativeError error, const InfBindingReject location,
							const std::uint32_t value = 0U) noexcept
	{
		// 成功や後段の汎用位置で最初の拒否を上書きしません
		if( error != 0 && rejection == InfBindingReject::NONE) {
			rejection = location ;
			observed  = value ;
		}

		return error ;
	}

	/// 内部到達段階です。未開始は0です
	std::uint32_t stage{} ;
	/// 実graphの全参照が解決した場合trueです
	bool		  referencesResolved{} ;
	/// 実graphのroot証拠が全検証済みの場合trueです
	bool		  rootEvidenceVerified{} ;
	/// 元graphの未解決参照件数です
	std::size_t	  unresolvedReferenceCount{} ;
	/// 最初の未解決参照の有限reason値です。未観測は0です
	std::uint32_t firstReferenceReason{} ;
	/// 実root署名の元HRESULTです。未観測または合格は0です
	NativeError	  rootSignatureError{} ;
	/// 最初の依存署名の元HRESULTです。未観測または合格は0です
	NativeError	  firstDependencySignatureError{} ;
	/// 最初の依存由来の元HRESULTです。未観測または合格は0です
	NativeError	  firstDependencyProvenanceError{} ;
	/// 選択文脈と全fieldを検査したNeedsの累積HKR設定行数です
	std::size_t	  verifiedRegistryRowCount{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 実検査した元基本INF閉包から必要役割の関係を構築します
 * @param[in] inspected 元保護byteと全署名を保持する同workerの内容検査です
 * @param[in] selectedPackages baseと全importの元順copyです。選択機能関係は私有native nodeから解析します
 * @param[out] plan 成功時だけ元閉包へ結合した不変計画です。失敗時は空です
 * @param[out] diagnostic 任意の数値診断です。nullなら採取せず合否へ使用しません
 * @param[in] registeredDeviceRead 自動起動ストレージの同じ選択機器を同期読取する操作。指定しない場合はnull
 * @param[in] displayDeviceRead Display補助の現在所有を同じ選択機器で読む操作。未指定ならnull
 * @return 内容と関係の一意な確認0、未対応・欠損・曖昧・循環は元HRESULTです
 * @note 計画は内容関係だけで、同意・復旧・PnP・私有install bindingを代替しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError makeRequiredDriverComponentPlan(
	const CommonInfInspection &inspected, std::span<const OfficialInfPackage> selectedPackages,
	std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	RequiredInfBindingDiagnostic					   *diagnostic			 = nullptr,
	const StorageRegisteredDeviceRead				   *registeredDeviceRead = nullptr,
	const DisplayRegisteredDeviceRead				   *displayDeviceRead	 = nullptr) ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsに渡す保護された登録元で付随INFの不在を再確認する
 * @param[in] inspected 登録元限定の不在を保持する検査済み単一基本INFの閉包
 * @return 同じ元親で通常名と圧縮名の両方が不在なら0、読取り失敗・変更・別用途はHRESULT
 * @note 同じ元親を固定して読取る。署名や作用に対する導入許可を発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyPreparedNativeCopyInfAbsence( const CommonInfInspection &inspected) ;

//------------------------------------------------------------------------------
/**
 * @brief 検査した基本INFの未解決CopyINFを付随参照として保持できるか判定する
 * @param[in] inspected 元配布の全内容検査と基本INFを保持する検査結果
 * @param[in] packageOrdinal 元順の位置。基本INFは0
 * @param[in] path 原INFから解決した相対参照
 * @return 同じ基本INFからの不在確認済み参照だけtrue
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		  canDeferMissingRootCopyInf( const CommonInfInspection &inspected,
													 std::size_t				packageOrdinal,
													 const std::wstring		   &path) noexcept ;

/** @brief 公開index/DTOから必要memberを追加できない不変内容計画です。導入能力を持ちません */
class RequiredDriverComponentPlan final {
public:
	/**
	 * @brief 必要関係を持たない空計画を作ります。factoryだけが内容を結合します
	 */
	RequiredDriverComponentPlan() = default ;
	/**
	 * @brief 非秘密の役割件数だけを返します
	 * @param[in] role 観測する追加役割です
	 * @return 一計画内0～7の確認済みmember数です
	 */
	[[nodiscard]] std::size_t count( DriverPlanRole role) const noexcept ;

private:
	friend class DriverStoreProvider ;
	friend class SignedIndexCandidateBindingSession ;
	/**
	 * @brief 実検査した元基本INF閉包から必要役割の関係を構築します
	 * @param[in] inspected 元保護byteと全署名を保持する同workerの内容検査です
	 * @param[in] selectedPackages baseと全importの元順copyです。選択機能関係は私有native nodeから解析します
	 * @param[out] plan 成功時だけ元閉包へ結合した不変計画です。失敗時は空です
	 * @note 第4引数（RequiredInfBindingDiagnostic *、out）はこの宣言では無名です。任意の数値診断です。nullなら採取せず合否へ使用しません
	 * @note 第5引数（const StorageRegisteredDeviceRead *、in）はこの宣言では無名です。nullまたは同じ選択機器の同期読取りです
	 * @note 第6引数（const DisplayRegisteredDeviceRead *、in）はこの宣言では無名。nullまたは同じ選択Displayの所有読取り
	 * @return 内容と関係の一意な確認0、未対応・欠損・曖昧・循環は元HRESULTです
	 * @note 計画は内容関係だけで、同意・復旧・PnP・私有install bindingを代替しません
	 */
	friend NativeError makeRequiredDriverComponentPlan(
		const CommonInfInspection &inspected, std::span<const OfficialInfPackage> selectedPackages,
		std::shared_ptr<const RequiredDriverComponentPlan> &plan, RequiredInfBindingDiagnostic *,
		const StorageRegisteredDeviceRead *, const DisplayRegisteredDeviceRead *) ;
	/** @brief 元CopyINFとAddComponentに一意に結合した役割memberです */
	struct Member {
		/// 同CommonInfInspection.requiredInfPackagesの0起点位置です
		std::size_t				  packageOrdinal{} ;
		/// 元class/GUIDで確認した追加役割です
		DriverPlanRole			  role{DriverPlanRole::EXTENSION} ;
		/// 必要SWCを作る元packageです。0はbase、以降はrequiredInfPackagesの1起点位置です
		std::size_t				  parentPackageOrdinal{} ;
		/// 当該元AddComponentの検証済みSWC IDです。Extensionでは空です
		std::vector<std::wstring> componentHardwareIds ;
	} ;
	/// 内容検査の非零scan sessionです
	ScanSessionId										  session_{} ;
	/// 元基本INFの相対pathです。worker内だけで保持します
	std::wstring										  basePath_ ;
	/// 元AddComponentの子、次に元閉包のExtensionを置く不変集合です。適用順の保証ではありません
	std::vector<Member>									  members_ ;
	/// 元順の全import copyです。selectedInstallSectionとactive関係は私有nodeへ結合します
	std::vector<OfficialInfPackage>						  selectedPackages_ ;
	/// 不在を確認した元基本INFの付随参照の扱い。Windows登録後の内容照合が必要です
	bool												  defersRootCopyInf_{} ;
	/// 実選択節のnative依存・全効果を検証したNeeds辺数です。八graphの累積最大32768です
	std::size_t											  verifiedNeedsEdgeCount_{} ;
	/// 元選択NeedsのINF/Store/CAT/固定helper全fileの不変tupleです
	std::vector<InfDependencyFixedFile>					  dependencyFiles_ ;
	/// 同選択の標準Windows登録helper/CAT/権限をnative直前に完全比較します
	std::vector<WindowsSystemFileTrust>					  systemFiles_ ;
	/// 同原文/文脈/所有者/全fieldの作用をfresh再構築へ比較します
	std::vector<SystemInfEffect>						  systemEffects_ ;
	/// 必要な既存serviceの安定configと元SDです
	std::vector<SystemServiceEvidence>					  systemServices_ ;
	/// 元基本ドライバーが上位フィルターを仮想Wi-Fiバスへ置換する場合trueです
	bool												  replacesWifiBusUpperFilters_{} ;
	/// storage PACKAGEの元全作用と必要な現serviceです。単独では導入許可ではありません
	std::optional<StorageInfEffects>					  storageEffects_ ;
	/// 元Display補助サービスの現在所有と共用の読取り。通常の候補にはない
	std::shared_ptr<const DisplayAuxiliaryOwnershipProof> displayOwnership_ ;
	/// 元内容で限定nullと確定した、機能roleを持たない0起点importです
	std::vector<std::size_t>							  stageOnlyImportOrdinals_ ;
	/// 固定RunOnceの成立からだけ発行する遅延factです
	bool												  delayedRegistration_{} ;
} ;

/** @brief 全INF検査の結果。全体失敗と個別INF拒否を分離する */
struct CommonDriverPackageInspection {
	/// 入力を固定したscan session。全体失敗では0
	ScanSessionId					 scanSessionId{} ;
	/// 外側入力の同一性hash。公式由来の証明ではない
	std::wstring					 archiveSha256 ;
	/// 外側入力のbyte数
	std::uint64_t					 archiveBytes{} ;
	/// 全体失敗のHRESULT。個別拒否だけなら0
	NativeError						 error{} ;
	/// 直下と一段内側を検査した通常fileの総数
	std::size_t						 inventoryFileCount{} ;
	/// 成功閉包の保持byte合計
	std::uint64_t					 retainedBytes{} ;
	/// 同操作の私有solid fileの実同時保持最大byte数
	std::uint64_t					 mappedSolidPeakBytes{} ;
	/// 同操作でdecodeした一意solid block数
	std::size_t						 decodedSolidBlockCount{} ;
	/// 成功と失敗を含む最大128 INF。PathとIDをUIへ渡さない
	std::vector<CommonInfInspection> infs ;
} ;

/** @brief collector専用の非実行内容です。通常binding/導入計画の入力型とは互換でありません */
struct CollectorInfContentInspection {
	/// 元archiveを固定したscan sessionです
	ScanSessionId							   scanSessionId{} ;
	/// 同所有workspaceだけの元INF相対位置です
	std::wstring							   infRelativePath ;
	/// 空または元一段archiveの相対位置です
	std::wstring							   nestedArchivePath ;
	/// 構造・全CAT/memberの到達段階で、導入資格を表しません
	CommonInfInspectionState				   state{CommonInfInspectionState::CLOSURE_REJECTED} ;
	/// 個別元HRESULTです。内容合格だけが0です
	NativeError								   error{} ;
	/// 全署名成功時だけ元byteの所有領域を保持します
	std::shared_ptr<OfficialDownloadWorkspace> workspace ;
	/// root一件と全memberの非実行内容です
	OfficialDriverClosure					   closure ;
	/// CopyINFから到達したimportです。独立候補へ変換しません
	std::vector<OfficialInfPackage>			   requiredInfPackages ;
	/// rootと全importの作用/不足棚卸しです。未対応も元findingへ保持します
	std::vector<MaintenanceInfStructure>	   effects ;
	/// 同梱依存を検査した公式Netだけが保持する、部分展開前の元容器の全通常ファイル
	std::vector<OfficialZipEntry>			   scopedDependencyArchiveEntries ;
	/// 棚卸し全体の元失敗です。0でも導入作用の全解釈を表しません
	NativeError								   effectInventoryError{} ;
} ;

/** @brief 非実行collector内容の集合です。公開codec・署名・端末適合・導入許可を持ちません */
struct CollectorDriverPackageContent {
	/// 元archiveのscan sessionです。全体失敗では0です
	ScanSessionId							   scanSessionId{} ;
	/// 元外側byteの小文字SHA-256です
	std::wstring							   archiveSha256 ;
	/// 元外側byte数です
	std::uint64_t							   archiveBytes{} ;
	/// 全体失敗の元HRESULTです
	NativeError								   error{} ;
	/// 全外側inventoryの通常file数です
	std::size_t								   inventoryFileCount{} ;
	/// 成功閉包の実保持byteです
	std::uint64_t							   retainedBytes{} ;
	/// 同操作の私有solid fileの実mapped peakです
	std::uint64_t							   mappedSolidPeakBytes{} ;
	/// 同操作でdecodeした一意solid block数です
	std::size_t								   decodedSolidBlockCount{} ;
	/// 明示rootだけの個別結果です。必須importをrootへ数えません
	std::vector<CollectorInfContentInspection> infs ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 明示したcollector rootを全CAT/参照付きの非実行内容だけへ検査します
 * @param[in] input 同操作中固定する原archive identityです
 * @param[in] format 実行しないZIP/CAB/SFX/resource形式です
 * @param[in] selectors 一段nestedと元INF相対位置の有限集合です。最大128件です
 * @param[out] content 個別拒否も保持する導入非互換型です。全体失敗時は診断だけです
 * @param[in] cancellation 同workerの非blocking取消し照会です
 * @param[in] scopedModels 同じ公式明細から得た一件の選択INFだけの対象です。通常はnullです
 * @return 全体検査完了0、原byte/容量/取消し等の全体失敗はHRESULTです
 * @note TapeDriveは通常共通Classに従います。追加のSCSIAdapter/MTDと必須System null importは導入資格を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCollectorDriverPackageContent(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	std::span<const std::pair<std::wstring_view, std::wstring_view>> selectors,
	CollectorDriverPackageContent &content, const std::function<bool()> &cancellation = {},
	const OfficialInfScopedModelsRequest *scopedModels = nullptr) ;

//------------------------------------------------------------------------------
/**
 * @brief 固定元readerで検査した通常fileから、選択INFとCAT・全参照・作用を確認する
 * @param[in] members 同じ私有収集操作で固定した元通常file群と元identity
 * @param[in] selectedInf 元範囲内の完全なINF相対名。大小文字を保持する
 * @param[in] platform 元定義が固定したWindows Server x64の明示観測点
 * @param[out] content 元閉包の非実行結果。個別失敗時は空
 * @param[out] identity 同じ署名済みINFと観測点の公開Models。失敗時は空
 * @return 全閉包と署名検査の完了時0、入力・取消し・I/O・内容検査の失敗はHRESULT
 * @note 内容用途の結果だけを作り、公開索引や導入許可を生成しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCollectorArchiveMembers( const CollectorArchiveMembers &members,
														 std::wstring_view				selectedInf,
														 const OfficialInfModelsPlatform &platform,
														 CollectorDriverPackageContent	 &content,
														 OfficialInfPublishedIdentity	 &identity) ;

//------------------------------------------------------------------------------
/**
 * @brief 審査済みの元ZIPから混在シリアルの元閉包と対象クライアントのModelsを検査する
 * @param[in] input 元ZIPのパス、実長、SHA-256と同じ私有収集操作の識別子
 * @param[in] reviewed 同じ外側ZIP、内側EXEと四つの元ファイルの審査条件
 * @param[in] selectedInf 元書庫内の完全なINF名。大小文字を保持する
 * @param[in] platform 公式配布対象のWindowsクライアントx64の明示観測点
 * @param[out] content 全内容と同梱依存を確認した元ZIPの私有結果。失敗時は空
 * @param[out] identity 同じ元INFと明示観測点の公開Models。失敗時は空
 * @param[in] cancellation 同じ収集操作の非blockingな停止照会。空は省略
 * @return 全取得・内容・同梱依存・対象Modelsが成立すれば0、それ以外は元HRESULT
 * @note 元EXEの実行、端末導入、公開用の許可発行は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCollectorReviewedSerialNsisContent(
	const DriverArchiveInput &input, const OfficialReviewedNsisZip &reviewed,
	std::wstring_view selectedInf, const OfficialInfModelsPlatform &platform,
	CollectorDriverPackageContent &content, OfficialInfPublishedIdentity &identity,
	const std::function<bool()> &cancellation = {}) ;

/** @brief 署名付きEXEと内側ZIP、対象Serverの元INFを結ぶ私有収集結果 */
struct CollectorSignedPeZipContent {
	/// 署名と取得証拠を照合した元EXEのbyte数
	std::uint64_t				  executableBytes{} ;
	/// 取得証拠から同じ元EXEと照合したSHA-256
	std::wstring				  executableSha256 ;
	/// 元EXE内で完全相対名が一致したZIP
	std::wstring				  zipMember ;
	/// 元EXEと区別した内側ZIPのhash・長さと選択INF検査結果
	CollectorDriverPackageContent inner ;
	/// 公式資料から呼出側が指定したServerのModels観測点
	OfficialInfModelsPlatform	  platform ;
	/// 署名を照合した選択INFから、指定したServerで読んだModels
	OfficialInfPublishedIdentity  identity ;
} ;

/** @brief 署名付きPEの版別条件で要求するSystem補助INFの種類 */
enum class CollectorPeZipImportRole {
	/// レジストリ登録だけを含む補助INF
	REGISTRY_ONLY,
	/// 空名の関連サービスだけを持つ補助INF
	NULL_SERVICE
} ;

/** @brief 同じ内側ZIPに含まれる必須補助INFの元名と審査した種類 */
struct CollectorPeZipRequiredImport {
	/// Windows区切りで大小文字を保持する完全相対名。検査が終わるまで呼出側が保持する
	std::wstring_view		 relativePath ;
	/// 共通の内容検査が確認する種類。省略した場合は従来のレジストリ専用
	CollectorPeZipImportRole role{CollectorPeZipImportRole::REGISTRY_ONLY} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 署名付きEXEの指定ZIPから主INFと指定した必須補助を検査し、ServerのModelsを読む
 * @param[in] input 同じ収集操作の現在user保護領域へ取得した元EXEの同一性
 * @param[in] acceptedPublishers 公式配布元定義にある外側の許可主署名者
 * @param[in] zipMember 元EXE内の完全なZIP相対名。Windows区切りで大小文字を保持する
 * @param[in] infMember 内側ZIPの主INFの完全相対名。Windows区切りで大小文字を保持する
 * @param[in] platform 公式配布対象として指定するWindows Server x64の観測点
 * @param[out] content 全検査成功時の元取得・内側内容・対象Models。失敗時は既定値
 * @param[in] cancellation 同workerの非blocking取消し照会。空なら取消し確認を省略する
 * @param[in] requiredImport 審査済みの必須補助INFの名前と種類。空なら主INF単独を要求する
 * @return 成功時0、取得、署名、選択INF、必須依存、Modelsまたは取消しの失敗時はHRESULT
 * @note 外側署名の証明書取得はcache内に限定する。EXE実行、公開、導入権限の発行は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCollectorSignedPeZipContent(
	const DriverArchiveInput &input, std::span<const std::wstring_view> acceptedPublishers,
	std::wstring_view zipMember, std::wstring_view infMember,
	const OfficialInfModelsPlatform &platform, CollectorSignedPeZipContent &content,
	const std::function<bool()>				   &cancellation   = {},
	std::optional<CollectorPeZipRequiredImport> requiredImport = std::nullopt) ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ原payloadの明示selectorを通常policyと一度の実保持で検査する
 * @param[in] input 同操作中固定する原archive identity
 * @param[in] format 明示ZIP/CAB/SFX形式。EXEは非実行解析だけを行う
 * @param[in] selectors firstが一段nested、secondが元INF相対名の検証済み集合。最大128件
 * @param[out] inspection 全成功時だけ元個別結果を保持する
 * @param[in] cancellation 空または同期workerの取消し照会
 * @return 元内容検査のHRESULT。個別拒否は元行へ残す
 * @note flat集合の同じmemberだけを共有し、任意UI/pathから由来や導入権限を作らない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSelectedCommonDriverPackages(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	std::span<const std::pair<std::wstring_view, std::wstring_view>> selectors,
	CommonDriverPackageInspection &inspection, const std::function<bool()> &cancellation = {}) ;

//------------------------------------------------------------------------------
/**
 * @brief 明示されたlocal archive一件を保護領域へ有限複製する
 * @param[in] selectedPath 利用者が選択したlocal drive上の絶対ZIP／CAB／非実行PE path
 * @param[in] scanSessionId 0ではないscan session
 * @param[in,out] workspace 未初期化領域。複製fileをscope終了まで所有する
 * @param[out] input 成功時の固定内容identity。失敗時は空
 * @param[out] format 成功時の形式。失敗時は使用しない
 * @return 通常file、有限copy、実size／hash固定に成功した場合0、それ以外はHRESULT
 * @note 2 GiB上限、1 MiB以下のchunkでcopyする。Networkも入力fileの実行も行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError copyLocalDriverArchive( std::wstring_view			  selectedPath,
												 ScanSessionId				  scanSessionId,
												 OfficialDownloadWorkspace	 &workspace,
												 DriverArchiveInput			 &input,
												 OfficialDriverArchiveFormat &format) ;

//------------------------------------------------------------------------------
/**
 * @brief 固定済み入力の全INFを個別の保護閉包とWindows署名で検査する
 * @param[in] input 呼出し中有効な保護archive identity。由来判定は含まない
 * @param[in] format ZIPまたはCAB。実行形式を拒否する
 * @param[out] inspection 全体成功時は全個別結果。全体失敗時はerrorだけを保持する
 * @param[in] cancellation 空またはworker内で呼ぶ非blocking取消し照会
 * @return 全INFの検査完了時0、入力・全体上限・取消し・例外時はHRESULT
 * @note 個別拒否でも残りを検査する。全体失敗では部分合格を破棄する。導入・stagingは行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCommonDriverPackage(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	CommonDriverPackageInspection &inspection, const std::function<bool()> &cancellation = {}) ;

//------------------------------------------------------------------------------
/**
 * @brief 監視側が固定した一INFだけを既存通常policyで内容検査します
 * @param[in] input 同operationが所有する固定archiveの原identityです
 * @param[in] format 元copyが判別したZIP/CABINETです
 * @param[in] selectedInf 実inventoryへ完全一致させる原相対INF名です。空/別形式を拒否します
 * @param[out] inspection 一INFの成功/拒否と全外側inventory件数です。全packageの完了ではありません
 * @param[in] cancellation 同workerの協調停止です
 * @param[in] nestedArchive 空または原outer内の一段nested memberです。実行しません
 * @return 一INFの評価完了0、入力/全体破損/取消し時は元HRESULTです
 * @note 旧全INF入口を変更しません。未選択INFは未検査で、取得/公式性/端末適用性/導入を認定しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSelectedCommonDriverPackage(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	std::wstring_view selectedInf, CommonDriverPackageInspection &inspection,
	const std::function<bool()> &cancellation = {}, std::wstring_view nestedArchive = {}) ;

//------------------------------------------------------------------------------
/**
 * @brief WiXの保護済み単一ストレージINFを同じファイルから端末用に再検査する
 * @param[in] session 元の取得と展開に使った非零スキャン識別子
 * @param[in] workspace 元INF・CAT・全参照を保持する同じ管理者保護領域の共有所有者
 * @param[in] original 署名済みWiX配布を認証して得た元閉包。元の全相対名、長さとSHA-256を持つ
 * @param[out] inspected 成功時は端末用に再解析した閉包と同じ領域の共有所有者。失敗時は診断だけ
 * @return 同じ単一SCSI基本INFの全内容とWindows署名が一致した場合0、それ以外はHRESULT
 * @pre 同じworkerで元配布を認証し、入力と別の結果を使って呼出し期間中は元閉包と領域を変更しない
 * @note 元領域を移動せず、端末適用性、同意、ストレージ作用の導入許可は別に確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectRetainedStorageInf(
	ScanSessionId session, const std::shared_ptr<OfficialDownloadWorkspace> &workspace,
	const OfficialDriverClosure &original, CommonInfInspection &inspected) ;

//------------------------------------------------------------------------------
/**
 * @brief 成功閉包の全file、metadata、署名を同一policyで再検証する
 * @param[in] inspected 保護領域を保持するVERIFIED結果
 * @return 全fileのsize／hash、INF metadata、Windows署名一致時0、それ以外はHRESULT
 * @note 導入許可やdevice bindingの検査を代替しない。Workerから呼ぶ
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError reverifyCommonDriverInf( const CommonInfInspection &inspected) ;

//------------------------------------------------------------------------------
/**
 * @brief 端末が検査した閉包の元用途・全ファイル・署名を再確認する
 * @param[in] inspected 通常の成功閉包または管理領域で確認した独自クラスの成功閉包
 * @return 検査内容が現在の元ファイルと一致した場合0、それ以外はHRESULT
 * @note 独自クラスの内容結果から導入資格を発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError reverifyCommonDriverInfContent( const CommonInfInspection &inspected) ;

//------------------------------------------------------------------------------
/**
 * @brief appの元選択archiveを独立に内容検査し、storage専用の非権限用途を記録します
 * @param[in] input 同scanのADMIN保護原archiveです
 * @param[in] format 元取得計画の非実行container形式です
 * @param[in] selectors 元署名recordのnested/INF位置の閉集合です
 * @param[out] inspection 全体失敗時空、個別失敗は元診断を保持します
 * @param[in] cancellation 同workerの協調取消しです。空は取消しなしです
 * @return 全体検査完了0、それ以外は原HRESULTです
 * @note collector DTOの変換を受けず、端末適用性やstorage導入資格を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSelectedDeviceDriverPackages(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	std::span<const std::pair<std::wstring_view, std::wstring_view>> selectors,
	CommonDriverPackageInspection &inspection, const std::function<bool()> &cancellation = {}) ;

//------------------------------------------------------------------------------
/**
 * @brief 内容合格INFとWindows適合観測を候補の八軸へ結合する
 * @param[in] scanSessionId 内容検査と一致するscan session
 * @param[in] candidate 結合先のopaque IDを持つ表示候補
 * @param[in] inspected 本workerが実検査したVERIFIED閉包
 * @param[in] evidenceId Scan内で当該検査へ一意に割り当てた0ではない証拠ID
 * @param[in] origin 取得層が確認した由来finding。LocalはUSER_PROVIDEDのままとする
 * @param[in] applicabilityError Windows適合観測のHRESULT。未実施を0で渡さない
 * @param[in] candidateRank Windowsの一致nodeのrank。非適用・失敗時は空
 * @param[out] assessment 全成功時の八軸。入力不正では空
 * @return 証拠とidentityを結合できた場合true。実行可能を意味しない
 * @note 現在driverとの順位比較とexecutor接続は行わず、導入可能へ昇格させない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool makeCommonInfCandidateAssessment(
	ScanSessionId scanSessionId, const UpdateCandidate &candidate,
	const CommonInfInspection &inspected, std::uint64_t evidenceId,
	const CandidateAssessmentFinding &origin, NativeError applicabilityError,
	std::optional<std::uint32_t> candidateRank, CandidateAssessment &assessment) ;

} // namespace drivercrate
