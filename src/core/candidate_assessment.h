//------------------------------------------------------------------------------
/**
 * @file candidate_assessment.h
 * @brief 候補の検証軸・具体的理由・必須条件・導入方式の有限契約。
 * @version 01.03.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  候補の有限な詳細検証契約を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  検査で判明した構成役割と未収集を分離。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * </pre>
 *
 * @note 値は同じscanの証拠に結合し、未確認を合格へ補完しない。OS・networkへ作用しない。
 * @see docs/adr/0150-device-observation-and-candidate-assessment-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/device_observation.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 集約auditから独立した固定の詳細検証軸。 */
enum class CandidateAssessmentAxis {
	/// 公式由来と利用者持込みの区別。
	ORIGIN,
	/// 取得・参照file閉包・hashの確認。
	ACQUISITION,
	/// 署名とWindows policyの確認。
	SIGNATURE,
	/// PnP・OS・x64の基礎適合。
	APPLICABILITY,
	/// 現在版と候補のWindows選択関係。
	WINDOWS_SELECTION,
	/// 選択した内容のdriver-only分類。
	DRIVER_ONLY,
	/// 明示された必須条件の確認。
	REQUIREMENTS,
	/// 導入方式とexecutorの実装状況。
	METHOD,
} ;

/** @brief 不適合・実行失敗・未対応を混同しない詳細状態。 */
enum class CandidateAssessmentState {
	/// 検査しておらず合否を判断できない。
	NOT_CHECKED,
	/// 当該軸の明示的な検査に合格した。
	PASSED,
	/// 当該検査で具体的な不適合を確認した。
	REJECTED,
	/// API等が失敗し確認できなかった。
	FAILED,
	/// 現実装では必要な形式・方式を検査できない。
	UNSUPPORTED,
	/// 明示的な検査範囲でこの条件を必要としない。
	NOT_APPLICABLE,
	/// 判定をWindows管理経路へ委譲する。
	MANAGED_BY_WINDOWS,
} ;

/** @brief UIへ本文や秘密識別子を渡さない有限な理由。 */
enum class CandidateAssessmentReason {
	/// 当該詳細をまだ検査していない。
	NOT_EXAMINED,
	/// 指定軸の検証を通過した。
	VALIDATED,
	/// Windows標準の管理経路を使用する。
	WINDOWS_MANAGED,
	/// API失敗のため判定できなかった。
	API_FAILURE,
	/// 必要な形式の検査が未対応である。
	FORMAT_UNSUPPORTED,
	/// 公式由来をまだ確認できていない。
	ORIGIN_UNVERIFIED,
	/// 利用者持込みで公式由来を証明しない。
	USER_PROVIDED,
	/// 公式起点の検証で拒否された。
	ORIGIN_REJECTED,
	/// 配布recordからCDNへの委譲が未確認である。
	DELEGATION_UNVERIFIED,
	/// 検査対象の取得がまだ完了していない。
	NOT_ACQUIRED,
	/// 実参照fileが不足している。
	REFERENCED_FILE_MISSING,
	/// 結合した期待hashと内容が一致しない。
	HASH_MISMATCH,
	/// Windows policyの署名検証で拒否された。
	SIGNATURE_INVALID,
	/// 必要な署名者根拠を確認できない。
	PUBLISHER_UNVERIFIED,
	/// 実deviceのPnP照合で一致しなかった。
	PNP_MISMATCH,
	/// 対象OS条件が一致しなかった。
	OS_MISMATCH,
	/// x64条件が一致しなかった。
	ARCHITECTURE_MISMATCH,
	/// 現在候補との順位比較を実施できていない。
	RANK_UNVERIFIED,
	/// 基礎適合とは別の旧非退行policyで保留された。
	LEGACY_POLICY_HOLD,
	/// 現在driverから変更がない。
	NO_CHANGE,
	/// 適合候補だがWindowsの推奨選択ではない。
	NOT_RECOMMENDED,
	/// 対象そのものがfirmwareである。
	FIRMWARE_PAYLOAD,
	/// 選択driverとfirmware更新を分離できない。
	INSEPARABLE_FIRMWARE_UPDATE,
	/// 確認範囲に明示された必須条件がない。
	NO_EXPLICIT_REQUIREMENT,
	/// 明示必須条件が不足している。
	REQUIREMENT_UNSATISFIED,
	/// 明示必須条件の必要値を確認できていない。
	REQUIREMENT_UNVERIFIED,
	/// 当該方式の実行経路が未実装である。
	EXECUTOR_UNAVAILABLE,
	/// 実行する範囲をまだ確認していない。
	EXECUTION_SCOPE_UNVERIFIED,
	/// 公式installerの対話手順へ選択を引き継ぎ、標準INF順位は適用しません。
	INSTALLER_HANDOFF_SELECTION,
	/// Binary作用証明ではなく、原公式手順の選択対象限定申告です。
	INSTALLER_SCOPE_ATTESTED,
} ;

/** @brief 秘密を含まないworker内証拠の種類。自己申告だけを検証成功としない。 */
enum class CandidateEvidenceKind {
	/// 未検査で参照すべき証拠がない。
	NONE,
	/// Windows APIの検証結果である。
	WINDOWS_API,
	/// 検証した公式配布recordである。
	OFFICIAL_RECORD,
	/// 実取得物に対する検査結果である。
	PACKAGE_INSPECTION,
	/// 利用者が明示した入力由来である。
	USER_INPUT,
	/// 実装済み方式や限定policyの事実である。
	IMPLEMENTATION_POLICY,
	/// 署名索引の収集者確認。公式live本文やメーカー署名と区別します。
	COLLECTOR_ATTESTATION,
} ;

/** @brief 一軸の主理由とscan内の検証証拠。 */
struct CandidateAssessmentFinding {
	/// 未検査を既定とする検証結果。
	CandidateAssessmentState		state{CandidateAssessmentState::NOT_CHECKED} ;
	/// 状態と対象軸に矛盾しない固定理由。
	CandidateAssessmentReason		reason{CandidateAssessmentReason::NOT_EXAMINED} ;
	/// 根拠の種類。未検査ではNONEを許す。
	CandidateEvidenceKind			evidenceKind{CandidateEvidenceKind::NONE} ;
	/// 同じscan内のopaqueな証拠連番。証拠なしの場合だけ0。
	std::uint64_t					evidenceId{} ;
	/// API失敗時の元診断。成功時は持たない。
	std::optional<DeviceDiagnostic> diagnostic ;
} ;

/** @brief 導入経路の種類。実行許可とは独立する。 */
enum class CandidateInstallMethod {
	/// 方式を確定できていない。
	UNDETERMINED,
	/// WUAまたはWindows管理の導入経路。
	WINDOWS_MANAGED,
	/// 検証済み標準INFの指定導入経路。
	STANDARD_INF,
	/// 公式installerへ明示的に引き継ぐ経路。
	OFFICIAL_INSTALLER,
	/// 自動実行しない手動経路。
	MANUAL,
} ;

/** @brief 明示条件の充足状態。解析未実施を条件なしとしない。 */
enum class CandidateRequirementState {
	/// 検査範囲に明示必須条件がない。
	NO_EXPLICIT_REQUIREMENT,
	/// 明示された条件を満たす。
	SATISFIED,
	/// 明示された条件を満たさない。
	UNSATISFIED,
	/// 必要な値を確認できない。
	UNVERIFIED,
} ;

/** @brief 条件の対象役割。必須性は名前から推測せず別に持つ。 */
enum class CandidateComponentRole {
	/// Deviceの基本driverである。
	BASE_DRIVER,
	/// 基本driverと別packageのextension INFである。
	EXTENSION_INF,
	/// 明示的なcomponentである。
	COMPONENT,
	/// Utilityであり自動導入対象ではない。
	UTILITY,
	/// NVM等の既存firmware状態への条件であり更新指示ではない。
	FIRMWARE_STATE,
} ;

/** @brief 出典と対象を結合した一つの明示条件。 */
struct CandidateExplicitRequirement {
	/// 同じscan内のopaqueな条件連番。0を拒否する。
	std::uint64_t			  requirementId{} ;
	/// 必須／任意と独立した対象役割。
	CandidateComponentRole	  role{CandidateComponentRole::COMPONENT} ;
	/// 公式の明示必須条件の場合だけtrue。
	bool					  required{} ;
	/// 条件の実測状態。個別条件では条件なしを使用しない。
	CandidateRequirementState state{CandidateRequirementState::UNVERIFIED} ;
	/// 条件の出典。公式recordまたはpackage検査に限定する。
	CandidateEvidenceKind	  evidenceKind{CandidateEvidenceKind::NONE} ;
	/// 出典・対象を結合したworker内のopaque証拠連番。
	std::uint64_t			  evidenceId{} ;
} ;

/** @brief 同一候補の固定八軸と最大16条件の詳細検証snapshot。 */
struct CandidateAssessment {
	/// 証拠を所有する0ではないscan session。
	std::uint64_t							  scanSessionId{} ;
	/// 結合する表示候補のopaque identity。
	std::wstring							  candidateIdentity ;
	/// 結合するdeviceのopaque identity。
	std::wstring							  deviceIdentity ;
	/// 結合するpackageのopaque identity。未取得時は空を許す。
	std::wstring							  packageIdentity ;
	/// 由来の主理由。
	CandidateAssessmentFinding				  origin ;
	/// 取得・閉包の主理由。
	CandidateAssessmentFinding				  acquisition ;
	/// 署名の主理由。
	CandidateAssessmentFinding				  signature ;
	/// 基礎適合の主理由。
	CandidateAssessmentFinding				  applicability ;
	/// Windows選択の主理由。
	CandidateAssessmentFinding				  windowsSelection ;
	/// Driver-onlyの主理由。
	CandidateAssessmentFinding				  driverOnly ;
	/// 明示必須条件の主理由。
	CandidateAssessmentFinding				  requirements ;
	/// 方式の主理由。
	CandidateAssessmentFinding				  method ;
	/// 確定した導入方式。未確定を既定とする。
	CandidateInstallMethod					  installMethod{CandidateInstallMethod::UNDETERMINED} ;
	/// 当該方式のexecutorが存在する場合だけtrue。選択許可ではない。
	bool									  executorAvailable{} ;
	/// 出典確認済み条件だけの有限集合。重複・16件超過を拒否する。
	std::vector<CandidateExplicitRequirement> explicitRequirements ;
	/// 当該packageの検査で判明した役割。未設定は役割未収集。
	std::optional<CandidateComponentRole>	  componentRole ;
} ;

/**
 * @brief 一軸の状態・理由・証拠・診断の組を純粋検証する。
 * @param[in] axis 固定の対象軸。
 * @param[in] finding 当該軸の主理由。
 * @return 未知enum、理由の軸違い、矛盾がなければtrue。
 */
[[nodiscard]] bool isCandidateAssessmentFindingValid(
	CandidateAssessmentAxis axis, const CandidateAssessmentFinding &finding) noexcept ;

/**
 * @brief 全軸と明示条件・方式の内部整合性を検証する。
 * @param[in] assessment 同じscanの詳細snapshot。
 * @return 有限上限と状態の不変条件を満たす場合true。
 */
[[nodiscard]] bool isCandidateAssessmentValid( const CandidateAssessment &assessment) noexcept ;

/**
 * @brief 詳細の証拠が呼出し側の候補へ完全一致するか検証する。
 * @param[in] assessment 検証対象の詳細。
 * @param[in] scanSessionId 現在のscan session。
 * @param[in] candidateIdentity 表示候補のidentity。
 * @param[in] deviceIdentity Deviceのidentity。
 * @param[in] packageIdentity Packageのidentity。未取得時は空。
 * @return 全結合と内部整合性が成立する場合true。
 */
[[nodiscard]] bool isCandidateAssessmentBound( const CandidateAssessment &assessment,
											  std::uint64_t				 scanSessionId,
											  std::wstring_view			 candidateIdentity,
											  std::wstring_view			 deviceIdentity,
											  std::wstring_view			 packageIdentity) noexcept ;

/**
 * @brief 詳細の全必要条件が導入を妨げないか確認する。
 * @param[in] assessment 内部整合性も再確認する詳細。
 * @return 実装済み方式と全必要軸が合格・委譲・正当な非該当の場合true。
 * @note これだけでは導入を許可せず、既存audit・session・Provider bindingも必須とする。
 */
[[nodiscard]] bool isCandidateAssessmentReady( const CandidateAssessment &assessment) noexcept ;

} // namespace drivercrate
