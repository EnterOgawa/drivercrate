//------------------------------------------------------------------------------
/**
 * @file inf_dependency_plan.h
 * @brief 有限INF依存の共通観測核と非実行計画の定義。
 * @version 01.00.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  有限依存核・三証拠軸・非実行計画を追加。
 * </pre>
 *
 * @note worker内でloaderを同期借用する。名称はworkerだけで保持し、実loader・導入許可は提供しない。
 * @see docs/adr/0269-bounded-inf-dependency-core-and-review-plan.md
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

/** @brief loaderの独立した一検証軸。存在のboolで代替しない。 */
enum class InfDependencyEvidence {
	/// 当該検査は未実施。
	NOT_CHECKED,
	/// loaderが当該検査を実施して確認した。
	VERIFIED,
	/// loaderが当該検査を実施して不合格だった。
	FAILED,
} ;

/** @brief loaderが確認する配布境界。enumだけで由来を認定しない。 */
enum class InfDependencyOrigin {
	/// 保護されたpackage内のINF。
	PACKAGE,
	/// 対象OSのsystem領域で観測するINF。
	SYSTEM,
} ;

/** @brief 同一端末の同一観測世代に拘束するOS文脈。外部へ保存しない。 */
struct InfDependencyContext {
	/// 観測したOS major。非零。
	std::uint32_t major{} ;
	/// 観測したOS minor。
	std::uint32_t minor{} ;
	/// 観測したOS build。非零。
	std::uint32_t build{} ;
	/// PE machine。0x8664だけを受理する。
	std::uint16_t machine{0x8664U} ;
	/// Serverならtrue。clientとの文脈転用を拒否する。
	bool		  windowsServer{} ;
	/// local観測世代のopaque値。非零で、移設先の充足へ転用しない。
	std::uint64_t observationId{} ;
} ;

/** @brief 一つのINFの観測snapshot。path・PnP IDを保持しない。 */
struct InfDependencyDocument {
	/// loaderのrun内identity。非零。同一値の異なる内容を拒否する。
	std::uint64_t		  identity{} ;
	/// 原byteの小文字SHA-256。名称のhashではない。
	std::wstring		  sha256 ;
	/// 原byte数。1 byte以上4 MiB以下。
	std::uint64_t		  byteCount{} ;
	/// package／system境界。由来検証とは別の値。
	InfDependencyOrigin	  origin{InfDependencyOrigin::PACKAGE} ;
	/// 期待byteとの結合。未確認では節を読み取らない。
	InfDependencyEvidence byteBinding{InfDependencyEvidence::NOT_CHECKED} ;
	/// 配布・system由来の独立した検証結果。
	InfDependencyEvidence provenance{InfDependencyEvidence::NOT_CHECKED} ;
	/// 当該INFの署名の独立した検証結果。全参照member署名ではない。
	InfDependencyEvidence signature{InfDependencyEvidence::NOT_CHECKED} ;
	/// 全入力と一致すべき同一OS／端末観測文脈。
	InfDependencyContext  context ;
} ;

/** @brief 今回解釈する明示参照の種類。他の作用は未評価のまま残る。 */
enum class InfDependencyDirective {
	/// 同じ元節で参照するINF。
	INCLUDE,
	/// 明示名で参照する処理節。
	NEEDS,
} ;

/** @brief 元節内の一参照。重複辺を消さない。 */
struct InfDependencyReference {
	/// IncludeまたはNeeds。未知enumは全体拒否する。
	InfDependencyDirective directive{InfDependencyDirective::NEEDS} ;
	/// worker内だけの原INF相対名または明示節名。値・commandではない。
	std::wstring		   target ;
} ;

/** @brief 一節に対するloaderの調査段階。未検査を未発見に変えない。 */
enum class InfDependencyReadState {
	/// 節の存在を照会していない。
	NOT_CHECKED,
	/// 照会済みで明示節がない。
	MISSING,
	/// 照会済みで明示節が存在する。作用完全性は未評価。
	PRESENT,
} ;

/** @brief 一明示節の有限なInclude／Needs観測。 */
struct InfDependencySection {
	/// 明示節の存在観測。PRESENT以外の参照集合は空にする。
	InfDependencyReadState				state{InfDependencyReadState::NOT_CHECKED} ;
	/// 一節最大4,096辺。元節はreadSection引数から結合する。
	std::vector<InfDependencyReference> references ;
} ;

/** @brief Include先の有限候補。照会未実施と照会済み未発見を区別する。 */
struct InfDependencyLookup {
	/// 照会完了ならtrue。falseの候補集合は空にする。
	bool							   checked{} ;
	/// 最大64の異なるrun内identity。複数候補を最初の一件へ絞らない。
	std::vector<InfDependencyDocument> documents ;
} ;

/** @brief 元INFと相対名を同期借用し有限候補へ返す関数型。 */
using InfDependencyLookupFunction = std::function<NativeError(
	const InfDependencyDocument &, std::wstring_view, InfDependencyLookup &)> ;

/** @brief byte結合済みINFと明示節を同期借用し有限観測へ返す関数型。 */
using InfDependencyReadFunction = std::function<NativeError(
	const InfDependencyDocument &, std::wstring_view, InfDependencySection &)> ;

/** @brief 実byte・Windows節調査を分離する同期loader契約。実adapterは別工程。 */
struct InfDependencyOperations {
	/// sourceと安全なInclude原名を借用し候補へ返す。0以外は全体拒否。captureは呼出し中生存する。
	InfDependencyLookupFunction								  lookup ;
	/// byte結合済みdocumentと明示節を借用し有限観測へ返す。装飾名を推測しない。0以外は全体拒否。
	InfDependencyReadFunction								  readSection ;
	/// 全発見documentのbyte／OS snapshot不変を再確認する。証拠軸を更新しない。0以外は全体拒否。
	std::function<NativeError( const InfDependencyDocument &)> recheck ;
} ;

/** @brief 明示辺だけの解決観測。導入充足ではない。 */
enum class InfDependencyState {
	/// 存在観測はあるが独立証拠が未確認／不合格。
	OBSERVED,
	/// package由来・byte・署名を確認した明示参照先。
	RESOLVED_PACKAGE,
	/// 同OSのsystem由来・byte・署名を確認した明示参照先。
	RESOLVED_SYSTEM,
	/// 照会済み未発見・曖昧・循環の参照。
	UNRESOLVED,
	/// 当該参照は照会されていない。
	NOT_CHECKED,
	/// 参照文字列が境界に違反しloaderを呼ばなかった。
	INVALID_REFERENCE,
} ;

/** @brief 保留の理由。未知・存在・署名を一つの失敗へ潰さない。 */
enum class InfDependencyReason {
	/// 明示辺は検証済み対象へ一意に結合した。
	NONE,
	/// 当該照会が未実施。
	NOT_CHECKED,
	/// 照会済みで対象未発見。
	MISSING,
	/// 複数の候補があり一意に結合できない。
	AMBIGUOUS,
	/// 再帰中の同じdocument／節への循環。
	CYCLE,
	/// byte・由来・署名の一つ以上が未確認／不合格。
	EVIDENCE_INCOMPLETE,
	/// 相対名または節名が不正。
	INVALID_NAME,
} ;

/** @brief 元INF・元節へ結合した一辺の結果。名称はworker内だけで保持する。 */
struct InfDependencyEdge {
	/// 非零の元document identity。
	std::uint64_t		   sourceIdentity{} ;
	/// 元の明示節名。
	std::wstring		   sourceSection ;
	/// Include／Needsの原対象名。
	std::wstring		   target ;
	/// 元参照の種類。
	InfDependencyDirective directive{InfDependencyDirective::NEEDS} ;
	/// 解決観測。署名や実device導入許可へ変換しない。
	InfDependencyState	   state{InfDependencyState::NOT_CHECKED} ;
	/// 未解決／未検査等の具体的理由。
	InfDependencyReason	   reason{InfDependencyReason::NOT_CHECKED} ;
	/// 一意対象なら非零。未発見・曖昧なら0。
	std::uint64_t		   targetIdentity{} ;
	/// 明示対象候補数。最大64。
	std::size_t			   candidateCount{} ;
} ;

/** @brief 一度だけ走査したdocument／節。共有節の再走査を止める。 */
struct InfDependencyVisitedSection {
	/// document identity。
	std::uint64_t		   identity{} ;
	/// worker内だけの明示節名。
	std::wstring		   section ;
	/// 明示節の存在観測。
	InfDependencyReadState state{InfDependencyReadState::NOT_CHECKED} ;
} ;

/** @brief 参照資料と基本driverの確認役割。追加導入の指示ではない。 */
struct InfDependencyPlanEntry {
	/// graph内documentの非零identity。
	std::uint64_t identity{} ;
	/// rootの基本driverならtrue。falseは参照資料で、自動導入対象ではない。
	bool		  baseDriver{} ;
} ;

/** @brief 導入能力を持たない独立した確認用計画。 */
struct InfDependencyReviewPlan {
	/// rootと発見した参照資料の確認項目。実行順序ではない。
	std::vector<InfDependencyPlanEntry> entries ;
	/// 明示辺とseed節が全て確認済みの場合true。全作用・device充足ではない。
	bool								referencesResolved{} ;
	/// rootのbyte・由来・署名が全て確認済みの場合true。
	bool								rootEvidenceVerified{} ;
	/// 作用完全性の検査状態。核は常にNOT_CHECKEDとする。
	InfDependencyEvidence				actionCoverage{InfDependencyEvidence::NOT_CHECKED} ;
	/// 実device適用性の検査状態。核は常にNOT_CHECKEDとする。
	InfDependencyEvidence				deviceApplicability{InfDependencyEvidence::NOT_CHECKED} ;
	/// 導入方式／公式installer評価。核は常にNOT_CHECKEDとする。
	InfDependencyEvidence				installRoute{InfDependencyEvidence::NOT_CHECKED} ;
} ;

/** @brief 全callback・再確認成功後だけ返す非実行観測。 */
struct InfDependencyResult {
	/// 同一OS／端末観測文脈。
	InfDependencyContext					 context ;
	/// 最大64 INFのsnapshot。hash／sizeと独立証拠をそのまま保持する。
	std::vector<InfDependencyDocument>		 documents ;
	/// 最大1,024の走査節。未検査／未発見も含む。
	std::vector<InfDependencyVisitedSection> sections ;
	/// 最大4,096辺の全結果。重複・拒否・曖昧も残す。
	std::vector<InfDependencyEdge>			 edges ;
	/// 導入型と互換でない確認用計画。
	InfDependencyReviewPlan					 plan ;
} ;

/**
 * @brief 同節Include／Needsを有限に観測し、非実行計画へ結合する。
 * @param[in] root byte結合済みの開始INF snapshot。
 * @param[in] seeds 同じroot内で観測する1～1,024の明示節名。
 * @param[in] operations worker内で同期借用するloader。再入・別thread操作は禁止する。
 * @param[out] result 全観測・全document再確認成功時のみ保持し、失敗時は空。
 * @return 観測成功0、入力／容量／OS差／callback失敗のHRESULT。
 * @pre 入力と出力の所有storageはaliasしない。
 * @note 最大64 INF・1,024節・4,096辺・32段。実byte loader、署名検証、導入許可は核自身では提供しない。
 */
[[nodiscard]] NativeError resolveInfDependencies( const InfDependencyDocument   &root,
												 std::span<const std::wstring>	seeds,
												 const InfDependencyOperations &operations,
												 InfDependencyResult		   &result) ;

} // namespace drivercrate
