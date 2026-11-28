//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding.cpp
 * @brief 索引の私有取得根拠とWindows指定bindingを原子的候補へ接続します
 * @version 01.51.00
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/10/12  元grant再結合と収集者由来の局所宣言を説明
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  複数INFと厳密共有taskの全deviceへ独立bindingを発行
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  通常索引の必要構成選択と役割別部分結果へ接続
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  元private node選択後の必要構成発行へ通常索引を接続
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  記述済みnative部分positiveの一device参照を保持
 * Ver.01.05.01 Shunji Ogawa  2026/10/15  全体内容INF件数をdevice別導入計画上限から分離
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  実選択Needs前提を追加INFと分離し候補評価へ接続
 * Ver.01.06.01 Shunji Ogawa  2026/10/15  再検証成功時も元全体内容検査のHRESULTをreportへ維持
 * Ver.01.06.02 Shunji Ogawa  2026/10/19  取得前参照へ現在driverのpackage情報を継承しない
 * Ver.01.07.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合
 * Ver.01.07.01 Shunji Ogawa  2026/10/24  必須解析の型・有限所有buffer・失敗制御を明示
 * Ver.01.08.00 Shunji Ogawa  2026/10/27  個別device投影と同record/deviceの基本参照集約を接続
 * Ver.01.08.01 Shunji Ogawa  2026/10/28  全選択検証後からbatch終端まで元proof寿命を保持
 * Ver.01.09.00 Shunji Ogawa  2026/10/28  元選択に結合した取得・検査と導入の二段階操作へ接続
 * Ver.01.10.00 Shunji Ogawa  2026/11/03  未署名検査と通常候補の完全tuple比較を共用
 * Ver.01.11.00 Shunji Ogawa  2026/11/03  記述済みINF参照へ取得前版だけを投影
 * Ver.01.12.00 Shunji Ogawa  2026/11/06  同元付属DATAを私有Windows-only scope計画へ接続
 * Ver.01.13.00 Shunji Ogawa  2026/11/06  代替Modelsを一選択へ集約し唯一の実tupleを保持
 * Ver.01.13.01 Shunji Ogawa  2026/11/07  同原packageの共同保持と現非実行policyを整合
 * Ver.01.14.00 Shunji Ogawa  2026/11/08  同内容候補の表示集約と元一件選択を保持
 * Ver.01.15.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.16.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続
 * Ver.01.16.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.16.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.16.03 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.16.04 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.16.05 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.17.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.18.00 Shunji Ogawa  2026/11/17  原record期限の再照合とMTD部分作用を接続
 * Ver.01.19.00 Shunji Ogawa  2026/11/18  全原参照先行検証後のhost取消しと最終Modelsを接続
 * Ver.01.19.01 Shunji Ogawa  2026/11/18  host拒否の公開失敗集計と当該reportのpending撤回を整合
 * Ver.01.20.00 Shunji Ogawa  2026/11/19  正規client最低buildの候補・最終Modelsと同hostを再確認
 * Ver.01.21.00 Shunji Ogawa  2026/11/19  独自クラスの内容結果を導入候補のランク観測から除外
 * Ver.01.22.00 Shunji Ogawa  2026/11/19  署名Models一致後に独自クラスの元null行を端末で判定
 * Ver.01.23.00 Shunji Ogawa  2026/11/19  独自クラスの登録を読み取った診断段階を保持
 * Ver.01.24.00 Shunji Ogawa  2026/11/19  実Models行の順位監査を候補発行の保留と区別
 * Ver.01.25.00 Shunji Ogawa  2026/11/19  独自クラスの元閉包を実適用前の配置先照合に結合
 * Ver.01.26.00 Shunji Ogawa  2026/11/19  独自クラスの同意と二時点の元署名レコード再確認を接続
 * Ver.01.27.00 Shunji Ogawa  2026/11/20  照合済みのCatalog対象IDを指定導入の元bindingへ渡す
 * Ver.01.28.00 Shunji Ogawa  2026/11/20  候補と指定導入の元位置を端末用レコード参照に統一
 * Ver.01.29.00 Shunji Ogawa  2026/11/20  Catalog対象の元Models・取得期限を復元と指定導入の境界へ接続
 * Ver.01.30.00 Shunji Ogawa  2026/11/20  機種別行の内容検査と指定導入tokenの発行を分離
 * Ver.01.31.00 Shunji Ogawa  2026/11/20  機種条件付きINFの適用確認と指定導入前の再照合を接続
 * Ver.01.32.00 Shunji Ogawa  2026/11/20  機器別の確認対象と同じ端末にだけ候補参照を発行
 * Ver.01.33.00 Shunji Ogawa  2026/11/20  取得済み候補の現在群を確認し指定導入の結合を保留
 * Ver.01.34.00 Shunji Ogawa  2026/11/20  同じ端末の承認と公式群を登録・適用の直前へ結合
 * Ver.01.34.01 Shunji Ogawa  2026/11/20  対象機器の最終観測後に導入時の取得許可と元レコードの期限を確認
 * Ver.01.35.00 Shunji Ogawa  2026/11/21  検査した共有起動ログ作用を候補表示へ渡す
 * Ver.01.36.00 Shunji Ogawa  2026/11/22  専用Modelsの内容合格と未評価の導入資格を区別
 * Ver.01.37.00 Shunji Ogawa  2026/11/22  公式範囲の保持閉包を候補評価で再検査
 * Ver.01.38.00 Shunji Ogawa  2026/11/22  公式Modelsの候補と復元前・各導入の原権限を接続
 * Ver.01.39.00 Shunji Ogawa  2026/11/22  公式ベンダー配布の完全IDを指定導入前の再照合へ結合
 * Ver.01.40.00 Shunji Ogawa  2026/11/22  元選択の共有補助サービスを候補の変更範囲へ投影
 * Ver.01.41.00 Shunji Ogawa  2026/11/23  自動起動型の検査済み共有作用を候補の変更範囲へ投影
 * Ver.01.42.00 Shunji Ogawa  2026/11/23  同梱INFへの委譲を同じ署名索引の元参照へ結ぶ
 * Ver.01.43.00 Shunji Ogawa  2026/11/23  検査済みイベント用DLLのコピーを候補の変更範囲に表示
 * Ver.01.44.00 Shunji Ogawa  2026/11/23  署名索引候補の単一起動変更範囲を同じ資格から表示
 * Ver.01.45.00 Shunji Ogawa  2026/11/23  同じ端末のWiX候補を閲覧専用で表示
 * Ver.01.46.00 Shunji Ogawa  2026/11/23  同じ候補行へ一意のWiX検査専用対象を結合
 * Ver.01.46.01 Shunji Ogawa  2026/11/23  規約を検査したWiX閉包を通常の導入監査から分離
 * Ver.01.47.00 Shunji Ogawa  2026/11/23  同じ機器とWiX取得の私有参照を再照合
 * Ver.01.48.00 Shunji Ogawa  2026/11/23  WiXの単一起動候補を元規約の確認待ちで発行
 * Ver.01.49.00 Shunji Ogawa  2026/11/23  同じ取得の元規約への同意を復元と指定導入へ接続
 * Ver.01.49.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * Ver.01.50.00 Shunji Ogawa  2026/11/27  付随INFの不在を確認した標準Display更新を通常候補へ接続
 * Ver.01.50.01 Shunji Ogawa  2026/11/27  非実行配布形式を取得後監査と導入前の再照合で維持
 * Ver.01.51.00 Shunji Ogawa  2026/11/28  全取得前参照に表示直前の個別期限を適用
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_candidate_binding.h"
#include "platform/client_min_build_scope.h"
#include <charconv>
#include "platform/signed_index_scan.h"
#include "platform/signed_index_wix_content.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/driver_store_provider.h"
#include "platform/signed_index_candidate_binding_internal.h"
#include "platform/official_file_verifier.h"
#include "core/candidate_audit.h"
#include "core/candidate_assessment.h"
#include "core/candidate_selection.h"
#include "core/official_preparation_operation.h"
#include "core/official_preparation_audit.h"
#include "core/provider_registry.h"
#include "core/pending_reference_version.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace drivercrate::signed_index_candidate_binding_detail {
namespace {
// 製品は全てWindows標準APIの固定表を使用します
const InstallerNativeCalls NATIVE_INSTALLER_CALLS{
	&CreateProcessW, &WaitForSingleObject, &GetExitCodeProcess, &CloseHandle, &GetSystemDirectoryW} ;
// 内部fixtureの単独所有scopeだけが同threadへ完全表を固定します
thread_local const ScopedInstallerFixture *activeInstaller{} ;
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
// 明示診断の同thread scopeでだけ有効な同期観測です
thread_local PublicationObserver publicationObserver{} ;
// Callback呼出し中だけ借用する観測所有者です
thread_local void				*publicationObserverState{} ;
#endif
}
//------------------------------------------------------------------------------
/**
 * @brief 試験用の同じWiX対象と表示行が保持した元照合数を返します
 * @param[in] session 同じスキャンと署名索引を保持する所有者です
 * @param[in] target 取得用の元対象です
 * @param[in] candidate 同スキャンの閲覧専用行です
 * @return 保存した照合数です。完全一致がなければ0です
 * @note 参照、取得票、追加の導入許可は発行しません
 */
//------------------------------------------------------------------------------
std::size_t Access::wixReferenceRelationCountForFixture( const SignedIndexScanSession	&session,
														const OfficialPreparationTarget &target,
														const UpdateCandidate			&candidate)
{
	const auto &references = session.binding_.references_ ;	// 元取得との照合数だけを観測します
	const auto	found	   = std::ranges::find_if( references, [&]( const auto &reference) {
		  return reference.target == target && reference.candidate.identity == candidate.identity &&
				 reference.hint.deviceIdentity == candidate.deviceIdentity ;
	  }) ; // 元取得対象と元表示行を同じ機器で照合する条件です
	return found == references.end() ? 0U : found->relationIndices.size() ;
}
//------------------------------------------------------------------------------
/**
 * @brief 完全表を同threadへ固定します
 * @param[in] calls 欠損のないWindows ABI表です
 */
//------------------------------------------------------------------------------
ScopedInstallerFixture::ScopedInstallerFixture( InstallerNativeCalls calls) noexcept : calls_( calls)
{
	activeInstaller = this ;
}
//------------------------------------------------------------------------------
/**
 * @brief 当該scopeの低位表だけを解除します
 */
//------------------------------------------------------------------------------
ScopedInstallerFixture::~ScopedInstallerFixture() noexcept
{
	// 別scopeの表を解除しません
	if( activeInstaller == this) {
		activeInstaller = nullptr ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 同scopeで固定した全低位表を借用します
 * @return 本scopeが生存する間だけ有効な完全表です
 */
//------------------------------------------------------------------------------
const InstallerNativeCalls &ScopedInstallerFixture::calls() const noexcept
{
	return calls_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同threadの完全表または固定native表だけを返します
 * @return 同workerのscope終端まで有効な固定表です
 */
//------------------------------------------------------------------------------
[[nodiscard]] const InstallerNativeCalls &installerCalls() noexcept
{
	return activeInstaller ? activeInstaller->calls() : NATIVE_INSTALLER_CALLS ;
}
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
//------------------------------------------------------------------------------
/**
 * @brief 同所有targetの既検査入力だけをunitへ読取りcopyします
 * @param[in] session 同threadの原scan ownerです
 * @param[in] target 元target identityです
 * @return 唯一の正常所有入力、欠損/別target/不正ordinalでは空です
 * @note 原const object/claim/grant/token/observerを変更しません
 */
//------------------------------------------------------------------------------
std::optional<DriverArchiveInput> Access::inspectionInputForFixture(
	const SignedIndexScanSession &session, const std::wstring_view target)
{
	std::optional<DriverArchiveInput> input ;	// 認可ではない既入力copyだけです
	// 同所有record全体から元targetだけを探します
	for( const auto &record : session.binding_.records_) {
		// 別targetを同hashから推測しません
		if( record.task.target.identity != target) {
			continue ;
		}

		// 重複target又は元owner/ordinal/入力不足ならcopyを返しません
		if( input || !record.lookup || record.lookup != session.acquisitionLookup_ ||
		   record.context != session.context_ ||
		   record.referenceIndex >= session.binding_.references_.size() ||
		   session.binding_.references_[record.referenceIndex].target != record.task.target ||
		   record.input.scanSessionId != record.task.scanSessionId ||
		   record.input.byteCount == 0U || record.input.inspectionPath.empty() ||
		   record.input.sha256.empty() ||
		   (record.ownedBodyRecordIndex &&
			*record.ownedBodyRecordIndex >= session.binding_.records_.size())) {
			return std::nullopt ;
		}

		input = record.input ;
	}

	return input ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同threadだけの同期非機密観測を登録または解除します
 * @param[in] observer 解除時はnullです。元処理の結果を変更できません
 * @param[in,out] state 同期呼出し中だけ借用する観測所有者です
 */
//------------------------------------------------------------------------------
void Access::observePublication( const PublicationObserver observer, void *const state) noexcept
{
	publicationObserver		 = observer ;
	publicationObserverState = state ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同byte候補の発行条件だけを同期観測し、元結果へ書込みません
 * @param[in] stage 内容評価前1、READY検証前3です
 * @param[in] ordinal 同recordの元INF順序です
 * @param[in] session 元scanです
 * @param[in] candidate 同bindingの候補です
 * @param[in] inf 同byteの内容検査です
 * @param[in] evidence 同取得の正証拠です
 * @param[in] origin 元由来のfindingです
 * @param[in] error Windows観測の元HRESULTです
 * @param[in] rank Windows観測の元rankです
 * @param[in] needs 同実計画の検証済みNeeds辺数です
 * @param[in] members 同実計画の追加INF数です
 */
//------------------------------------------------------------------------------
void observePublication( const unsigned stage, const std::size_t ordinal,
						const ScanSessionId session, const UpdateCandidate &candidate,
						const CommonInfInspection &inf, const std::uint64_t evidence,
						const CandidateAssessmentFinding &origin, const NativeError error,
						const std::optional<std::uint32_t> rank, const std::size_t needs,
						const std::size_t members) noexcept
{
	// 明示観測がない通常処理では追加評価やcallbackを実行しません
	if( publicationObserver == nullptr) {
		return ;
	}

	PublicationDiagnostic diagnostic ;	// 原文字列を含まない数値snapshotです
	diagnostic.stage			  = stage ;
	diagnostic.infOrdinal		  = ordinal ;
	diagnostic.candidateCurrent	  = candidate.current ;
	diagnostic.verifiedNeedsEdges = needs ;
	diagnostic.additionalMembers  = members ;
	diagnostic.contentContextValid =
		inf.scanSessionId == session && inf.state == CommonInfInspectionState::VERIFIED &&
		inf.error == 0U && inf.workspace && inf.closure.packages.size() == 1U && evidence != 0U &&
		!candidate.packageIdentity.empty() ;
	diagnostic.originValid =
		isCandidateAssessmentFindingValid( CandidateAssessmentAxis::ORIGIN, origin) ;
	diagnostic.observationValid = error == 0U || !rank ;
	// 単一の元INFがある場合だけmetadataの完全一致を観測します
	if( inf.closure.packages.size() == 1U) {
		diagnostic.providerMatches =
			candidate.provider == inf.closure.packages.front().providerName ;
		diagnostic.versionMatches = candidate.version == inf.closure.packages.front().driverVersion ;
	}

	// 未構築の八軸をREADYや条件なしへ補完しません
	if( candidate.assessment) {
		diagnostic.assessmentReady = isCandidateAssessmentReady( *candidate.assessment) ;
		// 各元必要役割を件数へ投影し、証拠や名称を出力しません
		for( const auto &requirement : candidate.assessment->explicitRequirements) {
			diagnostic.baseRequirements +=
				requirement.role == CandidateComponentRole::BASE_DRIVER ? 1U : 0U ;
			diagnostic.extensionRequirements +=
				requirement.role == CandidateComponentRole::EXTENSION_INF ? 1U : 0U ;
			diagnostic.componentRequirements +=
				requirement.role == CandidateComponentRole::COMPONENT ? 1U : 0U ;
		}
	}

	publicationObserver( diagnostic, publicationObserverState) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 完全なlaunch表だけを同worker threadへ結合します
 * @param[in] calls 全五関数のWindows ABI fixtureです
 * @return 欠損または同threadの重複scopeでは空、それ以外は単独所有scopeです
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedInstallerFixture> Access::createInstaller( InstallerNativeCalls calls)
{
	// 全低位表の欠損とscopeの重複を拒否し、部分native fallbackを設けません
	if( activeInstaller || !calls.createProcess || !calls.waitProcess || !calls.exitCode ||
	   !calls.closeHandle || !calls.systemDirectory) {
		return nullptr ;
	}

	return std::unique_ptr<ScopedInstallerFixture>( new ScopedInstallerFixture( calls)) ;
}
#endif
} // namespace drivercrate::signed_index_candidate_binding_detail

namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
/**
 * @brief 原digestとnative小文字SHA-256の完全一致だけを検査します
 * @param[in] digest 認証recordの原SHA-256です
 * @param[in] text 同owned byteから計算した小文字hexです
 * @return 全64桁一致の場合だけtrueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesDigest( const IndexManifestSha256 &digest,
								 const std::wstring_view	text) noexcept
{
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// byte表現だけの固定表です
	// 部分hashや別表記を補完しません
	if( text.size() != digest.size() * 2U) {
		return false ;
	}

	// 同じ元digestの全byteを比較します
	for( std::size_t index = 0U; index < digest.size(); ++index) {
		// 上位/下位四bitの原表現を一致させます
		if( text[index * 2U] != HEX[digest[index] >> 4U] ||
		   text[index * 2U + 1U] != HEX[digest[index] & 15U]) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開ASCIIとnativeの元文字列を実path化せず比較します
 * @param[in] published 認証recordの原公開値です
 * @param[in] actual 同HINFまたは同owned inventoryの原値です
 * @param[in] member trueは公開slashとnative backslashの区切りだけを対応させます
 * @return memberは原case一致、他はWindows ordinalのcase非依存一致だけtrueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesPublishedText( const std::string_view	published,
										const std::wstring_view actual, const bool member = false)
{
	// Class/Models/PnPはWindowsが同一と扱うcase差だけを許し、原公開値は保持します
	if( !member) {
		const std::wstring value{published.begin(),
								 // Codecが検査済みの有限ASCIIです
								 published.end()} ;
		return CompareStringOrdinal( value.data(), static_cast<int>( value.size()), actual.data(),
									static_cast<int>( actual.size()), TRUE) == CSTR_EQUAL ;
	}

	return published.size() == actual.size() &&
		   std::ranges::equal(
			   published, actual, [member]( const unsigned char expected, const wchar_t observed) {
				   return expected < 0x80U && static_cast<wchar_t>( expected) ==
												  (member && observed == L'\\' ? L'/' : observed) ;
			   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有限ASCIIの大文字小文字だけを既存Windows identity比較へ揃えます
 * @param[in] left 元codecが検査した文字列です
 * @param[in] right 比較対象の原文字列です
 * @return 同じ文字列の場合trueです。値を変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameChoiceText( const std::string_view left,
								  const std::string_view right) noexcept
{
	const auto canonical = []( const unsigned char value) {
		return value >= 'A' && value <= 'Z' ? value + ('a' - 'A') : value ;
	} ; // Windows identityのcaseだけを揃え、member区切りは補完しません
	return std::ranges::equal( left, right, [&]( const auto a, const auto b) {
		return canonical( static_cast<unsigned char>( a)) == canonical( static_cast<unsigned char>( b)) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 曖昧な独自suffixを受理せず、標準x64 OS装飾のbaseだけを借用します
 * @param[in] section 元Models sectionです
 * @return NTamd64と省略なしmajor/minor・最大五つの数値OS fieldだけならbase、それ以外は空です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::string_view> modelChoiceBase(
	const std::string_view section) noexcept
{
	const auto marker = section.find( '.') ;	// Models baseの後だけを標準装飾として読みます
	// 空base・別architecture・途中一致は未知装飾として別参照へ残します
	if( marker == std::string_view::npos || marker == 0U || section.size() < marker + 8U ||
	   !sameChoiceText( section.substr( marker, 8U), ".NTamd64")) {
		return std::nullopt ;
	}

	auto suffix = section.substr( marker + 8U) ;	// 最大五つのTargetOSVersion fieldです
	// 装飾なしの標準NTamd64もbaseの借用だけを許可します
	if( suffix.empty()) {
		return section.substr( 0U, marker) ;
	}

	// TargetOSVersion以外の独自suffixをOS条件へ読み替えません
	if( suffix.front() != '.') {
		return std::nullopt ;
	}

	suffix.remove_prefix( 1U) ;
	// major/minor/product/suite/buildの最大五fieldだけを有限に読みます
	for( unsigned field = 0U; field < 5U; ++field) {
		const auto dot	= suffix.find( '.') ;		// 一つの元数値fieldの境界です
		const auto part = suffix.substr( 0U, dot) ;	// 空のproduct/suiteは標準省略だけ許可します
		// 省略したmajor/minorを任意のWindows版へ補完しません
		if( part.empty() && field < 2U) {
			return std::nullopt ;
		}

		// 省略可能なproduct/suite以外の原数値をuint32境界まで確認します
		if( !part.empty()) {
			std::uint32_t value{} ;	// uint32 overflowや任意suffixを拒否するための読取り値です
			const auto	  parsed =
				std::from_chars( part.data(), part.data() + part.size(),
								value) ;	// 数値全体の消費とoverflowを保持する読取り診断です
			// 部分数値・suffix・整数overflowを既知OS装飾として受理しません
			if( parsed.ec != std::errc{} || parsed.ptr != part.data() + part.size()) {
				return std::nullopt ;
			}
		}

		// 最終fieldまで成立した標準装飾だけからbaseを返します
		if( dot == std::string_view::npos) {
			return field >= 1U && !part.empty() ? std::optional{section.substr( 0U, marker)}
												: std::nullopt ;
		}

		suffix.remove_prefix( dot + 1U) ;
	}

	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元認証recordの完全identityを同owned INF/現HINFの観測へ照合します
 * @param[in] original 原lookupのrelationIndexから戻った未変更recordです
 * @param[in] inspection 同取得のouter原hash/sizeです
 * @param[in] hint 同private sealが原recordへ結んだ実outer identityです
 * @param[in] inf 同workspace/closureが所有する元INFです
 * @param[in] actual 同元HINFの原hash/Class/現在Modelsと公開ID全集合です
 * @return 全tuple一致の場合だけtrueです。rankやtokenは発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesPublishedInf( const IndexDistributionRecord	   &original,
									   const CommonDriverPackageInspection &inspection,
									   const IndexedDriverArchiveHint	   &hint,
									   const CommonInfInspection		   &inf,
									   const OfficialInfPublishedIdentity  &actual)
{
	const auto &identity = original.publishedIdentityEvidence ;	// 元recordだけの申告です
	const auto &package	 = original.packageEvidence ;			// 別recordのouter根拠を借りません
	// 公開identity不足や別member/原byteをrank成功で補完しません
	if( identity.state != IndexEvidenceState::PUBLISHED ||
	   identity.kind != IndexIdentityEvidenceKind::INF || !identity.evidenceSha256 ||
	   hint.archiveSha256 != inspection.archiveSha256 ||
	   hint.archiveBytes != inspection.archiveBytes ||
	   (package.size.value && *package.size.value != inspection.archiveBytes) ||
	   ((!package.size.value ||
		 (!package.publishedHash.sha256 && !package.calculatedHash.sha256)) &&
		!matchesDigest( original.recordSha256, hint.recordSha256)) ||
	   (package.publishedHash.sha256 &&
		!matchesDigest( *package.publishedHash.sha256, inspection.archiveSha256)) ||
	   (package.calculatedHash.sha256 &&
		!matchesDigest( *package.calculatedHash.sha256, inspection.archiveSha256)) ||
	   !matchesPublishedText( identity.nestedArchiveIdentity, inf.nestedArchivePath, true) ||
	   !matchesPublishedText( identity.infIdentity, inf.infRelativePath, true) ||
	   !matchesDigest( *identity.evidenceSha256, actual.infSha256) ||
	   !matchesPublishedText( identity.classGuid, actual.classGuid)) {
		return false ;
	}

	const auto model = std::ranges::find_if( actual.models, [&]( const auto &value) {
		return matchesPublishedText( identity.modelSection, value.modelSection) ;
	}) ; // 同現OS選択の原節だけです
	// 節欠損やIDの部分集合を同identityへ丸めません
	if( model == actual.models.end() ||
	   std::ranges::count_if( actual.models,
							 [&]( const auto &value) {
								 return matchesPublishedText( identity.modelSection,
															 value.modelSection) ;
							 }) != 1 ||
	   identity.pnpIds.size() != model->hardwareIds.size() + model->compatibleIds.size()) {
		return false ;
	}

	// 順序だけを適合条件にせず、種別付き原ID全集合を完全一致させます
	return std::ranges::all_of( identity.pnpIds, [&]( const auto &id) {
		const auto &ids =
			id.kind == IndexPnpIdKind::HARDWARE ? model->hardwareIds : model->compatibleIds ;
		return std::ranges::count_if( ids, [&]( const auto &value) {
				   return matchesPublishedText( id.value, value) ;
			   }) == 1 ;
	}) ;
}

/** @brief 起動前から終端まで取得済みfileを書換え・削除から固定するRAIIです */
class InstallerReadFile final {
public:
	/**
	 * @brief 所有fileの複製を禁止します
	 * @param[in] other 借用元です。本constructorは呼出し禁止です
	 */
	InstallerReadFile( const InstallerReadFile &other) = delete ;
	/**
	 * @brief 所有fileの代入を禁止します
	 * @param[in] other 借用元です。本演算子は呼出し禁止です
	 */
	InstallerReadFile &operator=( const InstallerReadFile &other) = delete ;
	/**
	 * @brief 元workspaceの実pathだけを読取り共有で開きます
	 * @param[in] path 私有元取得の完全pathです
	 */
	explicit InstallerReadFile( const std::wstring &path) noexcept
		: file_( CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL, nullptr))
	{
	}
	/**
	 * @brief 同scopeが開いたfileだけを全return・例外経路で閉じます
	 */
	~InstallerReadFile() noexcept
	{
		// File生成失敗を所有handleとして閉じません
		if( file_ != INVALID_HANDLE_VALUE) {
			CloseHandle( file_) ;
		}
	}
	/**
	 * @brief Fileを所有できたか確認します
	 * @return 開けた場合trueです。失敗直後のGetLastErrorは呼出し側が保持します
	 */
	[[nodiscard]] bool valid() const noexcept
	{
		return file_ != INVALID_HANDLE_VALUE ;
	}

private:
	/// 書換え・削除共有を許さない実取得fileの単独所有handleです
	HANDLE file_{INVALID_HANDLE_VALUE} ;
} ;
/** @brief 指定した完全表のprocess/thread handleを同scopeで閉じるRAIIです */
class InstallerProcess final {
public:
	/**
	 * @brief 所有process/threadの複製を禁止します
	 * @param[in] other 借用元です。本constructorは呼出し禁止です
	 */
	InstallerProcess( const InstallerProcess &other) = delete ;
	/**
	 * @brief 所有process/threadの代入を禁止します
	 * @param[in] other 借用元です。本演算子は呼出し禁止です
	 */
	InstallerProcess &operator=( const InstallerProcess &other) = delete ;
	/**
	 * @brief 完全表と所有handleを借用・所有します
	 * @param[in] calls Scope終端まで生存する完全表です
	 * @param[in] handles 起動APIが返した二handleです
	 */
	InstallerProcess( const signed_index_candidate_binding_detail::InstallerNativeCalls &calls,
					 PROCESS_INFORMATION handles) noexcept
		: calls_( calls), handles_( handles)
	{
	}
	/**
	 * @brief 起動APIが返した二handleだけを閉じます
	 */
	~InstallerProcess() noexcept
	{
		// Process生成の二handleを同じ表へ返します
		if( handles_.hThread) {
			static_cast<void>( calls_.closeHandle( handles_.hThread)) ;
		}

		// Processの終端または取得失敗後に所有handleを解放します
		if( handles_.hProcess) {
			static_cast<void>( calls_.closeHandle( handles_.hProcess)) ;
		}
	}

private:
	/// 起動に使用した同threadの完全表です
	const signed_index_candidate_binding_detail::InstallerNativeCalls &calls_ ;
	/// 外へ流出させない所有process/thread handleです
	PROCESS_INFORMATION												   handles_{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 検証済み公式EXEまたは固定Windows MSI UIだけへ明示的に引継ぎます
 * @param[in] path 元private workspaceの完全pathです
 * @param[in] msi 元署名recordのMSI形式だけでtrueです
 * @param[out] exitCode 原processの終端codeです。起動失敗時は空です
 * @param[out] reboot 終端codeが明示する再起動だけを保持します
 * @return Windows APIまたはinstaller原終了codeのHRESULTです。導入成功ではありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError launchOfficialInstaller( const std::filesystem::path &path, const bool msi,
												  std::optional<std::uint32_t> &exitCode,
												  bool						   &reboot)
{
	exitCode.reset() ;
	reboot			  = false ;
	const auto &calls = signed_index_candidate_binding_detail::installerCalls() ;	// 全表です
	std::vector<wchar_t> system(
		32768U) ;	// Windows x64標準起動元を同じ有限容量・ゼロ初期値で所有します
	// 固定Windows標準directoryの実受信長です。切捨てを拒否します
	const auto length = calls.systemDirectory( system.data(), static_cast<UINT>( system.size())) ;
	// Windows標準directoryの欠損や切捨てを任意pathで補完しません
	if( length == 0U || length >= system.size()) {
		return static_cast<NativeError>(
			HRESULT_FROM_WIN32( length == 0U ? GetLastError() : ERROR_INSUFFICIENT_BUFFER)) ;
	}

	const auto file = path.native() ;	// 元保護workspaceのopaque pathです
	// Command文字列の引用を変えるpathを拒否し、任意flagsを受けません
	if( file.empty() || file.find( L'"') != std::wstring::npos || file.size() > 30000U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 元形式から固定する完全application pathです。検索pathを使用しません
	const auto application =
		msi ? (std::filesystem::path( system.data()) / L"msiexec.exe").native() : file ;
	// 元保護pathだけを引用した非silent commandです。任意flagsを受けません
	std::wstring command = L"\"" + application + L"\"" + (msi ? L" /i \"" + file + L"\"" : L"") ;
	// 元scopeだけで使用する有限な検査値です。未知を成功へ補完しません
	STARTUPINFOW startup{} ;
	// 非silentの既定UIです
	startup.cb = sizeof( startup) ;
	PROCESS_INFORMATION handles{} ;	// 生成APIだけが所有handleを発行します
	// 検索path・handle継承・silent flagsを使用しない明示的引継ぎです
	if( !calls.createProcess( application.c_str(), command.data(), nullptr, nullptr, FALSE, 0U,
							nullptr, system.data(), &startup, &handles)) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	const InstallerProcess process{calls, handles} ;	// 終端後も同API表で閉じます
	// 受理済みinstallerを強制終了せず、原終端を待ちます
	if( calls.waitProcess( handles.hProcess, INFINITE) != WAIT_OBJECT_0) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	DWORD code{} ;	// 元processのcodeを推測せず取得します
	// 終了codeを取得できない引継ぎを成功へ補完しません
	if( !calls.exitCode( handles.hProcess, &code) || code == STILL_ACTIVE) {
		return static_cast<NativeError>(
			HRESULT_FROM_WIN32( code == STILL_ACTIVE ? ERROR_BUSY : GetLastError())) ;
	}

	exitCode = code ;
	reboot	 = code == ERROR_SUCCESS_REBOOT_REQUIRED || code == ERROR_SUCCESS_REBOOT_INITIATED ;
	return code == ERROR_SUCCESS || reboot ? 0 : static_cast<NativeError>( HRESULT_FROM_WIN32( code)) ;
}
//------------------------------------------------------------------------------
/**
 * @brief Guard通過済み明示4要素versionをaction分類だけへ使用します
 * @param[in] value Binderが保持した明示version
 * @return 正規4要素ならpacked値、それ以外は空です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> numericVersion( std::wstring_view value) noexcept
{
	return parseFourPartDriverVersion( value) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 取得済み成功を保持した全選択拒否結果を作ります
 * @param[in] identities 元選択順
 * @param[in] error 元拒否HRESULT
 * @return 個別download成功とinstall失敗の結果
 */
//------------------------------------------------------------------------------
[[nodiscard]] InstallResult rejectedInstall( std::span<const std::wstring> identities,
											NativeError					  error)
{
	InstallResult result ;	// 全selectionへ同じ事前拒否を保持します
	result.downloadOutcome = OutcomeCode::SUCCESS ;
	result.installOutcome  = OutcomeCode::FAILURE ;
	result.installError	   = error ;
	// 同じ元選択順を保持し、拒否から未選択driverを追加しません
	for( const auto &identity : identities) {
		result.updates.push_back( {.identity		   = identity,
								  .downloadOutcome = OutcomeCode::SUCCESS,
								  .installOutcome  = OutcomeCode::FAILURE,
								  .installError	   = error}) ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 発行したINFトークンの候補情報と版区分を元表示行へ結びます
 * @param[in] reference 当該端末の同じ取得前表示行です
 * @param[in] binding 実選択を確認した元Driver Storeトークンです
 * @param[in] acquisitionId 同じ保護取得結果の識別子です
 * @param[in] infOrdinal 同じ保持結果内の元INF位置です
 * @param[in] referenceIndex 同じ私有参照の位置です
 * @param[in] terms 同じ取得に適用した規約の状態です
 * @return 後段の評価を結合する表示候補です
 * @throws std::logic_error Windowsが返した版から区分を確定できなかった場合です
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateCandidate makeBoundInfCandidate( const UpdateCandidate			&reference,
													const OfficialInfInstallBinding &binding,
													const std::uint64_t				 acquisitionId,
													const std::size_t				 infOrdinal,
													const std::size_t				 referenceIndex,
													const OfficialPreparationTerms	 terms)
{
	// 実選択前の表示値は同じ端末の行から受け継ぎます
	UpdateCandidate candidate = reference ;
	candidate.identity		  = L"index-candidate-" + std::to_wstring( acquisitionId) + L"-" +
						 std::to_wstring( infOrdinal) + L"-" + std::to_wstring( referenceIndex) ;
	candidate.packageIdentity = L"index-package-" + std::to_wstring( acquisitionId) ;
	candidate.title			  = L"署名索引（収集者確認）" ;
	candidate.provider		  = binding.candidateProvider ;
	candidate.version		  = binding.candidateVersion ;
	candidate.driverDate	  = binding.candidateDate ;
	// 候補との区分を決めるWindowsの現在バージョンです
	const auto currentVersion = numericVersion( binding.currentVersion) ;
	// Windowsが選んだ候補の比較用バージョンです
	const auto candidateVersion = numericVersion( binding.candidateVersion) ;
	// 現在ドライバーなしの場合だけ現在バージョンの欠落を許可します
	if( !candidateVersion || (!currentVersion && binding.rankAudit.currentState !=
													OfficialDriverRankCurrentState::NO_DRIVER)) {
		throw std::logic_error( "index binding version mismatch") ;
	}

	candidate.action = binding.rankAudit.currentState == OfficialDriverRankCurrentState::NO_DRIVER
						   ? DriverAction::INITIAL_INSTALL
					   : *candidateVersion > *currentVersion  ? DriverAction::UPDATE
					   : *candidateVersion == *currentVersion ? DriverAction::REINSTALL
															  : DriverAction::DOWNGRADE ;
	candidate.installable	   = true ;
	candidate.allContentCached = true ;
	candidate.eulaAccepted	   = terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT ||
							 terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
	candidate.audit = {CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
					   CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
					   CandidateInstallReadiness::READY} ;
	return candidate ;
}

/** @brief 未commitの新tokenを例外経路でも当該issuerへ戻すguardです */
class NewTokenGuard final {
public:
	/**
	 * @brief 発行済み一tokenを同期scopeへ固定します
	 * @param[in,out] store 元issuer
	 * @param[in] session 元scan
	 * @param[in] token 新token
	 * @param[in] installer Installer専用guardならtrueです。標準INFとは別issuer集合です
	 */
	NewTokenGuard( DriverStoreProvider &store, ScanSessionId session, std::uint64_t token,
				  bool installer = false) noexcept
		: store_( store), session_( session), token_( token), installer_( installer)
	{
	}
	/**
	 * @brief Pending所有に移していない新tokenだけを破棄します
	 */
	~NewTokenGuard() noexcept
	{
		// 別Providerのtokenへ触れず、この同期scopeで作った一tokenだけを戻します
		if( token_ != 0U) {
			// 別形式のbinding集合を同じtoken値で破棄しません
			if( installer_) {
				static_cast<void>( store_.discardOfficialInstallerDeviceBinding( session_, token_)) ;
			} else {
				static_cast<void>( store_.discardOfficialInfInstallBinding( session_, token_)) ;
			}
		}
	}
	/**
	 * @brief 新tokenの所有をpending transactionへ渡します
	 */
	void release() noexcept
	{
		token_ = 0U ;
	}

private:
	/// 元workerのbinding issuer
	DriverStoreProvider &store_ ;
	/// 元scan session
	ScanSessionId		 session_ ;
	/// Pendingへ移す前だけ存在する新token
	std::uint64_t		 token_ ;
	/// 元issuerのinstaller専用集合でだけtrueです
	bool				 installer_{} ;
} ;
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 原record申告を通常候補と同じINF完全tuple比較へ渡します。許可を発行しません
 * @param[in] original 共通codecが検査した元record値です。認証の有無は表しません
 * @param[in] inspection 同元outerを所有する通常内容検査結果です
 * @param[in] hint 同元outerのsize/hashとrecord参照です
 * @param[in] inf 同保護workspaceの一INFです
 * @param[in] actual 同元HINFから再読取りした公開identityです
 * @return 元outer/INF/Models/Class/種別付き公開ID全集合が一致する場合trueです
 * @note Windows適合、rank、候補session、tokenを生成しません
 */
//------------------------------------------------------------------------------
bool matchesIndexPublishedInf( const IndexDistributionRecord		  &original,
							  const CommonDriverPackageInspection &inspection,
							  const IndexedDriverArchiveHint &hint, const CommonInfInspection &inf,
							  const OfficialInfPublishedIdentity &actual)
{
	return matchesPublishedInf( original, inspection, hint, inf, actual) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新candidate・tokenを一括rollbackします
 * @param[in,out] store 元token issuer
 */
//------------------------------------------------------------------------------
void SignedIndexCandidateBindingSession::rollback( DriverStoreProvider &store) noexcept
{
	// 全既存routeのcopyより後の新tokenだけを破棄します
	for( std::size_t index = routes_.size(); index < pendingRoutes_.size(); ++index) {
		const auto &route = pendingRoutes_[index] ;	// 今回だけの新binding
		static_cast<void>( store.discardOfficialInfInstallBinding(
			route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
			route.binding.token)) ;
		static_cast<void>( store.discardOfficialInstallerDeviceBinding(
			route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
			route.installerToken)) ;
	}

	pendingRoutes_.clear() ;
	pending_ = false ;
}
namespace {
//------------------------------------------------------------------------------
/**
 * @brief 既Models選択と表示比較で共有する完全INF証拠だけを照合します
 * @param[in] left 原recordです
 * @param[in] right 別原recordです
 * @return 同payload/policyとINF/全公表ID/versionが一致した場合trueです
 */
//------------------------------------------------------------------------------
bool sameIndexInfChoiceEvidence( const IndexDistributionRecord &left,
								const IndexDistributionRecord &right) noexcept
{
	const auto &a = left.publishedIdentityEvidence ;	// 個別に認証codecが読んだ原identityです
	const auto &b = right.publishedIdentityEvidence ;	// 相互の不足fieldを補完しません
	return left.inspectionStage == IndexInspectionStage::CONTENT_INSPECTED &&
		   right.inspectionStage == IndexInspectionStage::CONTENT_INSPECTED &&
		   left.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   right.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   left.version.value && !left.version.value->empty() &&
		   left.version.value == right.version.value &&
		   matchesSharedIndexPayloadEvidence( left, right) &&
		   a.state == IndexEvidenceState::PUBLISHED && b.state == IndexEvidenceState::PUBLISHED &&
		   a.kind == IndexIdentityEvidenceKind::INF && b.kind == IndexIdentityEvidenceKind::INF &&
		   a.evidenceSha256 && a.evidenceSha256 == b.evidenceSha256 &&
		   a.evidenceUrl == b.evidenceUrl && !a.infIdentity.empty() &&
		   a.infIdentity == b.infIdentity && a.nestedArchiveIdentity == b.nestedArchiveIdentity &&
		   !a.classGuid.empty() && sameChoiceText( a.classGuid, b.classGuid) && !a.pnpIds.empty() &&
		   std::ranges::is_permutation(
			   a.pnpIds, b.pnpIds, []( const auto &first, const auto &second) {
				   return first.kind == second.kind && sameChoiceText( first.value, second.value) ;
			   }) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じINF/Modelsの原内容とpolicyだけを比較する表示専用判定です
 * @param[in] left 同じ署名snapshotから参照する原recordです
 * @param[in] right 同snapshotの別原recordです
 * @return 完全payload/policy・INF証拠・同Models/公表ID・version/日付一致時だけtrueです
 * @note 原Reference/record/routingを統合せず、取得・導入権限を発行しません
 */
//------------------------------------------------------------------------------
bool areIdenticalIndexDisplayChoices( const IndexDistributionRecord &left,
									 const IndexDistributionRecord &right) noexcept
{
	return sameIndexInfChoiceEvidence( left, right) &&
		   !left.publishedIdentityEvidence.modelSection.empty() &&
		   sameChoiceText( left.publishedIdentityEvidence.modelSection,
						  right.publishedIdentityEvidence.modelSection) &&
		   left.publishedDate.value == right.publishedDate.value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同一INFの異なる標準x64 OS装飾を持つ代替recordの厳密値比較です
 * @param[in] left 個別codec検査済みの元recordです
 * @param[in] right 同じ署名snapshotから参照する別の元recordです
 * @return 元payload/policy/期限・INF/hash/Class/版/公表ID全集合とModels base一致時だけtrueです
 * @note 認証/通信/適合/導入権限を発行しません。私有Referenceが元relation集合を別に所有します
 */
//------------------------------------------------------------------------------
bool areEquivalentIndexModelChoices( const IndexDistributionRecord &left,
									const IndexDistributionRecord &right) noexcept
{
	const auto &a		  = left.publishedIdentityEvidence ;	// 原Modelsだけを比較します
	const auto &b		  = right.publishedIdentityEvidence ;	// 同内容でも同Modelsは別参照を保ちます
	const auto	firstBase = modelChoiceBase( a.modelSection) ;	// 既標準装飾の解釈です
	const auto	secondBase = modelChoiceBase( b.modelSection) ;	// 不明装飾を補完しません
	return sameIndexInfChoiceEvidence( left, right) && firstBase && secondBase &&
		   sameChoiceText( *firstBase, *secondBase) &&
		   !sameChoiceText( a.modelSection, b.modelSection) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全検証後だけ新routeをnoexcept swapします
 */
//------------------------------------------------------------------------------
void SignedIndexCandidateBindingSession::commit() noexcept
{
	// 全reportとComposite mapの検証後だけ、allocationなしでroutingを公開します
	if( pending_) {
		routes_.swap( pendingRoutes_) ;
		pendingRoutes_.clear() ;
		pending_ = false ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 全route・record・参照行を終端失効します
 * @param[in,out] store 元issuer。未結合の場合nullptrです
 */
//------------------------------------------------------------------------------
void SignedIndexCandidateBindingSession::invalidate( DriverStoreProvider *const store) noexcept
{
	// Issuerが生存している間に新tokenとcommit済みtokenを全て失効します
	if( store != nullptr) {
		rollback( *store) ;
		// 確定済み全routeの固有tokenを終端で破棄します
		for( const auto &route : routes_) {
			static_cast<void>( store->discardOfficialInfInstallBinding(
				route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
				route.binding.token)) ;
			static_cast<void>( store->discardOfficialInstallerDeviceBinding(
				route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
				route.installerToken)) ;
		}
	}

	pendingRoutes_.clear() ;
	routes_.clear() ;
	pairs_.clear() ;
	records_.clear() ;
	references_.clear() ;
	pending_	   = false ;
	retainedBytes_ = 0U ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 署名索引の元INF情報を同じ端末の表示項目へ投影します
 * @param[in] original 署名索引で確認した元配布レコードです
 * @param[in] relationIndex 同じスキャンで一意な元の照合関係の位置です
 * @param[in] current 同じ端末の現在行です。表示属性だけを借ります
 * @return 実行権限を持たない取得前の参照行です
 * @throws std::bad_alloc 表示情報を所有する領域を確保できません
 * @note 版は同クラスの内容検査済み元INFだけから投影します
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateCandidate makeIndexReferenceCandidate( const IndexDistributionRecord &original,
														  const std::size_t		 relationIndex,
														  const UpdateCandidate &current)
{
	UpdateCandidate candidate ;	// 導入、実適用性、同意と取得targetを持たない取得前情報です
	candidate.deviceIdentity		= current.deviceIdentity ;
	candidate.manufacturer			= current.manufacturer ;
	candidate.model					= current.model ;
	candidate.driverClass			= current.driverClass ;
	candidate.deviceClassGuid		= current.deviceClassGuid ;
	candidate.discoveryBus			= current.discoveryBus ;
	candidate.identity				= L"index-reference-" + std::to_wstring( relationIndex) ;
	candidate.providerId			= SIGNED_INDEX_PROVIDER_ID ;
	candidate.discoveryBasis		= CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
	candidate.sourceName			= L"署名索引（収集者確認）" ;
	candidate.sourceLocation		= L"端末内で署名・byte・Windows適合を再検証" ;
	candidate.audit					= {.sourceOrigin = CandidateAuditGateState::PASSED} ;
	candidate.title					= L"署名索引（収集者確認・取得前）" ;
	candidate.detailDisplayIdentity = candidate.identity ;
	const auto &identity = original.publishedIdentityEvidence ;	// 元INF、Modelsとハッシュの申告です
	// 内容検査済みの同クラスINFだけから版を表示します
	if( original.inspectionStage == IndexInspectionStage::CONTENT_INSPECTED &&
	   identity.state == IndexEvidenceState::PUBLISHED &&
	   identity.kind == IndexIdentityEvidenceKind::INF && identity.evidenceSha256 &&
	   !identity.infIdentity.empty() && !identity.modelSection.empty() &&
	   matchesPublishedText( identity.classGuid, current.deviceClassGuid) &&
	   original.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
	   original.version.value) {
		candidate.version.assign( original.version.value->begin(), original.version.value->end()) ;
	}

	return candidate ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名レコードと端末へ発行した一意のWiX検査対象を選びます
 * @param[in] lookup 表示する元の不変lookupです
 * @param[in] adapter 同じ取得issuerです
 * @param[in] plan 同じスキャンの元取得計画です
 * @param[in] relation 表示する同じレコードと端末の元関係です
 * @param[in] nowUtc 元期限の照合に使う表示直前の信頼UTCです
 * @return 一意で有効な元取得参照の位置です。不明または曖昧なら値なしです
 * @note 呼出し中だけ位置を借用します。通信、規約同意、導入許可は発行しません
 */
//------------------------------------------------------------------------------
std::optional<std::size_t> SignedIndexCandidateBindingSession::findWixInspectionBinding(
	const std::shared_ptr<const SignedIndexRecordLookup> &lookup,
	const SignedIndexAcquisitionAdapter &adapter, const OfficialPreparationPlan &plan,
	const IndexRecordRelation &relation, const std::chrono::sys_seconds nowUtc)
{
	// 元取得権限を持たない表示行はそのまま残し、取得targetだけを結合しません
	if( !lookup || adapter.lookup_ != lookup || adapter.context_ != relation.context ||
	   !adapter.acquisitionOpen_ || !*adapter.acquisitionOpen_ || !relation.deviceIdentity ||
	   plan.scanSessionId != relation.context.scanSessionId || plan.planId == 0U) {
		return std::nullopt ;
	}

	const auto &relations			= lookup->relations() ;	// 同じ元スキャンの端末照合を借用します
	const auto	matchesRecordDevice = [&]( const auto &binding) {
		 // 元位置と同じ端末のopaque IDで照合し、異なる公開IDの代表位置を許容します
		 if( binding.relationIndex >= relations.size()) {
			 return false ;
		 }

		 const auto &bound = relations[binding.relationIndex] ;	// 取得issuerが選んだ元代表です
		 return bound.context == relation.context && bound.recordIndex == relation.recordIndex &&
				bound.deviceIdentity == relation.deviceIdentity ;
	 } ; // 元関係は同期呼出し中だけ借用します
	const auto binding =
		// 元取得対象です
		std::ranges::find_if( adapter.bindings_, matchesRecordDevice) ;
	// 一意な未消費の同用途対象だけを表示して、別承認や曖昧な結合を避けます
	if( binding == adapter.bindings_.end() || binding->claimedTask ||
	   binding->limits != plan.limits || binding->target.providerId != SIGNED_INDEX_PROVIDER_ID ||
	   binding->target.terms != OfficialPreparationTerms::INSPECTION_ONLY ||
	   binding->target.identity.empty() ||
	   std::find_if( std::next( binding), adapter.bindings_.end(), matchesRecordDevice) !=
		   adapter.bindings_.end()) {
		return std::nullopt ;
	}

	const auto target =
		std::ranges::find( plan.targets, binding->target.identity,
						  &OfficialPreparationTarget::identity) ;	// 現行計画の元対象です
	// 元対象の一部、同じIDの重複、または失効した元関係から操作を表示しません
	if( target == plan.targets.end() || *target != binding->target ||
	   std::ranges::count( plan.targets, target->identity, &OfficialPreparationTarget::identity) !=
		   1) {
		return std::nullopt ;
	}

	std::string reason ;	// 元関係の再照合診断はworker内だけで使います
	return adapter.validateBinding( *binding, relation.context, nowUtc, reason,
								   SignedIndexAcquisitionAdapter::RecordValidation::PREPARATION) ==
				   0U
			   ? std::optional{static_cast<std::size_t>( binding - adapter.bindings_.begin())}
			   : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 照合済みの取得前参照を同じ端末の現在行へ結合します
 * @param[in] lookup 同じ端末用レコード位置を保持する元認証lookup
 * @param[in] adapter 同原lookupの全元関係を保持する取得issuer
 * @param[in] plan 同scanの未変更取得計画
 * @param[in] candidates 同scanの既表示現在行
 * @param[in] hints 同deviceの検証済みopaque hint
 * @param[in] nowUtc 表示直前の信頼UTCです。未確認の場合は索引の参照を発行しません
 * @return 元recordと同deviceへ結合した非導入参照行
 * @note WiX候補は元計画と同じ端末への私有参照を保持し、検査専用の表示を返します
 */
//------------------------------------------------------------------------------
std::vector<UpdateCandidate> SignedIndexCandidateBindingSession::makeReferences(
	const std::shared_ptr<const SignedIndexRecordLookup> &lookup,
	const SignedIndexAcquisitionAdapter &adapter, const OfficialPreparationPlan &plan,
	const std::span<const UpdateCandidate>			   candidates,
	const std::span<const OfficialDiscoveryDeviceHint> hints,
	const std::optional<std::chrono::sys_seconds>	   nowUtc)
{
	std::vector<Reference>		 pending ;	// 原子的に反映する元target一対一対応
	std::vector<UpdateCandidate> result ;	// 検証後だけ返す非導入行
	// 別planを既存参照へ再利用しません
	if( !lookup || !references_.empty() || plan.scanSessionId == 0U || plan.targets.size() > 256U ||
	   candidates.size() > 65536U) {
		throw std::logic_error( "index reference context mismatch") ;
	}

	const auto &snapshot = lookup->snapshot() ;			// 照合関係を発行した不変の署名索引です
	const auto	records	 = snapshot.consumerRecords() ;	// 同署名snapshotの端末用原集合です
	const auto	publishedAt =
		// 時計が署名済みの発行時刻より前に戻った場合も表示しません
		snapshot.schemaReceipt().assetBytes().manifest().data().publishedAtUtc ;
	// 時刻未確認や時計の巻き戻りから選択可能な参照を作りません
	if( !nowUtc || *nowUtc < publishedAt) {
		return result ;
	}

	std::set<std::pair<std::size_t, std::wstring_view>>
		displayedWix ;	// 元recordと端末の表示重複を防ぎます
	// 元の凍結関係から閲覧専用行と取得計画付きの参照を発行します
	for( std::size_t relationIndex = 0U; relationIndex < lookup->relations().size();
		++relationIndex) {
		const auto &relation = lookup->relations()[relationIndex] ;	// 同lookupの原関係
		const auto &original = records[relation.recordIndex] ;		// 同じ関係が参照する原証拠です
		// 照合や取得計画の生成後に期限を迎えた行だけを表示から外します
		if( *nowUtc >= snapshot.consumerRecordRegion( relation.recordIndex).expiresAtUtc) {
			continue ;
		}

		// WiXの表示行は取得issuerの有無と独立し、同じ端末の照合証拠を使います
		if( original.wixContentEvidence) {
			// 同一端末の完全Hardware ID証拠を確認します
			if( relation.context.scanSessionId != plan.scanSessionId || !relation.deviceIdentity ||
			   !relation.deviceProof ||
			   (relation.state != IndexRecordMatchState::MATCHED &&
				relation.state != IndexRecordMatchState::VERIFIED_DEVICE)) {
				continue ;
			}

			const auto current = std::ranges::find_if( candidates, [&]( const auto &value) {
				return value.current && value.deviceIdentity == *relation.deviceIdentity ;
			}) ; // 同じ元スキャンの現在行だけに参照を付けます
			// 他クラスや欠けた現在行を補完せず、複数IDの照合は同じ端末の一行にまとめます
			if( current != candidates.end() &&
			   matchesPublishedText( original.publishedIdentityEvidence.classGuid,
									current->deviceClassGuid) &&
			   displayedWix.emplace( relation.recordIndex, current->deviceIdentity).second) {
				auto	   candidate	= makeIndexReferenceCandidate( original, relationIndex,
																	  *current) ;	// 同端末の非導入行です
				const auto bindingIndex = findWixInspectionBinding( lookup, adapter, plan, relation,
																   *nowUtc) ;	// 一意の元対象です
				// 元計画と完全一致している場合だけ検査専用の操作を表示します
				if( bindingIndex) {
					const auto &binding =
						adapter.bindings_[*bindingIndex] ;	// 同じrecordと機器の全照合関係です
					candidate.inspectionTargetIdentity = binding.target.identity ;
					const auto hint					   = std::ranges::find(
						   hints, current->deviceIdentity,
						   &OfficialDiscoveryDeviceHint::
							   deviceIdentity) ;	// 同じスキャンで検証した元機器hintです
					// 元機器が一意な場合だけ後続の再検査まで端末との結合を維持します
					if( hint != hints.end() &&
					   std::ranges::count( hints, current->deviceIdentity,
										  &OfficialDiscoveryDeviceHint::deviceIdentity) == 1) {
						pending.push_back( {binding.relationIndex, binding.relationIndices,
										   binding.target, candidate, *current, *hint}) ;
					}
				}

				result.push_back( std::move( candidate)) ;
			}

			continue ;
		}

		const auto binding = std::ranges::find_if( adapter.bindings_, [&]( const auto &value) {
			return std::ranges::find( value.relationIndices, relationIndex) !=
				   value.relationIndices.end() ;
		}) ; // 同issuerが原関係全体へ結合した取得binding
		// 未記述関係から表示参照や取得targetを生成しません
		if( binding == adapter.bindings_.end()) {
			continue ;
		}

		const auto &targetId = binding->target.identity ;	// URL/名称から作らない元opaque ID
		const auto	target =
			std::find_if( plan.targets.begin(), plan.targets.end(), [&]( const auto &value) {
				return value.providerId == SIGNED_INDEX_PROVIDER_ID && value.identity == targetId ;
			}) ; // describeの同targetだけ
		// 同planの対象へ結合できないrelationを候補へ戻しません
		if( target == plan.targets.end()) {
			continue ;
		}

		const bool eligibleRelation =
			relation.state == IndexRecordMatchState::MATCHED ||
			(relation.state == IndexRecordMatchState::VERIFIED_PARTIAL &&
			 relation.reason == IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL &&
			 relation.positiveProof) ||
			(relation.state == IndexRecordMatchState::VERIFIED_DEVICE &&
			 relation.reason == IndexRecordMatchReason::VERIFIED_DEVICE_PROJECTION &&
			 relation.deviceProof) ;	// Adapterが元tupleとleaseを検証した記述済み関係です
		// 記述済みの既知一deviceだけへ参照を作り、他node不足を導入可へ変えません
		if( relation.context.scanSessionId != plan.scanSessionId || !eligibleRelation ||
		   !relation.deviceIdentity ||
		   (relation.state != IndexRecordMatchState::VERIFIED_DEVICE &&
			(relation.relatedDevices.size() != 1U ||
			 relation.relatedDevices.front() != *relation.deviceIdentity))) {
			throw std::logic_error( "index target relation mismatch") ;
		}

		// ファームウェアの確認対象が元端末又は元条件から変わった場合は表示に出しません
		if( (target->firmwareCondition || binding->target.firmwareCondition) &&
		   (!target->firmwareCondition || *target != binding->target ||
			target->firmwareCondition->deviceIdentity != *relation.deviceIdentity)) {
			throw std::logic_error( "index firmware preparation relation mismatch") ;
		}

		// 同record/deviceへ当たる複数公開IDは一つの基本参照に集約し、原関係はlookupへ保持します
		if( std::ranges::any_of( pending, [&]( const auto &value) {
			   return value.target.identity == targetId &&
					  value.candidate.deviceIdentity == *relation.deviceIdentity &&
					  std::ranges::any_of( value.relationIndices, [&]( const auto position) {
						  return lookup->relations()[position].recordIndex == relation.recordIndex ;
					  }) ;
		   })) {
			continue ;
		}

		const auto alternate = std::ranges::find_if( pending, [&]( const auto &value) {
			return value.target == *target &&
				   value.candidate.deviceIdentity == *relation.deviceIdentity &&
				   areEquivalentIndexModelChoices(
					   records[lookup->relations()[value.relationIndex].recordIndex],
					   records[relation.recordIndex]) &&
				   std::ranges::none_of( value.relationIndices, [&]( const auto position) {
					   return sameChoiceText(
						   records[lookup->relations()[position].recordIndex]
							   .publishedIdentityEvidence.modelSection,
						   records[relation.recordIndex].publishedIdentityEvidence.modelSection) ;
				   }) ;
		}) ; // 同INFの別Modelsだけを私有原位置の集合へまとめます
		// 表示参照は増やさず、元Models recordの位置だけを同じ私有集合へ保持します
		if( alternate != pending.end()) {
			alternate->relationIndices.push_back( relationIndex) ;
			continue ;
		}

		const auto current =
			std::find_if( candidates.begin(), candidates.end(), [&]( const auto &value) {
				return value.current && value.deviceIdentity == *relation.deviceIdentity ;
			}) ; // 同scanの元現在行
		const auto hint = std::find_if( hints.begin(), hints.end(), [&]( const auto &value) {
			return value.deviceIdentity == *relation.deviceIdentity ;
		}) ; // 同presentの検証済みhint
		// 未表示deviceやhint欠損から参照行を発行しません
		if( current == candidates.end() || hint == hints.end()) {
			continue ;
		}

		auto candidate =
			// 元の表示情報だけです
			makeIndexReferenceCandidate( original, relationIndex, *current) ;
		candidate.preparationTargetIdentity = target->identity ;
		const auto displayTwin				= std::ranges::find_if( pending, [&]( const auto &value) {
			 return value.target == *target &&
					value.candidate.deviceIdentity == candidate.deviceIdentity &&
					areIdenticalIndexDisplayChoices(
						records[lookup->relations()[value.relationIndex].recordIndex], original) ;
		 }) ; // 同payloadでも別INF/Modelsは共有しません
		// 原candidate identityやrelation集合は変更しません
		if( displayTwin != pending.end()) {
			candidate.detailDisplayIdentity = displayTwin->candidate.detailDisplayIdentity ;
		}

		pending.push_back( {relationIndex, {relationIndex}, *target, candidate, *current, *hint}) ;
		result.push_back( std::move( candidate)) ;
	}

	references_.swap( pending) ;
	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元署名の配布形式と消費済みgrantを共通検査へ結ぶ
 * @param[in] acquisition 元取得の確定結果
 * @param[in] grant 同じ元取得で消費した権限
 * @param[in] hint 封印から確認した元レコードと配布バイト
 * @param[in] format 元署名レコードが指定した配布形式
 * @param[out] input 成功時だけ共通検査入力。失敗時は空
 * @return 元配布の照合成立で0、拒否時は元HRESULT
 * @note 非実行形式の確定に実行ファイルの拡張子を使わない
 */
//------------------------------------------------------------------------------
NativeError SignedIndexCandidateBindingSession::bindDelegatedInput(
	const OfficialAcquisitionResult &acquisition, const RecordScopedDownloadGrant &grant,
	const IndexedDriverArchiveHint &hint, const IndexPayloadFormat format,
	DelegatedOfficialPackageInput &input) noexcept
{
	// 署名が指定した非実行解析の形式と元レコードの照合を初回・再読取りで揃える
	if( format == IndexPayloadFormat::PE_RESOURCE_CONTAINER ||
	   format == IndexPayloadFormat::SEVEN_ZIP_SFX) {
		return makeDelegatedOfficialPackageInput(
			acquisition, grant, hint,
			format == IndexPayloadFormat::PE_RESOURCE_CONTAINER
				? OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER
				: OfficialDriverArchiveFormat::SEVEN_ZIP_SFX,
			input) ;
	}

	return makeDelegatedOfficialPackageInput( acquisition, grant, input) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元task・grant・期限・封印・全参照と実byteを再照合します
 * @param[in] owner 同取得issuer/元workspace
 * @param[in] record 同所有record
 * @param[in] services Worker固定のUTC
 * @param[in] observeHost 取得時と同じホスト観測を行う場合trueです
 * @return 完全一致0、失効・期限・内容変化の元HRESULT
 * @note LOCAL claimを再消費しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexCandidateBindingSession::reverifyRecordBinding(
	const SignedIndexScanSession &owner, const PreparedRecord &record,
	const provider_worker_index_detail::Services &services, const bool observeHost) const
{
	// 原target全体の参照/ordinalを先に検証し、不正Bで正常Aのobserverを消費しません
	if( !record.lookup || record.lookup != owner.acquisitionLookup_ ||
	   record.context != owner.context_ || record.referenceIndex >= references_.size() ||
	   references_[record.referenceIndex].target != record.task.target) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto &relations = record.lookup->relations() ;					// 元同scan関係だけです
	const auto	originals = record.lookup->snapshot().consumerRecords() ;	// 元署名recordです
	const auto &primary = references_[record.referenceIndex] ;				// 同じ元取得が選んだ代表と全関係です
	const bool	wix		= record.task.target.terms ==
					 OfficialPreparationTerms::INSPECTION_ONLY ;	// 規約と閉包を持つ元形式です
	const SignedIndexAcquisitionAdapter::PreparedBinding
		*wixBinding{} ;	// この呼出しに限り元取得承認を借用します
	// WiXは他の保持形式と混ぜず、元承認の代表と全照合関係をそのまま確認します
	if( wix) {
		const auto &bindings = owner.adapter_.bindings_ ;	// 元公式ページと封印を発行した取得者です
		const auto	claimed	 = std::ranges::find_if( bindings, [&]( const auto &binding) {
			  return binding.claimedTask && *binding.claimedTask == record.task ;
		  }) ; // この元取得だけに結ぶ所有参照です
		// 元参照が増減した場合や内容検査が未成立の場合は後続の候補検査へ渡さない
		if( !record.wixInspection || record.ownedBodyRecordIndex || record.localInspection ||
		   record.installerHandoff || record.scopedInspection ||
		   record.inspection.state != IndexedDriverInspectionState::INSPECTION_COMPLETED ||
		   !record.inspection.inputBound || record.task.target.deviceCount != 1U ||
		   claimed == bindings.end() || claimed->relationIndex != primary.relationIndex ||
		   claimed->relationIndices != primary.relationIndices) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		wixBinding = &*claimed ;
	}

	std::set<std::wstring> devices ;	// 元承認の全device件数を確認します
	// 承認targetの全device参照を純粋に照合します
	for( const auto &reference : references_) {
		// 別targetへ同配布物の権限を広げません
		if( reference.target != record.task.target) {
			continue ;
		}

		// 代表不在/過大集合/別device参照をobserver前に拒否します
		if( (wix && &reference != &primary) || reference.relationIndices.empty() ||
		   reference.relationIndices.front() != reference.relationIndex ||
		   reference.relationIndices.size() > (wix ? relations.size() : originals.size()) ||
		   reference.hint.deviceIdentity != reference.candidate.deviceIdentity) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		std::set<std::size_t> ordinals ;	// 重複relationを完全一致と数えません
		// 選択した各relationを元tupleへ戻します
		for( const auto ordinal : reference.relationIndices) {
			// 範囲外と同ordinal重複を先に拒否します
			if( ordinal >= relations.size() || !ordinals.insert( ordinal).second) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}

			const auto &relation = relations[ordinal] ;	// 境界検証後の原relationです
			// 別scan/deviceや範囲外recordを原関係へ補完しません
			if( relation.recordIndex >= originals.size() || relation.context != record.context ||
			   !relation.deviceIdentity ||
			   *relation.deviceIdentity != reference.hint.deviceIdentity) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}

			const auto &original = originals[relation.recordIndex] ;	// 同ordinalの原recordです
			// 原ID/source/hashの差を位置一致だけで救済しません
			if( relation.recordId != original.recordId || relation.sourceId != original.sourceId ||
			   relation.recordSha256 != original.recordSha256) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}
		}

		devices.insert( reference.hint.deviceIdentity) ;
	}

	// 原承認の有限device件数に完全一致しない場合は止めます
	if( devices.empty() || devices.size() > 32U ||
	   devices.size() != record.task.target.deviceCount) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// Local recordは原TRANSFER ownerだけを直接借用します。過去grantを新許可にしません
	if( record.ownedBodyRecordIndex) {
		const auto index = *record.ownedBodyRecordIndex ;	// 安定ordinalです
		// 元owner以外・循環・照合票のないflagだけを拒否します
		if( index >= records_.size() || &records_[index] == &record ||
		   records_[index].ownedBodyRecordIndex || !record.localInspection ||
		   !record.localInspection->matches( record.task) ||
		   record.lookup != owner.acquisitionLookup_ || record.context != owner.context_ ||
		   !owner.acquisition_ || !owner.workspace_) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		const auto &source = records_[index] ;	// 元TRANSFERの不変由来/期限です
		const auto	sourceError =
			// 原A全期限を再確認します
			reverifyRecordBinding( owner, source, services, observeHost) ;
		// 元ownerの拒否をBの別時刻窓で上書きしません
		if( sourceError != 0U) {
			return sourceError ;
		}

		const auto current = services.utc ? services.utc() : std::nullopt ;	// Bも現時計へ結びます
		const auto seconds = current && current->time_since_epoch().count() > 0
								 ? static_cast<std::uint64_t>( current->time_since_epoch().count())
								 : 0U ;		// 原UTCです
		IndexedDriverArchiveHint hint ;		// B独立selectorです
		DriverArchiveInput		 input ;	// 原owned byteを借用します
		const auto				 error = owner.adapter_.bindRetainedInspectionInput(
			  record.task, source.task, record.context, seconds, *owner.acquisition_,
			  *owner.workspace_, source.seal, *record.localInspection, hint, input,
			  observeHost) ;	// 原B全期限も独立再確認します
		// 同hashだけでrecord/device scope不一致を補完しません
		if( error != 0U) {
			return error ;
		}

		return hint.indexSha256 == record.hint.indexSha256 &&
					   hint.recordSha256 == record.hint.recordSha256 &&
					   hint.archiveSha256 == record.hint.archiveSha256 &&
					   hint.archiveBytes == record.hint.archiveBytes &&
					   hint.selectedInfs == record.hint.selectedInfs &&
					   input.inspectionPath == record.input.inspectionPath &&
					   input.sha256 == record.input.sha256 &&
					   input.byteCount == record.input.byteCount
				   ? 0U
				   : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	const auto	now		 = services.utc ? services.utc() : std::nullopt ;	// 元workerの信頼UTC
	const auto &metadata = record.grant.metadata() ;						// 元grant期限を延長しません
	// 元claim/private owner/同context/同消費済みgrant以外を受理しません
	if( !now || now->time_since_epoch().count() <= 0 || record.lookup != owner.acquisitionLookup_ ||
	   record.context != owner.context_ ||
	   record.task.scanSessionId != owner.context_.scanSessionId || record.task.planId == 0U ||
	   !owner.acquisition_ || !owner.workspace_ ||
	   metadata.state != OfficialDownloadGrantState::CONSUMED ||
	   metadata.outcome != OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION ||
	   metadata.error != 0 ||
	   record.grant.validateSignedIndexAuthority( record.task.scanSessionId) != 0) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto seconds = static_cast<std::uint64_t>( now->time_since_epoch().count()) ;	// 正のUTC秒
	// 署名元とgrantの元最小期限に再照合し、再承認やinstallで延長しません
	if( seconds < metadata.issuedUtcSeconds || seconds >= metadata.expiresUtcSeconds) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
	}

	IndexedDriverArchiveHint hint ;		// 同sealから再照合した元index/record/byte
	DriverArchiveInput		 input ;	// 同保護実archive
	const auto				 error = owner.adapter_.bindInspectionInputImpl(
		  record.task, record.context, seconds, *owner.acquisition_, *owner.workspace_, record.seal,
		  hint, input, observeHost) ;	// 実全byteと期限の再検証
	// 元grant検証のHRESULTを上書きせず返します
	if( error != 0U) {
		return error ;
	}

	// 全形式が同元seal・原取得byteへ再結合し、成功DTOを権限へ変更しません
	if( hint.indexSha256 != record.hint.indexSha256 ||
	   hint.recordSha256 != record.hint.recordSha256 ||
	   hint.archiveSha256 != record.hint.archiveSha256 ||
	   hint.archiveBytes != record.hint.archiveBytes ||
	   hint.selectedInfs != record.hint.selectedInfs ||
	   input.inspectionPath != record.input.inspectionPath || input.sha256 != record.input.sha256 ||
	   input.byteCount != record.input.byteCount) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	// WiXの消費済み取得票は、署名元の原規約に保持した実ファイルへ再結合します
	if( wixBinding) {
		const auto &original =
			originals[relations[primary.relationIndex].recordIndex] ;	// 検証済みの元v8行です
		// 同一取得票と両保護領域に結ぶ閉包だけを使用します
		if( metadata.grantId != wixBinding->grantId ||
		   input.workspaceMode != record.input.workspaceMode ||
		   !record.wixInspection->package.workspace || !record.wixInspection->driverWorkspace ||
		   record.wixInspection->package.workspace->protectionMode() != input.workspaceMode ||
		   record.wixInspection->driverWorkspace->protectionMode() != input.workspaceMode) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		std::vector<WixTermsDocument>
				   terms ;	// 原ダイジェストと全言語を再照合する呼出し内の作業値です
		const auto termsError = readSignedIndexWixTerms( original, *record.wixInspection, {},
														terms) ;	// 同じ原収集証拠です
		// 一つでも不成立の場合は元診断を保持して導入資格へ進めません
		if( termsError != 0U) {
			return termsError ;
		}

		// 取得後に提示した全言語の順序と本文が原バイトの再読取りに一致する場合だけ導入へ進めます
		if( !record.wixTerms || record.wixTerms->confirmedAtUtc > *now ||
		   !std::ranges::equal( terms, record.wixTerms->documents,
							   []( const auto &left, const auto &right) {
								   return left.locale == right.locale && left.body == right.body ;
							   })) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		const auto &inspection =
			record.inspection.inspection ;	// 同じ保護領域で端末用に再解析した内容です
		// 元取得・領域と異なる結果や非導入用途の検査を後続へ渡さない
		if( record.inspection.error != 0U || inspection.scanSessionId != input.scanSessionId ||
		   inspection.archiveSha256 != input.sha256 || inspection.archiveBytes != input.byteCount ||
		   inspection.infs.size() != 1U ||
		   inspection.infs.front().workspace.get() != record.wixInspection->driverWorkspace.get()) {
			return record.inspection.error != 0U ? record.inspection.error
												 : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		const auto storageError = reverifyCommonDriverInf(
			// 元保護領域を端末用同条件で再検査します
			inspection.infs.front()) ;
		// 端末用の内容と署名の不成立も作用を許可しません
		if( storageError != 0U) {
			return storageError ;
		}

		const auto completed =
			// 実ファイルと指定された実機器の観測が終わった後のUTCです
			services.utc() ;
		// 途中の失効や時計逆行から新しい元期限を発行しません
		if( !completed || *completed < *now || *completed >= record.wixTerms->expiresAtUtc ||
		   static_cast<std::uint64_t>( completed->time_since_epoch().count()) >=
			   metadata.expiresUtcSeconds) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
		}

		std::string reason ;	// 独立した元索引期限の拒否理由です
		return owner.adapter_.validateBinding( *wixBinding, record.context, completed, reason) ;
	}

	// InstallerはINF用ledgerへ偽装せず、同署名・期待publisherを改めて検査します
	if( record.installerHandoff) {
		// 未検査・原署名拒否を引継ぎ可能へ補完しません
		if( record.inspection.state !=
			   IndexedDriverInspectionState::INSTALLER_INSPECTION_COMPLETED ||
		   record.installerError != 0 || !record.inspection.inputBound ||
		   record.publisher.empty()) {
			return record.installerError != 0 ? record.installerError
											  : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		const std::array<std::wstring_view, 1U> publishers{
			record.publisher} ;	// 原完全一致policyです
		return verifyAuthenticodePublisher( input.inspectionPath, publishers) ;
	}

	const auto &original = originals[relations[primary.relationIndex].recordIndex] ;	// 元署名の代表
	// 元署名の形式が得られない場合は保管した入力の形式から補完しない
	if( !original.acquisitionDescriptor) {
		return E_ACCESSDENIED ;
	}

	DelegatedOfficialPackageInput delegated ;	// 元成功grantの同ledger再結合
	// 同消費済みgrantと実取得ledgerを再照合した元HRESULT
	const auto					  delegatedError = bindDelegatedInput(
		   record.acquisition, record.grant, hint, original.acquisitionDescriptor->format, delegated) ;
	// 全元hash/size/pathと同grantを再結合し、公開DTOを権限へ昇格しません
	if( delegatedError != 0U || hint.indexSha256 != record.hint.indexSha256 ||
	   hint.recordSha256 != record.hint.recordSha256 ||
	   hint.archiveSha256 != record.hint.archiveSha256 ||
	   hint.archiveBytes != record.hint.archiveBytes ||
	   input.inspectionPath != record.input.inspectionPath || input.sha256 != record.input.sha256 ||
	   input.byteCount != record.input.byteCount || delegated.format != record.delegated.format ||
	   delegated.provenance.downloadGrantId != record.delegated.provenance.downloadGrantId ||
	   delegated.provenance.acquisitionId != record.delegated.provenance.acquisitionId) {
		return delegatedError != 0U ? delegatedError
									: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 専用Modelsの端末関係と取得代表の原レコードが同じか確認します
 * @param[in] record 元取得・元参照を所有する保持記録です
 * @param[in] pair 同取得に属する端末と発行先の関係です
 * @return 同じ認証済み原レコードです。別の取得・端末・原位置ではnullptrです
 */
//------------------------------------------------------------------------------
const IndexDistributionRecord *SignedIndexCandidateBindingSession::scopedRouteOriginal(
	const PreparedRecord &record, const Pair &pair) const
{
	// 別の導入方式や元取得の範囲外から専用レコードを引きません
	if( !record.scopedInspection || record.installerHandoff || pair.requiredPlan ||
	   pair.declarativeQualification || pair.hardwareScoped || pair.infOrdinal != 0U ||
	   pair.recordIndex >= records_.size() || &records_[pair.recordIndex] != &record ||
	   !record.lookup || record.referenceIndex >= references_.size() ||
	   pair.referenceIndex >= references_.size()) {
		return nullptr ;
	}

	// 同じ認証済み索引内の端末関係です
	const auto &relations = record.lookup->relations() ;
	// 発行先の端末に結び付いた取得前の参照です
	const auto &reference = references_[pair.referenceIndex] ;
	// 保持結果が使う取得代表の元位置です
	const auto	representative = references_[record.referenceIndex].relationIndex ;
	// 当該取得に属する元端末関係だけを解決します
	if( pair.relationIndex >= relations.size() || representative >= relations.size() ||
	   reference.target != record.task.target ||
	   reference.hint.deviceIdentity != pair.deviceIdentity ||
	   std::ranges::find( reference.relationIndices, pair.relationIndex) ==
		   reference.relationIndices.end()) {
		return nullptr ;
	}

	// 同じ承認で元端末に照合した関係です
	const auto &relation = relations[pair.relationIndex] ;
	// 専用欄を含む認証済みの端末用レコード集合です
	const auto	originals = record.lookup->snapshot().consumerRecords() ;
	// 同じCABでも別原レコード・端末の関係は借りません
	if( relation.context != record.context || !relation.deviceIdentity ||
	   *relation.deviceIdentity != pair.deviceIdentity ||
	   relation.recordIndex >= originals.size() ||
	   relation.recordIndex != relations[representative].recordIndex) {
		return nullptr ;
	}

	// 取得代表と同じ位置で認証された専用レコードです
	const auto &original = originals[relation.recordIndex] ;
	return original.recordSchemaVersion == 6U && original.catalogHardwareScope &&
				   original.scopedModelsEvidence && original.acquisitionDescriptor &&
				   relation.recordSha256 == original.recordSha256
			   ? &original
			   : nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元ホストと端末の観測後に同じ取得元・再利用先の原期限と許可を確認します
 * @param[in] owner 元スキャンと取得許可を持つ所有者です
 * @param[in] record 同じ保護ファイルの取得または再利用記録です
 * @param[in] pair 元レコードと対象端末に結ぶ候補です
 * @param[in] services 再観測後に使う実UTCです
 * @return 元ホスト・端末・両者の原期限有効時0、元拒否はHRESULTです
 * @pre 同記録の所有と元バイトを確認済みです
 */
//------------------------------------------------------------------------------
NativeError SignedIndexCandidateBindingSession::authorizeScopedRoute(
	const SignedIndexScanSession &owner, const PreparedRecord &record, const Pair &pair,
	const provider_worker_index_detail::Services &services) const
{
	// 候補の端末関係から同じ専用レコードを読み出します
	const auto *original = scopedRouteOriginal( record, pair) ;
	// 元スキャン・索引の所有と保持済み配布物の参照を先に確認します
	if( !original || record.lookup != owner.acquisitionLookup_ || record.context != owner.context_ ||
	   (record.ownedBodyRecordIndex && *record.ownedBodyRecordIndex >= records_.size())) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 元取得許可と再観測を同じアダプターへ問い合わせます
	const auto &adapter = owner.adapter_ ;
	// 元OSと同じホストが現在も成立するか確認します
	auto		error = adapter.reobserveHost( record.context) ;
	// ホストが変わっていない場合だけ元レコードの端末条件を観測します
	if( error == 0U) {
		error = adapter.reobservePreparedDevice( *original, record.task.target, record.context) ;
	}

	// 現在の観測に失敗したときは期限照会で元の失敗を上書きしません
	if( error != 0U) {
		return error ;
	}

	// 再利用時は取得ファイルを元から所有するTRANSFERの記録です
	const auto &transfer =
		record.ownedBodyRecordIndex ? records_[*record.ownedBodyRecordIndex] : record ;
	// 元転送を許可した一回限りのgrantの固定値です
	const auto &grant = transfer.grant.metadata() ;
	// 時間を要する観測の後に同じ時点のUTCを取得します
	const auto	now = services.utc ? services.utc() : std::nullopt ;
	// 元grantの発行・失効と同じepoch秒です
	const auto	seconds = now ? now->time_since_epoch().count() : 0 ;
	// 時計不明・時刻戻り・終了済み窓では導入許可を戻しません
	if( seconds <= 0 || static_cast<std::uint64_t>( seconds) < grant.issuedUtcSeconds ||
	   static_cast<std::uint64_t>( seconds) >= grant.expiresUtcSeconds) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
	}

	// 端末の生IDを含まない元照合の理由です
	std::string reason ;
	// 原取得と再利用先を同じ時点で検査し片方の成立を借りません
	for( const auto *input : {&transfer, &record}) {
		// 当該taskを保持する元の承認と端末集合です
		const auto binding =
			std::ranges::find( adapter.bindings_, input->task.target,
							  &SignedIndexAcquisitionAdapter::PreparedBinding::target) ;
		// 元のclaimと受取側端末の承認関係が失われた場合は止めます
		if( binding == adapter.bindings_.end() || binding->claimedTask != input->task ||
		   (input == &record && std::ranges::find( binding->relationIndices, pair.relationIndex) ==
									binding->relationIndices.end())) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		error = adapter.validateBinding( *binding, record.context, now, reason) ;
		// 元取得と受取先が同じ場合は同じ承認を二度確認しません
		if( error != 0U || &transfer == &record) {
			return error ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 当該端末の私有計画と既存トークンを元レコード・保持閉包と再照合します
 * @param[in] owner 同じ取得を保持する元スキャンです
 * @param[in] store 実選択とトークンを保持する同じ発行元です
 * @param[in] services 元期限を確認するサービスです
 * @param[in] record 不変閉包の所有記録です
 * @param[in] pair 同じ端末とレコードを指す発行済み候補です
 * @return 完全一致0、元拒否はHRESULTです
 * @note ホスト観測と登録・適用は行いません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexCandidateBindingSession::reverifyScopedRoute(
	const SignedIndexScanSession &owner, const DriverStoreProvider &store,
	const provider_worker_index_detail::Services &services, const PreparedRecord &record,
	const Pair &pair) const
{
	// 導入計画が指すべき認証済みの端末別レコードです
	const auto *original = scopedRouteOriginal( record, pair) ;
	// 専用計画と実トークンの両方が元候補に残っている必要があります
	if( !original || !pair.scopedQualification || pair.binding.token == 0U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 先に保護ファイルと取得許可の元所有を検査します
	auto error = reverifyRecordBinding( owner, record, services, false) ;
	// 元署名と取得物が有効な場合だけ現在の実選択を読み直します
	if( error == 0U) {
		error = store.revalidateScopedInfInstallQualification(
			record.task.scanSessionId, pair.deviceIdentity, record.scopedInspection, record.hint,
			*original, pair.scopedQualification) ;
	}

	// 所有または元選択の拒否を後段のトークン確認で上書きしません
	if( error != 0U) {
		return error ;
	}

	// 元計画と所有一致を確認済みの一つの署名付きINFです
	const auto &inf = record.scopedInspection->infs.front() ;
	return store.revalidateOfficialInfInstallBinding( record.task.scanSessionId, pair.deviceIdentity,
													 *inf.workspace, inf.closure.packages.front(),
													 pair.binding) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元バイトと保持閉包の確認後に、対象のOSと端末の機種・必須群を確認します
 * @param[in] owner 同取得issuerと原hostの所有者です
 * @param[in] record 同所有recordです
 * @param[in] services 元UTC serviceです
 * @return 全成立0、原binding又は当該候補の端末条件の拒否です
 * @note 機種条件の不一致は他のレコードのhost拒否へ変換しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexCandidateBindingSession::reverifyRecord(
	const SignedIndexScanSession &owner, const PreparedRecord &record,
	const provider_worker_index_detail::Services &services) const
{
	// 専用Modelsは元byteを先に検証しホストは後で一度確認します
	const auto error = reverifyRecordBinding( owner, record, services, !record.scopedInspection) ;
	// 純粋検証の拒否時はhostを観測しません
	if( error != 0U) {
		return error ;
	}

	const auto &reference = references_[record.referenceIndex] ;	// 純粋検証済みの原代表です
	const auto &original =
		record.lookup->snapshot().consumerRecords()
			[record.lookup->relations()[reference.relationIndex].recordIndex] ;	// 元認証recordです
	// 専用欄の原レコードだけは原証拠を受取側の閉包へ結び直します
	if( original.recordSchemaVersion == 6U) {
		// 署名済みの証拠か閉包が欠けたときは通常INFへ読み替えません
		if( !original.scopedModelsEvidence || !record.scopedInspection) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		const auto contentError = reverifyIndexedScopedDriverPackage(
			record.task.scanSessionId, record.hint, *original.scopedModelsEvidence,
			*record.scopedInspection) ;	// 受取側の元証拠で保持閉包を検査します
		// 元閉包の失敗時にホスト観測で検査結果を上書きしません
		if( contentError != 0U) {
			return contentError ;
		}
	}

	const auto hostError = requiresBoundIndexHost( original)
							   ? owner.adapter_.reobserveHost( record.context)
							   : 0U ;	// 既存のOS条件です
	// OSが一致した場合だけ同じ端末の機種と承認済みの条件を確認します
	return hostError != 0U ? hostError
						   : owner.adapter_.reobservePreparedDevice( original, record.task.target,
																	record.context) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 指定導入の元所有・全Models・端末条件を再確認します
 * @param[in] owner 同scanと原hostの所有者です
 * @param[in] record 同取得recordです
 * @param[in] pair 同record/元relation/INF ordinalへ結ぶ既routeです
 * @param[in] services 元UTC serviceです
 * @param[in] observeHost 同選択の内容検査後にOSと機種の再観測も行う場合trueです
 * @return 完全一致0、内容不一致E_ACCESSDENIED又は原拒否です
 * @note 最終機器観測後に取得許可と元レコードの期限を確認し、内容不一致からhost拒否ラッチや新tokenを作りません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexCandidateBindingSession::reverifyBoundScopedPair(
	const SignedIndexScanSession &owner, const PreparedRecord &record, const Pair &pair,
	const provider_worker_index_detail::Services &services, const bool observeHost) const
{
	// 元配布範囲の検査前は呼出し側が指定した場合だけホストを観測します
	const auto error = reverifyRecordBinding( owner, record, services, observeHost) ;
	// 元所有/期限/byteを確認できなければpairを使いません
	if( error != 0U) {
		return error ;
	}

	const auto &relations = record.lookup->relations() ;					// 同所有lookupだけです
	const auto	originals = record.lookup->snapshot().consumerRecords() ;	// 元署名内容です
	// 別record又は元pair ordinal不正を先に拒否します
	if( pair.recordIndex >= records_.size() || &records_[pair.recordIndex] != &record ||
	   pair.referenceIndex >= references_.size() || pair.relationIndex >= relations.size()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto &reference = references_[pair.referenceIndex] ;	// 検査済みordinalです
	const auto &relation  = relations[pair.relationIndex] ;		// 元recordとの結合を確認します
	// 同target/deviceの元選択集合にないrelationを拒否します
	if( reference.target != record.task.target ||
	   reference.hint.deviceIdentity != pair.deviceIdentity ||
	   std::ranges::find( reference.relationIndices, pair.relationIndex) ==
		   reference.relationIndices.end() ||
	   relation.recordIndex >= originals.size() || relation.context != record.context ||
	   !relation.deviceIdentity || *relation.deviceIdentity != pair.deviceIdentity) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto &original	   = originals[relation.recordIndex] ;	// 同relationの原recordだけです
	const bool	hardwareScoped = isIndexHardwareScoped( original) ;	// 元署名の完全ID条件です
	// 元レコードが持つ公式対象条件を候補の保持値から外さない
	if( pair.hardwareScoped != hardwareScoped) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const bool needsHost =
		pair.declarativeQualification || requiresBoundIndexHost( original) ;	// 元候補のhost条件です
	// 元Modelsを再確認する条件のある候補だけ現在の節を読み直す
	if( !pair.hardwareScoped && !needsHost) {
		return 0U ;
	}

	// 非標準方式や未所有INFをscoped最終readerへ渡しません
	if( original.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE ||
	   record.installerHandoff || pair.infOrdinal >= record.inspection.inspection.infs.size()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto &inf = record.inspection.inspection.infs[pair.infOrdinal] ;	// 元所有の単一INFです
	// 元workspaceと単一閉包がないINFを拒否します
	if( !inf.workspace || inf.closure.packages.size() != 1U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const bool declarative =
		inf.closure.packages.front().inspectionPurpose ==
		OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ;	// 独自クラスは元実選択の資格が必要
	// 通常の元候補から独自クラスだけの導入資格へ切り替えません
	if( declarative != static_cast<bool>( pair.declarativeQualification)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto contentError = declarative
								  ? reverifyCommonDriverInfContent( inf)
								  : reverifyCommonDriverInf( inf) ;	// CATと全閉包を元用途で再確認する
	// 全閉包の元拒否をModels成功で消しません
	if( contentError != 0U) {
		return contentError ;
	}

	OfficialInfPublishedIdentity actual ;	// currentOS/NULL platformの原reader出力です
	const auto					 identityError =
		readOfficialInfPublishedIdentity( *inf.workspace, inf.closure.packages.front(),
										 actual) ;	// 元currentOS readerの独立した原HRESULTです
	// 元reader拒否を局所内容一致へ補完しません
	if( identityError != 0U) {
		return identityError ;
	}

	// 局所内容拒否をhost native failureや新しいglobal latchへ変更しません
	if( !matchesIndexPublishedInf( original, record.inspection.inspection, record.hint, inf,
								 actual)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::set<std::size_t> matches ;	// 最終でも元選択集合内の唯一一致だけを認めます
	// 最終でも選択集合の全元recordを照合します
	for( const auto ordinal : reference.relationIndices) {
		const auto &selected = relations[ordinal] ;	// 全ordinalは純粋検証済みです
		// 実currentOS identityに一致した元recordだけを数えます
		if( matchesIndexPublishedInf( originals[selected.recordIndex], record.inspection.inspection,
									record.hint, inf, actual)) {
			matches.insert( selected.recordIndex) ;
		}
	}

	// 別recordへの入替えと複数一致をhost観測前に拒否します
	if( matches.size() != 1U || !matches.contains( relation.recordIndex)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 全選択の純粋検査を先行する場合は、呼出元でhostを確認する
	if( needsHost && observeHost) {
		const auto hostError =
			// 元host条件の再確認です
			owner.adapter_.reobserveHost( record.context) ;
		// 元hostの変化を期限確認の結果で上書きしない
		if( hostError != 0U) {
			return hostError ;
		}
	}

	// 対象付き行の期限は全Modelsと元hostの検査中にも進みます
	if( !pair.hardwareScoped) {
		return 0U ;
	}

	const auto &adapter = owner.adapter_ ;	// 認証済みの取得承認を同じownerから参照します
	const auto	binding = std::ranges::find(
		 adapter.bindings_, record.task.target,
		 &SignedIndexAcquisitionAdapter::PreparedBinding::target) ;	// 同じ元承認です
	// 選択した元targetの保持値を失った場合は続行しない
	if( binding == adapter.bindings_.end()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 同じ元レコードに対する現在の型番と承認済みの群を、期限の最終照会より先に確認します
	if( observeHost) {
		const auto deviceError =
			adapter.reobservePreparedDevice( original, record.task.target,
											record.context) ;	// 元端末への属性照会結果です
		// 群や型番が変わった場合は最初の拒否を保持します
		if( deviceError != 0U) {
			return deviceError ;
		}
	}

	const auto	now		   = services.utc ? services.utc() : std::nullopt ;	// 機器観測後の実UTCです
	const auto &transfer   = record.ownedBodyRecordIndex ? records_[*record.ownedBodyRecordIndex]
														 : record ;			// 検証済みの取得元所有値です
	const auto &grant	   = transfer.grant.metadata() ;					// 配布物取得時の元権限の期限です
	const auto	nowSeconds = now ? now->time_since_epoch().count() : 0 ;	// 同一時点のepoch秒です
	// 元取得の時刻不明・変化と取得許可の期限を成功へ補わない
	if( nowSeconds <= 0 || static_cast<std::uint64_t>( nowSeconds) < grant.issuedUtcSeconds ||
	   static_cast<std::uint64_t>( nowSeconds) >= grant.expiresUtcSeconds) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
	}

	std::string reason ;	// 秘密の端末IDを含まない診断です
	return adapter.validateBinding( *binding, record.context, now, reason) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同じ取得を承認した端末に、専用Modelsと実Windows選択から候補を発行します
 * @param[in] owner 同じ署名付き索引と保護取得の所有者です
 * @param[in,out] store 同スキャン・同端末の唯一のトークン発行元です
 * @param[in] services 再観測後の元期限を確認するサービスです
 * @param[in] recordIndex 保持済み取得結果の私有位置です
 * @param[in,out] report 適合と候補発行の件数・理由を保持する監査結果です
 * @param[out] applicableReferences 実選択に合格した端末の私有参照です
 * @pre 対象全体の元取得・署名、保護閉包と所有を確認済みです
 */
//------------------------------------------------------------------------------
void SignedIndexCandidateBindingSession::auditScopedInfCandidates(
	const SignedIndexScanSession &owner, DriverStoreProvider &store,
	const provider_worker_index_detail::Services &services, const std::size_t recordIndex,
	OfficialPreparationAuditReport &report, std::set<std::size_t> &applicableReferences)
{
	// この監査で確認済みの専用取得記録です
	const auto &record = records_[recordIndex] ;
	// 再利用を含め実取得証拠を保持する元記録です
	const auto &transfer =
		record.ownedBodyRecordIndex ? records_[*record.ownedBodyRecordIndex] : record ;
	// 候補へ表示根拠として結ぶ元取得の識別子です
	const auto evidenceId = transfer.acquisition.acquisitionId ;
	// 同じ取得許可の端末ごとに一つの候補を監査します
	for( std::size_t referenceIndex = 0U; referenceIndex < references_.size(); ++referenceIndex) {
		// 結果を結ぶ同スキャンの取得前表示行です
		const auto &reference = references_[referenceIndex] ;
		// 別の取得対象に関係する端末へ候補を追加しません
		if( reference.target != record.task.target) {
			continue ;
		}

		// 端末と元レコードを保持する未発行の候補です
		Pair pair ;
		pair.recordIndex	= recordIndex ;
		pair.referenceIndex = referenceIndex ;
		pair.relationIndex	= reference.relationIndex ;
		pair.deviceIdentity = reference.hint.deviceIdentity ;
		++report.examinedPairCount ;
		// 当該端末と元取得が共通する認証済みレコードです
		const auto *original = scopedRouteOriginal( record, pair) ;
		// 実選択を確認する前の元取得権限の検査結果です
		auto		error = original ? authorizeScopedRoute( owner, record, pair, services)
									 : static_cast<NativeError>( E_ACCESSDENIED) ;
		// 原権限が有効な端末でだけWindowsの選択を確認します
		if( error == 0U) {
			error = store.buildScopedInfInstallQualification(
				record.task.scanSessionId, pair.deviceIdentity, record.scopedInspection,
				record.hint, *original, pair.scopedQualification) ;
		}

		// 実選択未成立を端末別の失敗として残します
		if( error != 0U) {
			++report.failedPairCount ;
			// 最初の端末別拒否の理由を保持します
			if( report.firstPairError == 0U) {
				report.firstPairError = error ;
			}

			continue ;
		}

		applicableReferences.insert( referenceIndex) ;
		++report.applicablePairCount ;
		++report.publication.examinedPairCount ;
		// 同じ公開取引の候補全体か、既に公開済みの候補群です
		const auto &staged = pending_ ? pendingRoutes_ : routes_ ;
		// 発行トークンを増やす前に候補全体の件数を制限します
		if( staged.size() >= 4096U) {
			throw std::length_error( "index routing limit") ;
		}

		// 同じ参照の候補発行を再度行っても、通常の選択を曖昧にしません
		if( std::ranges::any_of(
			   staged, [&]( const auto &route) { return route.referenceIndex == referenceIndex ; })) {
			error = static_cast<NativeError>( E_ACCESSDENIED) ;
		} else {
			error = store.createScopedInfInstallBinding(
				record.task.scanSessionId, pair.deviceIdentity, pair.scopedQualification,
				reference.current.provider, reference.current.version, reference.current.driverDate,
				pair.binding) ;
		}

		// 未発行のまま終了した場合に新トークンを破棄します
		NewTokenGuard guard{store, record.task.scanSessionId, pair.binding.token} ;
		// Windows選択とトークン発行の後にも元の許可を確認します
		if( error == 0U) {
			error = authorizeScopedRoute( owner, record, pair, services) ;
		}

		// 適合確認は保持したまま発行条件を失った候補を除外します
		if( error != 0U) {
			++report.publication.excludedPairCount ;
			// 後の候補の発行失敗で最初の診断を上書きしません
			if( report.publication.firstError == 0U) {
				report.publication.firstError = error ;
			}

			continue ;
		}

		pair.rankAudit	  = pair.binding.rankAudit ;
		pair.observedRank = pair.rankAudit.candidateRank ;
		// 同じトークンから構築する端末用の表示候補です
		auto candidate =
			makeBoundInfCandidate( reference.candidate, pair.binding, evidenceId, pair.infOrdinal,
								  referenceIndex, record.task.target.terms) ;
		// 私有計画の確認を通常の表示評価へ投影します
		CandidateAssessment assessment ;
		assessment.scanSessionId	 = record.task.scanSessionId ;
		assessment.candidateIdentity = candidate.identity ;
		assessment.deviceIdentity	 = candidate.deviceIdentity ;
		assessment.packageIdentity	 = candidate.packageIdentity ;
		assessment.componentRole	 = CandidateComponentRole::BASE_DRIVER ;
		assessment.origin = {CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
							 CandidateEvidenceKind::COLLECTOR_ATTESTATION, evidenceId} ;
		assessment.acquisition		= {CandidateAssessmentState::PASSED,
									   CandidateAssessmentReason::VALIDATED,
									   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
		assessment.signature		= {CandidateAssessmentState::PASSED,
									   CandidateAssessmentReason::VALIDATED,
									   CandidateEvidenceKind::WINDOWS_API, evidenceId} ;
		assessment.applicability	= {CandidateAssessmentState::PASSED,
									   CandidateAssessmentReason::VALIDATED,
									   CandidateEvidenceKind::WINDOWS_API, pair.binding.token} ;
		assessment.windowsSelection = assessment.applicability ;
		// 選択行の作用を私有計画で検査済みです。未選択行の関係は導入へ引き継ぎません
		assessment.driverOnly	= assessment.acquisition ;
		assessment.requirements = {CandidateAssessmentState::NOT_APPLICABLE,
								   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
								   CandidateEvidenceKind::OFFICIAL_RECORD, evidenceId} ;
		// 同じ公開レコードで明示された必須条件だけを表示に引き継ぎます
		for( std::size_t condition = 0U;
			condition < original->acquisitionDescriptor->prerequisites.items.size(); ++condition) {
			assessment.explicitRequirements.push_back(
				{condition + 1U, CandidateComponentRole::BASE_DRIVER, true,
				 CandidateRequirementState::SATISFIED, CandidateEvidenceKind::OFFICIAL_RECORD,
				 evidenceId}) ;
		}

		// 明示された必要条件がある場合は確認済みと明示します
		if( !assessment.explicitRequirements.empty()) {
			assessment.requirements = {CandidateAssessmentState::PASSED,
									   CandidateAssessmentReason::VALIDATED,
									   CandidateEvidenceKind::OFFICIAL_RECORD, evidenceId} ;
		}

		assessment.installMethod = CandidateInstallMethod::STANDARD_INF ;
		assessment.method = {CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
							 CandidateEvidenceKind::IMPLEMENTATION_POLICY, pair.binding.token} ;
		assessment.executorAvailable = true ;
		// 全軸が成立した候補だけを通常の導入選択へ発行します
		if( !isCandidateAssessmentReady( assessment)) {
			throw std::logic_error( "scoped index assessment not ready") ;
		}

		candidate.assessment			 = std::move( assessment) ;
		candidate.setupClassRegistration = pair.binding.setupClassRegistration ;
		pair.candidate					 = std::move( candidate) ;
		// 既存候補を保持して新候補を同じ一括発行の対象にします
		if( !pending_) {
			pendingRoutes_ = routes_ ;
			pending_	   = true ;
		}

		pendingRoutes_.push_back( pair) ;
		guard.release() ;
		report.publishedCandidates.push_back( std::move( pair.candidate)) ;
		++report.publication.publishedCount ;
	}

	report.applicability = report.applicablePairCount != 0U ? CandidateAuditGateState::PASSED
						   : report.failedPairCount != 0U	? CandidateAuditGateState::FAILURE
															: CandidateAuditGateState::REJECTED ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 私有資格内の単一起動変更範囲を確認画面に必要な値へ投影する
 * @param[in] effects 同じ署名索引候補で照合した選択作用
 * @param[in] scope 同じ選択・対象機器の私有資格に保持した全分類
 * @return 起動とイベントの作成・維持・変更、および実際に追加変更する局所値と電源の件数
 * @throws std::logic_error 私有資格の観測と元行が不一致、または確認を許可しない分類の場合
 * @note 端末の元値、機器識別、実ファイルの位置や資格自体を返さない
 */
//------------------------------------------------------------------------------
SingleBootStorageChangeSummary summarizeSingleBootStorage(
	const StorageInfEffects &effects, const StorageSingleBootInstallScope &scope)
{
	const auto display = []( StorageServiceChange change) {
		// 確認を許可しない状態を維持や更新の表示へ縮約しない
		switch( change) {
			// 端末で対象の正式な不在を確認した
			case StorageServiceChange::CREATE:
				return StoragePlannedChange::CREATE ;
			// 元署名に対して現在値が同じ
			case StorageServiceChange::KEEP:
				return StoragePlannedChange::KEEP ;
			// 同じ選択機器に結ぶ値を変更する
			case StorageServiceChange::UPDATE_SELECTED:
				return StoragePlannedChange::UPDATE ;
			// 共有変更、不明または定義外値を確認対象としない
			default:
				throw std::logic_error( "single boot change is not qualified") ;
		}
	} ; // 借用なしで受入れ済み変更を表示用の種別へ写す
	const auto &values	= scope.observed.device.registry.values ;	// 同じ候補順の元作用の位置
	const auto &changes = scope.changes.registry ;					// 同じ位置に対応する確認済み変更種別
	// 元行と現在値の対応が不完全な場合に短い件数だけを表示しない
	if( values.size() != changes.size() ||
	   scope.observed.powerChanges.size() != effects.powerSettings.size()) {
		throw std::logic_error( "single boot change rows do not match") ;
	}

	SingleBootStorageChangeSummary made ;	// 同じ元選択の変更だけを画面へ渡す値
	made.boot  = display( scope.changes.boot) ;
	made.event = display( scope.changes.event) ;
	// 維持する設定を追加または変更する件数へ含めない
	made.powerSettingCount = static_cast<std::uint32_t>(
		std::ranges::count_if( scope.observed.powerChanges, []( auto change) {
			return change == StoragePowerChange::CREATE ||
				   change == StoragePowerChange::UPDATE_SELECTED ;
		})) ;
	// 同じ元行の所有文脈から機器と関連サービスを分けて数える
	for( std::size_t index = 0U; index < values.size(); ++index) {
		// 元の値を維持する行は追加や変更の件数に含めない
		if( display( changes[index]) == StoragePlannedChange::KEEP) {
			continue ;
		}

		const auto &entry =
			// 元AddRegと所有先
			effects.effects.at( values[index].effectIndex).original ;
		// サービスキーと機器固有キーの作用範囲を同じ件数へ合算しない
		if( entry.source.scope == SystemInfContext::SERVICE) {
			++made.serviceValueCount ;
		} else {
			++made.deviceValueCount ;
		}
	}

	return made ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief WiXの同じ元機器一台に、元規約への同意を要する単一起動候補を発行します
 * @param[in,out] owner 元取得と索引の所有者です
 * @param[in,out] store 同じ端末のWindows選択を照合する所有者です
 * @param[in] services 元期限を確認する依存です
 * @param[in] recordIndex 元閉包と消費済み取得を持つ検証済み私有位置です
 * @param[in] cancellation 同取得からの取消しです
 * @return 適合性の結果と、発行条件が成立した場合だけ未確定の候補です
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationAuditReport> SignedIndexCandidateBindingSession::
	auditWixPreparedRecord( SignedIndexScanSession &owner, DriverStoreProvider &store,
						   const provider_worker_index_detail::Services &services,
						   const std::size_t							 recordIndex,
						   const PreparationCancellation				&cancellation)
{
	const auto &record	  = records_[recordIndex] ;					// 同じ検査操作で保持した元EXEと全規約です
	const auto &reference = references_[record.referenceIndex] ;	// 元計画に現在処理を結ぶ一台です
	OfficialPreparationAuditReport report ;							// 所有トークンと別にUIへ返す結果です
	report.targetIdentity = record.task.target.identity ;
	report.providerId	  = SIGNED_INDEX_PROVIDER_ID ;
	report.infCount		  = 1U ;
	auto &source		  = report.candidates.emplace_back( OfficialPreparationCandidateAudit{
		 reference.candidate.identity,
				 {CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
				  CandidateAuditGateState::PENDING, CandidateAuditGateState::PENDING,
				  CandidateInstallReadiness::BLOCKED}}) ;	// 元検査行を別の導入候補に変更しません
	report.contentError	  = reverifyRecordBinding( owner, record, services) ;
	// 元規約、取得票又は閉包が変わった場合は現在の順位を照会しません
	if( report.contentError != 0U) {
		report.content = source.audit.contentIntegrity = CandidateAuditGateState::FAILURE ;
		return report ;
	}

	// 同じ取得の取消しが届いた場合は監査結果を現在一覧へ反映しません
	if( cancellation && cancellation()) {
		return std::nullopt ;
	}

	report.content = source.audit.contentIntegrity = CandidateAuditGateState::PASSED ;
	report.acceptedInfCount						   = 1U ;
	report.examinedPairCount					   = 1U ;
	const auto &inf		= record.inspection.inspection.infs.front() ;	// 同保護領域の端末用再検査です
	const auto &package = inf.closure.packages.front() ;				// 実署名と全参照を再検査済みの基本INFです
	Pair		pair ;													// 唯一の機器と元取得へ限定した照合です
	pair.recordIndex	 = recordIndex ;
	pair.referenceIndex	 = record.referenceIndex ;
	pair.relationIndex	 = reference.relationIndex ;
	pair.deviceIdentity	 = reference.hint.deviceIdentity ;
	const auto rankError = store.auditOfficialInfRank(
		record.task.scanSessionId, pair.deviceIdentity, *inf.workspace, package, pair.rankAudit,
		&report.firstPairDiagnostic) ;	// 同じ端末の完全順位です
	// API失敗と正常な非適用を分け、いずれも候補発行に進めません
	if( rankError != 0U || pair.rankAudit.decision != OfficialDriverRankDecision::APPLICABLE) {
		report.applicability = source.audit.systemApplicability =
			rankError != 0U ? CandidateAuditGateState::FAILURE : CandidateAuditGateState::REJECTED ;
		report.failedPairCount = rankError != 0U ? 1U : 0U ;
		report.firstPairError  = rankError ;
		return report ;
	}

	report.applicability = source.audit.systemApplicability = CandidateAuditGateState::PASSED ;
	report.applicablePairCount								= 1U ;
	report.publication.examinedPairCount					= 1U ;
	report.publication.excludedPairCount					= 1U ;
	report.publication.state = OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES ;
	const auto &relations	 = record.lookup->relations() ;	// 同じ元対象の全照合を借用します
	const auto &original =
		record.lookup->snapshot()
			.consumerRecords()[relations[pair.relationIndex].recordIndex] ;	// 単一の元配布です
	const auto &published = original.publishedIdentityEvidence ;			// 署名索引のModelsと対象IDです
	std::vector<std::wstring> hardwareIds ;									// 端末が照合した完全IDの集合だけを保持します
	hardwareIds.reserve( reference.relationIndices.size()) ;
	// 同じレコードの公開IDのうちこの端末の照合が成立したものだけを渡します
	for( const auto index : reference.relationIndices) {
		const auto &id = relations[index].publicIdIndex ;	// 元照合が確認したIDの位置です
		// 位置が不正な場合や完全Hardware ID以外は選択の根拠にしません
		if( !id || *id >= published.pnpIds.size() || !isExactWixHardwareId( published.pnpIds[*id])) {
			report.publication.firstError = static_cast<NativeError>( E_ACCESSDENIED) ;
			return report ;
		}

		const auto &value = published.pnpIds[*id].value ;	// 署名索引に保存した元Hardware IDです
		hardwareIds.emplace_back( value.begin(), value.end()) ;
	}

	const std::wstring				   models{published.modelSection.begin(),
							  // 元Models節の名前です
							  published.modelSection.end()} ;
	const OfficialStorageInfModelScope modelScope{models,
												  hardwareIds} ;	// 同期呼出しの間だけ借用します
	// 順位照会中に取消しが届いた場合は新しい私有資格を発行しません
	if( cancellation && cancellation()) {
		return std::nullopt ;
	}

	RequiredInfBindingDiagnostic diagnostic ;	// 候補発行が拒否された場合の最初の段階です
	report.publication.firstError = store.createStorageInfInstallBinding(
		record.task.scanSessionId, pair.deviceIdentity, inf, pair.requiredPlan,
		reference.current.provider, reference.current.version, reference.current.driverDate,
		pair.rankAudit, pair.binding, &diagnostic, {}, false, &modelScope) ;
	// Windows選択や単一起動の所有が確認できなければ順位合格だけを保持します
	if( report.publication.firstError != 0U) {
		report.publication.bindingPath		= diagnostic.path ;
		report.publication.bindingRejection = static_cast<std::uint32_t>( diagnostic.rejection) ;
		report.publication.bindingStage		= diagnostic.stage ;
		return report ;
	}

	NewTokenGuard guard{store, record.task.scanSessionId,
						pair.binding.token} ;	// 取消しや例外で新規発行を戻します
	const auto	  stored =
		// 同issuerの私有証拠です
		store.officialInfInstallBindings_.find( pair.binding.token) ;
	// 必要計画と同じ単一起動の証拠がなければ常規の導入候補に変換しません
	if( !pair.requiredPlan || !pair.requiredPlan->storageEffects_ ||
	   stored == store.officialInfInstallBindings_.end() || !stored->second.storageQualification ||
	   !stored->second.storageQualification->singleBoot_ ||
	   stored->second.storageQualification->effects_ != *pair.requiredPlan->storageEffects_) {
		report.publication.firstError = static_cast<NativeError>( E_ACCESSDENIED) ;
		return report ;
	}

	report.publication.firstError = reverifyRecordBinding( owner, record, services) ;
	// 実ノードの読み取り中に既に失効した取得を候補一覧へ登録しません
	if( report.publication.firstError != 0U) {
		return report ;
	}

	const auto evidenceId = record.acquisition.acquisitionId ;	// 同じ実取得を示す非機密IDです
	auto	   candidate  = makeBoundInfCandidate(
		   reference.candidate, pair.binding, evidenceId, 0U, pair.referenceIndex,
		   OfficialPreparationTerms::INSPECTION_ONLY) ;	// 新しいIDを割り当て、同意は未成立です
	candidate.inspectionTargetIdentity.clear() ;
	candidate.detailDisplayIdentity.clear() ;
	candidate.wixInspectionSourceIdentity = reference.candidate.identity ;
	candidate.setupClassRegistration	  = pair.binding.setupClassRegistration ;
	const auto &effects = *pair.requiredPlan->storageEffects_ ;	// 同じ選択の変更予定です
	const auto &scope =
		*stored->second.storageQualification->singleBoot_ ;			// 共有先と現在状態を確認した結果です
	auto &change		   = candidate.storageChange.emplace() ;	// 元作用の表示だけを候補へ結びます
	change.startType	   = effects.service.start ;
	change.bootFlags	   = effects.service.bootFlags ;
	change.existingService = scope.observed.device.candidateService.evidence.has_value() ;
	change.requiredImportCount =
		static_cast<std::uint32_t>( pair.requiredPlan->stageOnlyImportOrdinals_.size()) ;
	change.singleBoot = summarizeSingleBootStorage( effects, scope) ;
	candidate.requiredExtensionCount =
		static_cast<std::uint32_t>( pair.requiredPlan->count( DriverPlanRole::EXTENSION)) ;
	candidate.requiredDriverComponentCount =
		static_cast<std::uint32_t>( pair.requiredPlan->count( DriverPlanRole::DRIVER_COMPONENT)) ;
	const CandidateAssessmentFinding origin{
		CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
		CandidateEvidenceKind::COLLECTOR_ATTESTATION, evidenceId} ;	// 元レコードの収集証拠です
	auto &assessment = candidate.assessment.emplace() ;				// 実選択に結ぶ候補の詳細です
	// 内容とWindowsの順位が成立しない場合は表示だけを発行しません
	if( !makeCommonInfCandidateAssessment( record.task.scanSessionId, candidate, inf, evidenceId,
										 origin, 0U, pair.rankAudit.candidateRank, assessment)) {
		throw std::logic_error( "WiX storage assessment mismatch") ;
	}

	assessment.windowsSelection = {CandidateAssessmentState::PASSED,
								   CandidateAssessmentReason::VALIDATED,
								   CandidateEvidenceKind::WINDOWS_API, pair.binding.token} ;
	assessment.method = {CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
						 CandidateEvidenceKind::IMPLEMENTATION_POLICY, pair.binding.token} ;
	assessment.executorAvailable = true ;
	assessment.driverOnly = {CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
							 CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
	assessment.requirements = {CandidateAssessmentState::NOT_APPLICABLE,
							   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
							   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
	// 元Needsが成立した場合にだけ候補に必要な構成として案内します
	if( pair.requiredPlan->verifiedNeedsEdgeCount_ != 0U) {
		assessment.explicitRequirements.push_back(
			{1U, CandidateComponentRole::BASE_DRIVER, true, CandidateRequirementState::SATISFIED,
			 CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId}) ;
	}

	// 同じ資格が保持した追加機能を省略せず候補表示へ結びます
	for( const auto &member : pair.requiredPlan->members_) {
		assessment.explicitRequirements.push_back(
			{assessment.explicitRequirements.size() + 1U,
			 member.role == DriverPlanRole::EXTENSION ? CandidateComponentRole::EXTENSION_INF
													  : CandidateComponentRole::COMPONENT,
			 true, CandidateRequirementState::SATISFIED, CandidateEvidenceKind::PACKAGE_INSPECTION,
			 evidenceId}) ;
	}

	// 全明示構成を確認した事実は同じ内容検査に結びます
	if( !assessment.explicitRequirements.empty()) {
		assessment.requirements = assessment.driverOnly ;
	}

	// 取消し又は上限に達した場合は旧候補を変更しません
	if( cancellation && cancellation()) {
		return std::nullopt ;
	}

	// 評価を完了した候補を掲載できる場合だけ、同じ操作へ専用の取得経路を発行します
	if( !isCandidateAssessmentReady( assessment) ||
	   (pending_ ? pendingRoutes_.size() : routes_.size()) >= 4096U) {
		throw std::logic_error( "WiX storage candidate publication mismatch") ;
	}

	// 全対象の検証が済むまで新しい私有経路と対応候補を一緒に留保します
	if( !pending_) {
		pendingRoutes_ = routes_ ;
		pending_	   = true ;
	}

	report.publishedCandidates.push_back( candidate) ;
	report.candidatePublicationAttempted = true ;
	report.publication.state = OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
	report.publication.excludedPairCount = 0U ;
	report.publication.publishedCount	 = 1U ;
	pair.candidate						 = std::move( candidate) ;
	pendingRoutes_.push_back( std::move( pair)) ;
	guard.release() ;
	return report ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元取得と実sealを再確認して内容・rank・bindingをpendingへ監査します
 * @param[in,out] owner 元scan/取得の私有owner
 * @param[in,out] store 同workerのDriver Store
 * @param[in] services 元worker固定service
 * @param[in] targetIdentity 元取得target
 * @param[in] displayed 同scan既表示行
 * @param[in] cancellation 検査後の候補発行も停止する同取得操作の取消しです
 * @return 当該取得成功を保持する有限report。別targetでは空です
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationAuditReport> SignedIndexCandidateBindingSession::
	auditPreparedRecord( SignedIndexScanSession &owner, DriverStoreProvider &store,
						const provider_worker_index_detail::Services &services,
						const std::wstring_view						  targetIdentity,
						const std::span<const UpdateCandidate>		  displayed,
						const PreparationCancellation				 &cancellation)
{
	const auto found = std::find_if( records_.begin(), records_.end(), [&]( const auto &record) {
		return record.task.target.identity == targetIdentity ;
	}) ; // 実取得成功を私有所有した元recordだけ
	// 取得済みの元参照に戻れない対象を監査結果へ変換しません
	if( found == records_.end() || found->referenceIndex >= references_.size()) {
		return std::nullopt ;
	}

	const auto recordIndex = static_cast<std::size_t>( found - records_.begin()) ;	// Stable ordinal
	// WiXは元Modelsと単一起動を限定して監査し、汎用アーカイブを装いません
	if( found->task.target.terms == OfficialPreparationTerms::INSPECTION_ONLY) {
		return auditWixPreparedRecord( owner, store, services, recordIndex, cancellation) ;
	}

	auto	   &record				= *found ;		// 同task/grant/seal/閉包の所有値
	const bool	pendingBeforeReport = pending_ ;	// 先行reportの未commit routeを保持します
	// 今回reportの新tokenだけをrollbackする元prefix境界です
	const auto	pendingPrefix = pendingBeforeReport ? pendingRoutes_.size() : routes_.size() ;
	const auto &contentOwner =
		record.ownedBodyRecordIndex && *record.ownedBodyRecordIndex < records_.size()
			? records_[*record.ownedBodyRecordIndex]
			: record ;										// reverifyRecordで直接ownerを検証します
	OfficialPreparationAuditReport report ;					// 非機密reportだけを本体へ渡します
	std::set<std::size_t>		   applicableReferences ;	// 当該取得で完全な順位監査に合格した元参照
	std::set<std::size_t>		   inboxNullReferences ;	// 同じ端末と元署名で委譲が確認できた元参照
	bool observedStorageDelegation{} ;						// ストレージ委譲を端末ごとに照会したか
	report.targetIdentity = targetIdentity ;
	report.providerId	  = SIGNED_INDEX_PROVIDER_ID ;
	// 取得が保持する元閉包の数を方式ごとに計数します
	const auto infCount = record.scopedInspection ? record.scopedInspection->infs.size()
												  : record.inspection.inspection.infs.size() ;
	const bool finiteInfCount =
		infCount <=
		OFFICIAL_PREPARATION_MAXIMUM_INF_COUNT ;	// Narrowing前にpayload全体の上限を固定します
	report.infCount = finiteInfCount ? static_cast<std::uint32_t>( infCount) : 0U ;
	report.contentError =
		finiteInfCount ? reverifyRecordBinding( owner, record, services, !record.scopedInspection)
					   : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
	report.installerHandoff = record.installerHandoff ;
	// 再検証の成功で元の全体内容失敗を消さず、既存の再検証失敗は優先して保持します
	if( report.contentError == 0U) {
		report.contentError = record.inspection.error ;
	}

	// 元seal/期限を失った取得物は内容・Windows候補を未合格へ戻します
	if( report.contentError != 0U) {
		report.content = CandidateAuditGateState::FAILURE ;
	} else {
		// Installerの署名・原作用範囲はINFの内容合格件数へ混入させません
		if( record.installerHandoff || record.scopedInspection) {
			report.content = CandidateAuditGateState::PASSED ;
		} else {
			// 本体共通検査の個別拒否を独立保持します
			for( const auto &inf : record.inspection.inspection.infs) {
				report.acceptedInfCount +=
					inf.state == CommonInfInspectionState::VERIFIED && inf.error == 0U ? 1U : 0U ;
				// 最初の内容拒否だけを保持し、後続成功で消しません
				if( report.firstContentRejection == 0U && inf.error != 0U) {
					report.firstContentRejection = inf.error ;
				}
			}

			report.content = report.acceptedInfCount != 0U ? CandidateAuditGateState::PASSED
														   : CandidateAuditGateState::REJECTED ;
		}
	}

	std::vector<OfficialDiscoveryDeviceHint> hints ;	// 同原承認targetへ結合済みの全device
	// 元共有taskの全deviceを保持し、未表示deviceを推測追加しません
	for( const auto &value : references_) {
		// 別taskの参照を同payloadへ無断で追加しません
		if( value.target == record.task.target && std::ranges::none_of( hints, [&]( const auto &hint) {
			   return hint.deviceIdentity == value.hint.deviceIdentity ;
		   })) {
			hints.push_back( value.hint) ;
		}
	}

	// 元承認件数と全参照が一致しない場合は共有候補を発行しません
	if( hints.size() != record.task.target.deviceCount || hints.empty() || hints.size() > 32U) {
		report.applicability	  = CandidateAuditGateState::FAILURE ;
		report.applicabilityError = static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 全元参照/件数/byte成立後だけServer又はscoped clientの同原hostを再観測します
	if( report.contentError == 0U && report.applicabilityError == 0U) {
		report.contentError = reverifyRecord( owner, record, services) ;
		// host拒否を内容合格から失敗へ戻します
		if( report.contentError != 0U) {
			report.content = CandidateAuditGateState::FAILURE ;
		}
	}

	// 専用Modelsは元内容とWindowsの実選択の両方を確認して候補を発行します
	if( record.scopedInspection && report.content == CandidateAuditGateState::PASSED) {
		report.acceptedInfCount = report.infCount ;
		// 全参照の所有が確認できた場合だけ専用候補を作ります
		if( report.applicabilityError == 0U) {
			auditScopedInfCandidates( owner, store, services, recordIndex, report,
									 applicableReferences) ;
		}
	}

	// 内容合格INFごとに全元deviceを照合し、別の非適用INFで正常pairを除外しません
	if( report.content == CandidateAuditGateState::PASSED && report.applicabilityError == 0U &&
	   !record.installerHandoff && !record.scopedInspection) {
		std::vector<DelegatedOfficialDeviceApplicability> applicability ;	// 元observer集計
		const auto										  pairBegin =
			// この取得の原record候補pairも既存4096枠へ制限します
			pairs_.size() ;
		InfFailureDiagnostic firstObserverFailure ;	// observer順で最初の同pair失敗だけです
		const DelegatedOfficialInfRankObserver observer = [&]( ScanSessionId		session,
															  std::wstring_view device,
															  const OfficialDownloadWorkspace
																					   &workspace,
															  const OfficialInfPackage &package,
															  std::optional<std::uint32_t> &rank) {
			InfFailureDiagnostic failure ;	// 同INF/device observer一回だけの元失敗です
			const NativeError	 observerError = [&]() -> NativeError {
				   rank.reset() ;
				   // Extension/SWCを独立した基本INF候補へ発行しません
				   if( package.role != DriverPlanRole::BASE_DRIVER) {
					   rank.reset() ;
					   return NativeError{} ;
				   }

				   const auto inf =
					   std::find_if( record.inspection.inspection.infs.begin(),
									record.inspection.inspection.infs.end(), [&]( const auto &value) {
										return value.workspace.get() == &workspace &&
											   value.closure.packages.size() == 1U &&
											   &value.closure.packages.front() == &package ;
									}) ; // 共同workspace内でも同原packageそのものへ結合します
				   // 観測対象INFが所有検査集合に存在しなければ内部不整合を返します
				   if( inf == record.inspection.inspection.infs.end() ||
					  inf->closure.packages.size() != 1U ||
					  &inf->closure.packages.front() != &package) {
					   return static_cast<NativeError>( E_UNEXPECTED) ;
				   }

				   OfficialInfPublishedIdentity actual ;	// 同owned INFの現HINFを再読取りします
				   // 同owned HINFからの元読取り診断だけを保持します
				   const auto					identityError =
					   readOfficialInfPublishedIdentity( workspace, package, actual, &failure) ;
				   // 公開tuple未確認をWindows rank成功へ代替しません
				   if( identityError != 0U) {
					   return identityError ;
				   }

				   std::vector<std::pair<std::size_t, std::size_t>>
					   matchingReferences ;	// 同元参照と唯一の原relation位置です
				   std::set<std::size_t>
							   seenRecords ;							// 同recordの複数公開ID relationだけを重複除去します
				   const auto &relations = record.lookup->relations() ;	// 元認証lookupです
				   const auto  originals =
					   // 原byteの集合です
					   record.lookup->snapshot().consumerRecords() ;
				   // 先頭target/deviceへ丸めず、全元recordを同native INFへ独立照合します
				   for( std::size_t referenceIndex = 0U; referenceIndex < references_.size();
					   ++referenceIndex) {
					   const auto &reference = references_[referenceIndex] ;	// 同describeの原関係です
					   // 別target/deviceを当該INFへ結びません
					   if( reference.target != record.task.target ||
						  reference.candidate.deviceIdentity != device ||
						  reference.relationIndex >= relations.size()) {
						   continue ;
					   }

					   std::optional<std::size_t> soleRelation ;	// 当該選択集合内の唯一の完全tupleです
					   // 元代表を含まない集合や原record数を超える集合を内部不整合として拒否します
					   if( reference.relationIndices.empty() ||
						  reference.relationIndices.front() != reference.relationIndex ||
						  reference.relationIndices.size() > originals.size()) {
						   return static_cast<NativeError>( E_UNEXPECTED) ;
					   }

					   // 選択した集合内の全元Modelsを同じ実INFへ独立に照合します
					   for( const auto relationIndex : reference.relationIndices) {
						   // 範囲外の位置を別recordへ補完しません
						   if( relationIndex >= relations.size()) {
							   return static_cast<NativeError>( E_UNEXPECTED) ;
						   }

						   const auto &relation =
							   relations[relationIndex] ;	// 原認証record位置を保持します
						   // 元scan/device/sourceから外れる関係を候補に混ぜません
						   if( relation.recordIndex >= originals.size() ||
							  relation.context != record.context || !relation.deviceIdentity ||
							  *relation.deviceIdentity != device) {
							   return static_cast<NativeError>( E_UNEXPECTED) ;
						   }

						   const auto &original =
							   originals[relation.recordIndex] ;	// 同集合の元recordだけです
						   // 原record/hash/sourceと実INFの完全tupleが一致したものだけを数えます
						   if( relation.recordSha256 == original.recordSha256 &&
							  relation.sourceId == original.sourceId &&
							  relation.recordId == original.recordId &&
							  matchesIndexPublishedInf( original, record.inspection.inspection,
													   record.hint, *inf, actual) &&
							  seenRecords.insert( relation.recordIndex).second) {
							   // 同じ選択集合に複数の実一致があればWindows rankで先頭へ丸めず拒否します
							   if( soleRelation) {
								   return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_DUP_NAME)) ;
							   }

							   soleRelation = relationIndex ;
						   }
					   }

					   // 唯一一致した原位置だけを後段のPairと選択引継ぎへ渡します
					   if( soleRelation) {
						   matchingReferences.emplace_back( referenceIndex, *soleRelation) ;
					   }
				   }

				   // 同tupleの元recordがないINFではWindows rank/tokenを発行しません
				   if( matchingReferences.empty()) {
					   return NativeError{} ;
				   }

				   // 多relationをnative rank/tokenの発行上限拡張へ変換しません
				   if( pairs_.size() - pairBegin > OFFICIAL_PREPARATION_MAXIMUM_PAIR_COUNT ||
					  matchingReferences.size() >
						  OFFICIAL_PREPARATION_MAXIMUM_PAIR_COUNT - (pairs_.size() - pairBegin)) {
					   return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
				   }

				   // 同currentOS Models/全typed ID一致後、Windows rank前の作用境界です
				   const auto hostError = reverifyRecord( owner, record, services) ;
				   // Models後のhost拒否ではWindows rankを観測しません
				   if( hostError != 0U) {
					   return hostError ;
				   }

				   // 独自クラスの元行を読み取りで確認し、空サービスを導入候補のランクへ渡さない
				   if( package.inspectionPurpose ==
					  OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT) {
					   // 複数の元recordが同じ端末に一致しても一つのModels節を推測しない
					   if( matchingReferences.size() != 1U) {
						   failure.stage = InfDiagnosticStage::IDENTITY_TUPLE ;
						   return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_DUP_NAME)) ;
					   }

					   // 元INFの全IDと一致した唯一の署名record
					   const auto &matched =
						   originals[relations[matchingReferences.front().second].recordIndex] ;
					   const auto model = std::ranges::find_if( actual.models, [&]( const auto &value) {
						   return matchesPublishedText( matched.publishedIdentityEvidence.modelSection,
													   value.modelSection) ;
					   }) ; // 元recordと完全一致した現在OSのModels
					   // 同一の所有閉包と署名を端末の内容用途で再確認する
					   const auto checked = reverifyCommonDriverInfContent( *inf) ;	// 元ファイルの再照合
					   // 元のModelsやファイルが見つからない場合は新しい作用を推測しない
					   if( checked != 0 || model == actual.models.end()) {
						   failure.stage = InfDiagnosticStage::CONTENT_REVERIFY ;
						   return checked != 0 ? checked : static_cast<NativeError>( E_ACCESSDENIED) ;
					   }

					   OfficialInfSelectedModelRole role{} ;	// Windowsが選んだ同じ元行の作用
					   std::optional<OfficialDriverRankAudit>
						   audit ;	// 実ドライバーの一行だけの順位評価
					   std::shared_ptr<const DeclarativeInfInstallQualification>
								  qualification ;	// 同じ選択の私有計画
					   // Windows選択と署名INFの元行を照合した結果
					   const auto selected = store.observeDeclarativeInfModelRole(
						   session, device, workspace, package, actual.infSha256, model->modelSection,
						   role, audit, &failure, &qualification) ;
					   // 読み取り失敗は空サービスの正常終了へ変換しません
					   if( selected != 0U) {
						   // クラス作用の読取りで記録した段階があれば保持する
						   if( failure.stage == InfDiagnosticStage::NONE) {
							   failure.stage = InfDiagnosticStage::IDENTITY_MODELS ;
						   }

						   return selected ;
					   }

					   // 空サービスは照合済みの候補なしとして終了します
					   if( role == OfficialInfSelectedModelRole::NULL_DRIVER && !audit) {
						   return NativeError{} ;
					   }

					   // 一行限定の順位評価が完了した元ドライバーだけが適合判定へ進みます
					   if( role != OfficialInfSelectedModelRole::KERNEL_DRIVER || !audit) {
						   failure.stage = InfDiagnosticStage::RANK_EVIDENCE ;
						   return static_cast<NativeError>( E_UNEXPECTED) ;
					   }

					   // Policy上の非適合は観測エラーにも順位の既定値にも変換しません
					   if( audit->decision != OfficialDriverRankDecision::APPLICABLE) {
						   return NativeError{} ;
					   }

					   const auto &[referenceIndex, relationIndex] =
						   // 一行の署名record
						   matchingReferences.front() ;
					   Pair pair ;	// 同じ署名recordに結ぶ一行限定の順位評価
					   pair.recordIndex	   = recordIndex ;
					   pair.referenceIndex = referenceIndex ;
					   pair.relationIndex  = relationIndex ;
					   pair.deviceIdentity = device ;
					   pair.infOrdinal =
						   static_cast<std::size_t>( inf - record.inspection.inspection.infs.begin()) ;
					   pair.rankAudit				 = *audit ;
					   pair.declarativeQualification = std::move( qualification) ;
					   pair.observedRank			 = audit->candidateRank ;
					   rank							 = pair.observedRank ;
					   pairs_.push_back( std::move( pair)) ;
					   return NativeError{} ;
				   }

				   const auto error = store.observeInfCandidateRank(
					   session, device, workspace, package, rank, &failure) ;	// 同INFだけの観測です
				   // Catalogで完全IDに結んだストレージの外部参照だけを同梱委譲の読取対象とする
				   if( error == 0U && rank && package.unresolvedIncludeNeeds &&
					  package.inspectionPurpose ==
						  OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE &&
					  matchingReferences.size() == 1U) {
					   // この端末と一致した原参照と署名レコード位置
					   const auto &[referenceIndex, relationIndex] = matchingReferences.front() ;
					   const auto &relation = relations[relationIndex] ;	// 同じ署名の対象IDとの関係
					   const auto &original =
						   originals[relation.recordIndex] ;	// 同じ元配布の完全Models
					   // 複数の互換IDや別のスコープ元から委譲を推定しない
					   if( original.catalogHardwareScope && relation.publicIdIndex &&
						  *relation.publicIdIndex < original.publishedIdentityEvidence.pnpIds.size()) {
						   observedStorageDelegation = true ;
						   // 元の照合関係が指定する公開側の完全PnP ID。ここでは元結果の参照を借用します
						   const auto &id =
							   original.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex]
								   .value ;
						   // 元端末と結合済みの公式Hardware ID
						   const auto &section =
							   original.publishedIdentityEvidence.modelSection ;	// 元署名のModels節
						   bool delegated{} ;										// この端末で同梱の空ドライバーへ委譲されるか
						   // 元の一行とWindows同梱INFを確認した結果
						   auto verification = store.observeStorageInboxNullDriver(
							   session, device, *inf, {section.begin(), section.end()},
							   std::wstring{id.begin(), id.end()}, *rank, delegated) ;
						   // 同梱の確認後にも元署名・元取得閉包と期限を読み直す
						   if( verification == 0U && delegated) {
							   verification = reverifyRecord( owner, record, services) ;
						   }

						   // 曖昧なnode、信頼不足と期限切れを委譲済みとして扱わない
						   if( verification != 0U) {
							   rank.reset() ;
							   failure.stage = InfDiagnosticStage::INBOX_NULL_DRIVER ;
							   return verification ;
						   }

						   // 確認済みの委譲に導入順位・Pair・tokenを作らない
						   if( delegated) {
							   inboxNullReferences.insert( referenceIndex) ;
							   rank.reset() ;
							   return NativeError{} ;
						   }
					   }
				   }

				   // 同INFへ完全一致した全recordを保持し、別recordへ結果を再割当てしません
				   for( const auto &[referenceIndex, relationIndex] : matchingReferences) {
					   Pair pair ;	// 元HRESULTとoptional rankを件数から推測しません
					   pair.recordIndex	   = recordIndex ;
					   pair.referenceIndex = referenceIndex ;
					   pair.relationIndex  = relationIndex ;
					   pair.deviceIdentity = device ;
					   pair.infOrdinal =
						   static_cast<std::size_t>( inf - record.inspection.inspection.infs.begin()) ;
					   pair.observerError = error ;
					   pair.observedRank  = rank ;
					   pairs_.push_back( std::move( pair)) ;
				   }

				   return error ;
			}() ; // 既observerのAPI/制御/元戻値を変更しません
			// 最初の実失敗だけをdelegateのfirstPairError順へ結びます
			if( observerError != 0U && firstObserverFailure.error == 0U) {
				// 入力整合等の未分類地点をAPI由来と推定しません
				if( failure.path == InfDiagnosticPath::NONE) {
					failure.path = InfDiagnosticPath::CANDIDATE_OBSERVATION ;
				}

				failure.error		 = observerError ;
				firstObserverFailure = failure ;
			}

			return observerError ;
		} ; // 同期callだけ借用し、元recordと元INFのordinalを保持します
		report.applicabilityError = inspectDelegatedOfficialDriverApplicability(
			record.task.scanSessionId, contentOwner.delegated, record.inspection.inspection, hints,
			observer, applicability) ;
		// 全observer完了後だけ完全rank監査とunique bindingを発行します
		for( auto &pair : pairs_) {
			// 異record・元拒否・rank欠損のpairはbinding作成へ進めません
			if( pair.recordIndex != recordIndex || pair.observerError != 0U || !pair.observedRank) {
				continue ;
			}

			++report.examinedPairCount ;
			const auto &pairReference = references_[pair.referenceIndex] ;				// 同元承認の当該device
			auto	   &inf		= record.inspection.inspection.infs[pair.infOrdinal] ;	// 所有閉包
			const auto &package = inf.closure.packages.front() ;						// 共通処理の単一基本INF
			InfFailureDiagnostic rankFailure ;											// 同pairの内容再検証/完全rankだけの失敗です
			const bool			 declarative = package.inspectionPurpose ==
									 OfficialInfInspectionPurpose::
										 DECLARATIVE_CLASS_CONTENT ;	// 元行の全順位を観測済みの用途
			pair.bindingError =
				declarative ? reverifyCommonDriverInfContent( inf) : reverifyCommonDriverInf( inf) ;
			// 内容再検証失敗は未実行のrank APIへ帰属させません
			if( pair.bindingError != 0U) {
				rankFailure.path  = InfDiagnosticPath::FULL_RANK_AUDIT ;
				rankFailure.phase = InfDiagnosticPhase::CANDIDATE_RANK ;
				rankFailure.stage = InfDiagnosticStage::CONTENT_REVERIFY ;
			}

			// 内容再検査に成功したpairだけWindows rankを再照会します
			if( pair.bindingError == 0U && !declarative) {
				pair.bindingError = store.auditOfficialInfRank(
					record.task.scanSessionId, pair.deviceIdentity, *inf.workspace, package,
					pair.rankAudit, &rankFailure) ;
			}

			// API完了0だけではAPPLICABLEへ昇格しません
			if( pair.bindingError != 0U ||
			   pair.rankAudit.decision != OfficialDriverRankDecision::APPLICABLE) {
				// 同じ最初の非ゼロerrorだけへ局所診断を結び、異pairを混ぜません
				if( report.firstPairError == 0U && pair.bindingError != 0U) {
					rankFailure.error = pair.bindingError ;
					// 内容再検証の下位由来が未記録ならAPI失敗と断定しません
					if( rankFailure.path == InfDiagnosticPath::NONE) {
						rankFailure.path = InfDiagnosticPath::FULL_RANK_AUDIT ;
					}

					report.firstPairDiagnostic = rankFailure ;
				}

				report.firstPairError =
					report.firstPairError != 0U ? report.firstPairError : pair.bindingError ;
				report.failedPairCount += pair.bindingError != 0U ? 1U : 0U ;
				continue ;
			}

			++report.applicablePairCount ;
			++report.publication.examinedPairCount ;
			applicableReferences.insert( pair.referenceIndex) ;
			// 新tokenの作成より前にも全取得を通した既存4096route枠を確認します
			if( (pending_ ? pendingRoutes_.size() : routes_.size()) >= 4096U) {
				throw std::length_error( "index routing limit") ;
			}

			// 全rank監査後、新tokenを発行する前にも同原hostを確認します
			pair.bindingError = reverifyRecord( owner, record, services) ;
			std::wstring requiredHardwareId ;				// 対象付き行の照合に使った元の公開ID
			bool		 requiresFirmwareAuthorization{} ;	// 機器別の群を変更直前に確認する資格です
			// 指定導入に進む個別関係を、署名済みの元レコードと同じスキャンの証拠へ結ぶ
			if( pair.bindingError == 0U) {
				const auto &relation =
					// この端末の選択関係
					record.lookup->relations()[pair.relationIndex] ;
				const auto &original =
					record.lookup->snapshot()
						.consumerRecords()[relation.recordIndex] ;	// 当該候補の元レコード
				// 元レコードが持つ単一ID又は公式群を導入の資格へ結びます
				if( isIndexHardwareScoped( original)) {
					pair.hardwareScoped			  = true ;
					requiresFirmwareAuthorization = !original.platformFirmwareGroups.empty() ;
					std::string reason ;	// 端末の生IDを含まない元関係の診断
					pair.bindingError = owner.adapter_.validateRecord(
						pair.relationIndex, record.context,
						services.utc ? services.utc() : std::nullopt, reason) ;
					// 従来の個別対象だけが元の一IDを必要とします。公式群は現在値全体で確認します
					if( pair.bindingError == 0U && !requiresFirmwareAuthorization) {
						const auto &id =
							original.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex]
								.value ;	// 元Hardware ID
						requiredHardwareId.assign( id.begin(), id.end()) ;
					}
				}
			}

			// token直前のhost拒否を当該pairへ保持します
			if( pair.bindingError != 0U) {
				// 既合格rankを失敗pairへ二重計上せず、公開除外だけを記録します
				++report.publication.excludedPairCount ;
				// 最初の元pair errorだけを保存します
				if( report.firstPairError == 0U) {
					report.firstPairError = pair.bindingError ;
				}

				// token前の除外も最初の元公開errorへ結び、無理由の候補なしへしません
				if( report.publication.firstError == 0U) {
					report.publication.firstError = pair.bindingError ;
				}

				continue ;
			}

			RequiredInfBindingDiagnostic bindingDiagnostic ;	// 同pairだけの元拒否位置です
			// 独自クラスは元一行と作用の私有計画がある場合だけ候補を発行します
			if( declarative) {
				pair.bindingError =
					pair.declarativeQualification && inf.requiredInfPackages.empty()
						? store.createOfficialInfInstallBindingImpl(
							  record.task.scanSessionId, pair.deviceIdentity, *inf.workspace,
							  package, pairReference.current.provider,
							  pairReference.current.version, pairReference.current.driverDate,
							  pair.rankAudit, pair.binding, &bindingDiagnostic, nullptr,
							  pair.declarativeQualification, requiredHardwareId,
							  requiresFirmwareAuthorization)
						: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
			}
			// 明示依存を消さず、実閉包の一意な必要役割から私有計画を構築します
			else if( package.inspectionPurpose ==
					OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE) {
				pair.bindingError = store.createStorageInfInstallBinding(
					record.task.scanSessionId, pair.deviceIdentity, inf, pair.requiredPlan,
					pairReference.current.provider, pairReference.current.version,
					pairReference.current.driverDate, pair.rankAudit, pair.binding,
					&bindingDiagnostic, requiredHardwareId, requiresFirmwareAuthorization) ;
			}
			// 通常非storageの既必要構成だけを従来のprivate factoryへ渡します
			else if( package.hasExternalDependencies || package.hasUnassessedProgramReferences ||
					!inf.requiredInfPackages.empty() || !package.unresolvedCopyInfPaths.empty()) {
				pair.bindingError = store.createRequiredInfInstallBinding(
					record.task.scanSessionId, pair.deviceIdentity, inf, pair.requiredPlan,
					pairReference.current.provider, pairReference.current.version,
					pairReference.current.driverDate, pair.rankAudit, pair.binding,
					&bindingDiagnostic, requiredHardwareId, requiresFirmwareAuthorization) ;
			} else {
				pair.bindingError = store.createOfficialInfInstallBinding(
					record.task.scanSessionId, pair.deviceIdentity, *inf.workspace, package,
					pairReference.current.provider, pairReference.current.version,
					pairReference.current.driverDate, pair.rankAudit, pair.binding,
					&bindingDiagnostic, requiredHardwareId, requiresFirmwareAuthorization) ;
			}

			// 一pairの普通拒否は元診断と除外へ保持し、他Provider結果を捨てません
			if( pair.bindingError != 0U) {
				++report.publication.excludedPairCount ;
				// 最初のpublication拒否を個別bindingの元HRESULTで保持します
				if( report.publication.firstError == 0U) {
					report.publication.firstError  = pair.bindingError ;
					report.publication.bindingPath = bindingDiagnostic.path ;
					report.publication.bindingRejection =
						static_cast<std::uint32_t>( bindingDiagnostic.rejection) ;
					report.publication.bindingObserved = bindingDiagnostic.observed ;
					report.publication.bindingStage	   = bindingDiagnostic.stage ;
					report.publication.bindingFlags =
						(package.hasExternalDependencies ? 1U : 0U) |
						(package.hasUnassessedProgramReferences ? 2U : 0U) |
						(package.unresolvedIncludeNeeds ? 4U : 0U) |
						(bindingDiagnostic.referencesResolved ? 8U : 0U) |
						(bindingDiagnostic.rootEvidenceVerified ? 16U : 0U) ;
					report.publication.dependencyReason	  = bindingDiagnostic.firstReferenceReason ;
					report.publication.rootSignatureError = bindingDiagnostic.rootSignatureError ;
					report.publication.dependencySignatureError =
						bindingDiagnostic.firstDependencySignatureError ;
					report.publication.dependencyProvenanceError =
						bindingDiagnostic.firstDependencyProvenanceError ;
				}

				continue ;
			}

			NewTokenGuard	guard{store, record.task.scanSessionId,
								  pair.binding.token} ;	// 例外時の新token cleanup
			// Windowsの実トークンを同一の表示行に結びます
			UpdateCandidate candidate = makeBoundInfCandidate(
				pairReference.candidate, pair.binding, contentOwner.acquisition.acquisitionId,
				pair.infOrdinal, pair.referenceIndex, record.task.target.terms) ;
			// 元配布内で不在を確認した付随INFを伴う場合は、現在使用中の基本ドライバーの更新に限ります
			if( pair.requiredPlan && pair.requiredPlan->defersRootCopyInf_) {
				// 在庫の初回導入、同バージョン、旧バージョンにこの判断を継承しません
				if( candidate.action != DriverAction::UPDATE) {
					++report.publication.excludedPairCount ;
					continue ;
				}

				candidate.unresolvedCopyInfCount =
					static_cast<std::uint32_t>( package.unresolvedCopyInfPaths.size()) ;
			}

			CandidateAssessment assessment ;	// 元実byteと同tokenへ結合した八軸
			const auto			evidenceId =
				contentOwner.acquisition.acquisitionId ;	// 同実ledgerのopaque証拠
			// メーカー署名へ読み替えず同取得根拠へ結合する収集者attestation所見
			const CandidateAssessmentFinding origin{
				CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
				CandidateEvidenceKind::COLLECTOR_ATTESTATION, evidenceId} ;
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
			signed_index_candidate_binding_detail::observePublication(
				1U, pair.infOrdinal, record.task.scanSessionId, candidate, inf, evidenceId, origin,
				pair.observerError, pair.observedRank,
				pair.requiredPlan ? pair.requiredPlan->verifiedNeedsEdgeCount_ : 0U,
				pair.requiredPlan ? pair.requiredPlan->members_.size() : 0U) ;
#endif
			// 実内容/observerを結合後、実binder/token/route確認から専用八軸を確定します
			if( !makeCommonInfCandidateAssessment( record.task.scanSessionId, candidate, inf,
												 evidenceId, origin, pair.observerError,
												 pair.observedRank, assessment)) {
				throw std::logic_error( "index content assessment mismatch") ;
			}

			assessment.windowsSelection	 = {CandidateAssessmentState::PASSED,
											CandidateAssessmentReason::VALIDATED,
											CandidateEvidenceKind::WINDOWS_API, pair.binding.token} ;
			assessment.method			 = {CandidateAssessmentState::PASSED,
											CandidateAssessmentReason::VALIDATED,
											CandidateEvidenceKind::IMPLEMENTATION_POLICY, pair.binding.token} ;
			assessment.executorAvailable = true ;
			// 内容関係と同issuer bindingを確認したmemberだけを明示構成へ加えます
			if( pair.requiredPlan) {
				// 表示値だけから資格を生成せず、同issuer private資格の元変更範囲を投影します
				if( pair.requiredPlan->storageEffects_) {
					// 同原選択の全作用と必要serviceの観測です
					const auto &effects = *pair.requiredPlan->storageEffects_ ;
					const auto &helper =
						effects.service.auxiliary ;	// 同じ元選択から照合済みの補助と資源
					// 署名付きイベント資源を含め、同じ導入で共有先に置くDLLの件数
					const auto sharedDlls =
						helper && helper->eventMessageCopy
							? 1U
							: static_cast<std::uint32_t>( std::ranges::count_if(
								  effects.service.mtdCopies, [&]( const auto &copy) {
									  return copy.target != effects.service.binaryTarget ;
								  })) ;
					candidate.storageChange = StorageChangeSummary{
						effects.service.start,
						effects.service.bootFlags,
						effects.sharedDiskTimeout,
						static_cast<std::uint32_t>(
							pair.requiredPlan->stageOnlyImportOrdinals_.size()),
						!effects.services.empty() && effects.services.front().evidence.has_value(),
						sharedDlls,
						effects.mtdDeviceType,
						effects.mtdDeviceCharacteristics,
						effects.autoLogger.has_value(),
						effects.service.auxiliary.has_value(),
						effects.automaticHost.has_value(),
						std::nullopt} ;

					// 単一起動は同じ元private資格の変更範囲を確認欄へ必須で渡す
					if( effects.singleBootEvent) {
						// 同じ発行トークンに結ぶ端末と候補の私有記録
						const auto stored =
							store.officialInfInstallBindings_.find( pair.binding.token) ;
						// 別の資格や未確認の表示から単一起動候補を発行しない
						if( stored == store.officialInfInstallBindings_.end() ||
						   !stored->second.storageQualification ||
						   !stored->second.storageQualification->singleBoot_ ||
						   stored->second.storageQualification->effects_ != effects) {
							throw std::logic_error( "single boot qualification mismatch") ;
						}

						const auto &scope = *stored->second.storageQualification
												 ->singleBoot_ ;	// 同じ端末と候補の観測
						candidate.storageChange->existingService =
							scope.observed.device.candidateService.evidence.has_value() ;
						candidate.storageChange->singleBoot =
							summarizeSingleBootStorage( effects, scope) ;
					}
				}

				candidate.requiredExtensionCount =
					static_cast<std::uint32_t>( pair.requiredPlan->count( DriverPlanRole::EXTENSION)) ;
				candidate.requiredDriverComponentCount = static_cast<std::uint32_t>(
					pair.requiredPlan->count( DriverPlanRole::DRIVER_COMPONENT)) ;
				assessment.driverOnly	= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
				assessment.requirements = {CandidateAssessmentState::NOT_APPLICABLE,
										   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
										   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
				// 追加INFのない計画も、実選択graphで充足したNeedsを前提へ保持します
				if( pair.requiredPlan->verifiedNeedsEdgeCount_ != 0U) {
					assessment.explicitRequirements.push_back(
						{assessment.explicitRequirements.size() + 1U,
						 CandidateComponentRole::BASE_DRIVER, true,
						 CandidateRequirementState::SATISFIED,
						 CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId}) ;
				}

				// 必要性をtitle/公開boolから生成せず元検証memberへ結合します
				for( const auto &member : pair.requiredPlan->members_) {
					assessment.explicitRequirements.push_back(
						{assessment.explicitRequirements.size() + 1U,
						 member.role == DriverPlanRole::EXTENSION
							 ? CandidateComponentRole::EXTENSION_INF
							 : CandidateComponentRole::COMPONENT,
						 true, CandidateRequirementState::SATISFIED,
						 CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId}) ;
				}

				// 実選択Needsまたは追加memberがある場合だけ充足を要約します
				if( !assessment.explicitRequirements.empty()) {
					assessment.requirements = assessment.driverOnly ;
				}
			}

			const auto &original =
				record.lookup->snapshot()
					.consumerRecords()[record.lookup->relations()[pair.relationIndex]
										   .recordIndex] ;	// 同原必須条件です
			// 共通INF閉包の依存を消さず、原taskの確認済み条件だけを別に結びます
			for( std::size_t condition = 0U;
				condition < original.acquisitionDescriptor->prerequisites.items.size();
				++condition) {
				assessment.explicitRequirements.push_back(
					{assessment.explicitRequirements.size() + 1U,
					 CandidateComponentRole::BASE_DRIVER, true,
					 CandidateRequirementState::SATISFIED, CandidateEvidenceKind::OFFICIAL_RECORD,
					 evidenceId}) ;
			}

			// 実在の明示必須条件を条件なしと表示しません
			if( !original.acquisitionDescriptor->prerequisites.items.empty()) {
				assessment.requirements = {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::OFFICIAL_RECORD, evidenceId} ;
			}

			candidate.assessment			 = std::move( assessment) ;
			candidate.setupClassRegistration = pair.binding.setupClassRegistration ;
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
			signed_index_candidate_binding_detail::observePublication(
				3U, pair.infOrdinal, record.task.scanSessionId, candidate, inf, evidenceId, origin,
				pair.observerError, pair.observedRank,
				pair.requiredPlan ? pair.requiredPlan->verifiedNeedsEdgeCount_ : 0U,
				pair.requiredPlan ? pair.requiredPlan->members_.size() : 0U) ;
#endif
			// 八軸の不足や未知依存をboolだけでREADYへ補完しません
			if( !isCandidateAssessmentReady( *candidate.assessment)) {
				throw std::logic_error( "index assessment not ready") ;
			}

			pair.candidate = std::move( candidate) ;
			// 全new routeと表示候補を検証前のtransactionにだけ加えます
			if( !pending_) {
				pendingRoutes_ = routes_ ;
				pending_	   = true ;
			}

			// route上限を超えた新候補をcommit前に拒否します
			if( pendingRoutes_.size() >= 4096U) {
				throw std::length_error( "index routing limit") ;
			}

			pendingRoutes_.push_back( pair) ;
			guard.release() ;
			report.publishedCandidates.push_back( pair.candidate) ;
			++report.publication.publishedCount ;
		}

		// 元API個別失敗と基礎非適用を合格へ変換しません
		report.examinedPairCount = 0U ;
		// 各元deviceの観測・未知を集計し、共有targetの先頭だけを成功へ換算しません
		for( const auto &value : applicability) {
			report.examinedPairCount += value.examinedPairCount ;
			report.failedPairCount += value.failedPairCount ;
			// 最初のpair拒否を元適合検査のHRESULTで保持します
			if( report.firstPairError == 0U) {
				// Delegateと同順の最初のobserver errorだけを保存します
				if( value.firstPairError != 0U &&
				   firstObserverFailure.error == value.firstPairError) {
					report.firstPairDiagnostic = firstObserverFailure ;
				}

				report.firstPairError = value.firstPairError ;
			}
		}

		report.applicability = report.applicablePairCount != 0U ? CandidateAuditGateState::PASSED
							   : report.applicabilityError != 0U || report.failedPairCount != 0U
								   ? CandidateAuditGateState::FAILURE
								   : CandidateAuditGateState::REJECTED ;
	}

	// 元公式installerの全原deviceへ独立current guardを発行し、Windows rank合格を捏造しません
	if( record.installerHandoff && report.content == CandidateAuditGateState::PASSED &&
	   report.applicabilityError == 0) {
		// 各元recordの権限を保ち、同target以外のdeviceを和集合へ追加しません
		for( std::size_t referenceIndex = 0; referenceIndex < references_.size(); ++referenceIndex) {
			const auto &reference = references_[referenceIndex] ;	// 同原relationです
			// 別承認targetを当該installerの作用対象にしません
			if( reference.target != record.task.target) {
				continue ;
			}

			// 一つの原deviceだけに結ぶ未公開のguardとrouteです
			Pair pair ;
			pair.recordIndex	= recordIndex ;
			pair.referenceIndex = referenceIndex ;
			pair.relationIndex	= reference.relationIndex ;
			pair.deviceIdentity = reference.hint.deviceIdentity ;
			++report.examinedPairCount ;
			pair.bindingError = store.createOfficialInstallerDeviceBinding(
				record.task.scanSessionId, pair.deviceIdentity, reference.current.provider,
				reference.current.version, reference.current.driverDate, pair.installerToken) ;
			// 原present/currentの読取失敗を適合やrank成功へ昇格しません
			if( pair.bindingError != 0) {
				++report.failedPairCount ;
				// 最初の原pair失敗だけを保持し、後続成功で消しません
				if( report.firstPairError == 0) {
					report.firstPairError = pair.bindingError ;
				}

				continue ;
			}

			// 未commit tokenを全例外経路で元issuerへ返す所有guardです
			NewTokenGuard guard{store, record.task.scanSessionId, pair.installerToken, true} ;
			// 同認証lookupの未変更原recordだけを借用します
			const auto	 &original =
				record.lookup->snapshot().consumerRecords()
					[record.lookup->relations()[reference.relationIndex].recordIndex] ;
			// 明示versionなしを任意の最新版へ補完しません
			if( !original.version.value) {
				continue ;
			}

			auto candidate = reference.candidate ;	// 元device表示と選択の所有copyです
			candidate.version =
				std::wstring{original.version.value->begin(), original.version.value->end()} ;
			// 明示候補versionのaction分類値です。適用性の代用ではありません
			const auto proposed = numericVersion( candidate.version) ;
			// 元現在版のaction分類値です。欠損を更新不要へ補完しません
			const auto current = numericVersion( reference.current.version) ;
			// 真NO_DRIVER以外の現在版欠損や未分類を初回導入へ変更しません
			if( !proposed || (!current && !reference.current.version.empty())) {
				continue ;
			}

			candidate.identity = L"index-installer-" +
								 std::to_wstring( contentOwner.acquisition.acquisitionId) + L"-" +
								 std::to_wstring( referenceIndex) ;
			candidate.packageIdentity = L"index-installer-package-" +
										std::to_wstring( contentOwner.acquisition.acquisitionId) ;
			candidate.title			   = L"署名索引（公式installer引継ぎ・導入状態未確認）" ;
			candidate.provider		   = record.publisher ;
			candidate.driverDate	   = original.publishedDate.value
											 ? std::wstring{original.publishedDate.value->begin(),
														original.publishedDate.value->end()}
											 : L"" ;
			candidate.action		   = !current				 ? DriverAction::INITIAL_INSTALL
										 : *proposed > *current	 ? DriverAction::UPDATE
										 : *proposed == *current ? DriverAction::REINSTALL
																 : DriverAction::DOWNGRADE ;
			candidate.installable	   = true ;
			candidate.allContentCached = true ;
			candidate.eulaAccepted	   = true ;
			candidate.audit = {CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
							   CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
							   CandidateInstallReadiness::READY} ;
			CandidateAssessment assessment ;	// 引継ぎと標準INFは別の方式・順位です
			assessment.scanSessionId	 = record.task.scanSessionId ;
			assessment.candidateIdentity = candidate.identity ;
			assessment.deviceIdentity	 = candidate.deviceIdentity ;
			assessment.packageIdentity	 = candidate.packageIdentity ;
			const auto evidence =
				contentOwner.acquisition.acquisitionId ;	// 原成功ledgerの同証拠です
			assessment.origin			= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::COLLECTOR_ATTESTATION, evidence} ;
			assessment.acquisition		= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::PACKAGE_INSPECTION, evidence} ;
			assessment.signature		= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::WINDOWS_API, evidence} ;
			assessment.applicability	= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::WINDOWS_API, pair.installerToken} ;
			assessment.windowsSelection = {CandidateAssessmentState::NOT_APPLICABLE,
										   CandidateAssessmentReason::INSTALLER_HANDOFF_SELECTION,
										   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
										   pair.installerToken} ;
			assessment.driverOnly		= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::INSTALLER_SCOPE_ATTESTED,
										   CandidateEvidenceKind::COLLECTOR_ATTESTATION, evidence} ;
			assessment.requirements		= {CandidateAssessmentState::NOT_APPLICABLE,
										   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
										   CandidateEvidenceKind::OFFICIAL_RECORD, evidence} ;
			// 元必須条件は同task承認または既知LOCAL_CHECKに結合済みです
			for( std::size_t condition = 0;
				condition < original.acquisitionDescriptor->prerequisites.items.size();
				++condition) {
				assessment.explicitRequirements.push_back(
					{condition + 1U, CandidateComponentRole::BASE_DRIVER, true,
					 CandidateRequirementState::SATISFIED, CandidateEvidenceKind::OFFICIAL_RECORD,
					 evidence}) ;
			}

			// 明示条件の存在を条件なしの合格へ丸めません
			if( !assessment.explicitRequirements.empty()) {
				assessment.requirements = {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::OFFICIAL_RECORD, evidence} ;
			}

			assessment.method			 = {CandidateAssessmentState::PASSED,
											CandidateAssessmentReason::VALIDATED,
											CandidateEvidenceKind::IMPLEMENTATION_POLICY, pair.installerToken} ;
			assessment.installMethod	 = CandidateInstallMethod::OFFICIAL_INSTALLER ;
			assessment.executorAvailable = true ;
			candidate.assessment		 = std::move( assessment) ;
			// 同意・全八軸・元record結合を検証前に公開しません
			if( !isCandidateAssessmentReady( *candidate.assessment)) {
				throw std::logic_error( "installer assessment mismatch") ;
			}

			pair.candidate = std::move( candidate) ;
			// 全routeを通常publicationのtransactionへ結合します
			if( !pending_) {
				pendingRoutes_ = routes_ ;
				pending_	   = true ;
			}

			// 私有route上限を越える候補を公開せず、全transactionを拒否します
			if( pendingRoutes_.size() >= 4096U) {
				throw std::length_error( "installer routing limit") ;
			}

			pendingRoutes_.push_back( pair) ;
			guard.release() ;
			report.publishedCandidates.push_back( pair.candidate) ;
			++report.applicablePairCount ;
			++report.publication.examinedPairCount ;
			++report.publication.publishedCount ;
		}

		report.applicability = report.applicablePairCount ? CandidateAuditGateState::PASSED
							   : report.failedPairCount	  ? CandidateAuditGateState::FAILURE
														  : CandidateAuditGateState::REJECTED ;
	}

	// 未公開token作成後の変化は当該reportのsuffixだけを戻し、先行report/旧履歴を保ちます
	if( !report.publishedCandidates.empty()) {
		// 候補を返す直前の原権限の確認結果です
		const auto hostError = [&]() -> NativeError {
			// 従来候補は同じ元閉包とホストの確認を使います
			if( !record.scopedInspection) {
				return reverifyRecord( owner, record, services) ;
			}

			// 今回の発行分だけを原端末条件と期限で確認します
			for( std::size_t index = pendingPrefix; index < pendingRoutes_.size(); ++index) {
				// 発行待ちの対象が今も元取得によって許可されるかを確認します
				const auto error =
					authorizeScopedRoute( owner, record, pendingRoutes_[index], services) ;
				// 一件でも失効した場合は今回の発行待ちの取り消しへ進みます
				if( error != 0U) {
					return error ;
				}
			}

			return 0U ;
		}() ;
		// publication直前のhost拒否では先行reportのpending prefixを巻き戻しません
		if( hostError != 0U) {
			// この同期reportが新規追加したtokenだけを元issuerへ戻します
			for( std::size_t index = pendingPrefix; index < pendingRoutes_.size(); ++index) {
				const auto &route = pendingRoutes_[index] ;	// 先行reportと既commitは境界の前です
				static_cast<void>( store.discardOfficialInfInstallBinding(
					route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
					route.binding.token)) ;
				static_cast<void>( store.discardOfficialInstallerDeviceBinding(
					route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
					route.installerToken)) ;
			}

			pendingRoutes_.resize( pendingPrefix) ;
			// 今回初めて開始したpendingでは旧routeのcopyをcommitし直しません
			if( !pendingBeforeReport) {
				pendingRoutes_.clear() ;
				pending_ = false ;
			}

			report.publishedCandidates.clear() ;
			report.publication.publishedCount = 0U ;
			report.publication.state = OfficialPreparationCandidatePublicationState::FAILURE ;
			report.publication.excludedPairCount = report.publication.examinedPairCount ;
			// 合格済みWindows rankの履歴と、現在の公開許可失敗を分けて保持します
			if( report.publication.firstError == 0U) {
				report.publication.firstError = hostError ;
			}

			// 既診断を後の拒否で上書きしません
			if( report.firstPairError == 0U) {
				report.firstPairError = hostError ;
			}
		}
	}

	const bool includesDeclarativeClass =
		std::ranges::any_of( record.inspection.inspection.infs, []( const auto &inf) {
			return inf.state == CommonInfInspectionState::VERIFIED &&
				   inf.closure.packages.size() == 1U &&
				   inf.closure.packages.front().inspectionPurpose ==
					   OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ;
		}) ; // 同一配布物で実ドライバーと空サービスが混在し得る用途
	// 元承認に含まれる全参照行だけへ内容結果を結合し、別targetへ転送しません
	for( std::size_t index = 0U; index < references_.size(); ++index) {
		const auto &value = references_[index] ;	// 同取得に照合する一台の元参照
		// 同じ未変更targetの参照だけをこのreportで更新します
		if( value.target == record.task.target) {
			auto applicability = report.applicability ;	// この参照へ表示する適合状態
			// 確認済みの委譲は同じ配布の別端末の判定と分けて表示する
			if( report.applicabilityError == 0U && inboxNullReferences.contains( index) &&
			   !applicableReferences.contains( index)) {
				applicability = CandidateAuditGateState::INBOX_NULL_DRIVER ;
			}
			// 混在する空サービスや未確認の端末へ別端末の適合結果を転用しません
			else if( (includesDeclarativeClass || record.scopedInspection ||
					 observedStorageDelegation) &&
					applicability == CandidateAuditGateState::PASSED &&
					!applicableReferences.contains( index)) {
				applicability = report.applicabilityError == 0U && report.failedPairCount == 0U
									? CandidateAuditGateState::REJECTED
									: CandidateAuditGateState::PENDING ;
			}

			report.candidates.push_back(
				{value.candidate.identity,
				 {CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED, report.content,
				  applicability, CandidateInstallReadiness::BLOCKED}}) ;
		}
	}

	// Candidate publication状態と除外を同reportへ確定します
	if( !report.publishedCandidates.empty()) {
		report.publication.state =
			OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
		report.candidatePublicationAttempted = true ;
	}
	// 適合観測があっても公開可能なbindingがなければ候補なしを明示します
	else if( report.applicablePairCount != 0U &&
			report.publication.state != OfficialPreparationCandidatePublicationState::FAILURE) {
		report.publication.state =
			OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES ;
	}

	// 元既表示参照だけへ同reportを結合できなければ全pendingをrollbackします
	if( !validatePreparationCandidatePublication( report, displayed)) {
		rollback( store) ;
		throw std::logic_error( "index publication mismatch") ;
	}

	return report ;
}
//------------------------------------------------------------------------------
/**
 * @brief 選択された全WiX候補の同意を元取得から保持した不変表示に照合します
 * @param[in] session 選択元の通常スキャンです
 * @param[in] identities 今回の選択候補です。他ProviderのIDも含められます
 * @param[in] wixConsents 今回の操作で受諾したWiXの候補と表示参照です
 * @return 各WiX候補に過不足なく同じ元表示の同意があればtrueです
 * @note 時計や端末を観測せず、書込みと期限の延長は行いません
 */
//------------------------------------------------------------------------------
bool SignedIndexCandidateBindingSession::validateWixInstallConsents(
	const ScanSessionId session, const std::span<const std::wstring> identities,
	const std::span<const WixInstallConsent> wixConsents) const
{
	// 同意を保持できる取得は最大256対象です
	if( wixConsents.size() > MAXIMUM_WIX_INSTALL_CONSENTS ||
	   wixConsents.size() > identities.size()) {
		return false ;
	}

	std::size_t matched{} ;	// 同意を伴う選択だけを数えます
	// 各明示選択を先に私有経路に照合し、一候補に一件の同意だけを受理します
	for( const auto &identity : identities) {
		const auto route =
			std::ranges::find( routes_, identity, []( const auto &entry) -> const std::wstring & {
				return entry.candidate.identity ;
			}) ; // 選択した候補に結ぶ同スキャンの私有経路です
		// 他Providerの選択は元の通常手順に委ねます
		if( route == routes_.end()) {
			continue ;
		}

		// 範囲外の経路へ同意を結びません
		if( route->recordIndex >= records_.size()) {
			return false ;
		}

		const auto &record = records_[route->recordIndex] ;	// 元取得に保存した同じ元規約です
		// 他方式への余分な同意は一致件数に含めません
		if( record.task.target.terms != OfficialPreparationTerms::INSPECTION_ONLY) {
			continue ;
		}

		const auto consent =
			std::ranges::find( wixConsents, identity,
							  &WixInstallConsent::candidateIdentity) ;	// 当該候補への同意です
		// コピーされた表示用文字列や別取得の規約から同意を復元しません
		if( session != record.task.scanSessionId || !route->requiredPlan || !record.wixTerms ||
		   !route->candidate.storageChange || !route->candidate.storageChange->singleBoot ||
		   route->candidate.wixInspectionSourceIdentity.empty() || consent == wixConsents.end() ||
		   consent->terms != record.wixTerms ||
		   std::ranges::count( wixConsents, identity, &WixInstallConsent::candidateIdentity) != 1) {
			return false ;
		}

		++matched ;
	}

	return matched == wixConsents.size() ;
}
//------------------------------------------------------------------------------
/**
 * @brief 必要役割を含む元選択を復旧開始前に一括検証します
 * @param[in] owner 元取得ownerです
 * @param[in] store 同workerの元binding issuerです
 * @param[in] services 元期限serviceです
 * @param[in] session 元scanです
 * @param[in] identities 通常画面の元選択ID集合です
 * @param[in] wixConsents 同じ操作が明示同意した検査済みWiX候補と元規約です
 * @return 全元必要計画のbyte/期限/状態一致0、不足はHRESULTです
 * @note 他Providerを変更せず、stage/復旧/導入を呼びません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexCandidateBindingSession::preflightRequiredInstall(
	const SignedIndexScanSession &owner, const DriverStoreProvider &store,
	const provider_worker_index_detail::Services &services, const ScanSessionId session,
	const std::span<const std::wstring>		 identities,
	const std::span<const WixInstallConsent> wixConsents) const
{
	// 全選択の元規約への同意を確認してから機器や期限を観測します
	if( !validateWixInstallConsents( session, identities, wixConsents)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::set<std::wstring> devices ;	// 元選択親の一意性です
	const bool			   required = std::ranges::any_of( routes_, [&]( const auto &route) {
		return (route.requiredPlan || route.hardwareScoped || route.scopedQualification ||
				(route.recordIndex < records_.size() &&
				 records_[route.recordIndex].scopedInspection)) &&
			   std::ranges::find( identities, route.candidate.identity) != identities.end() ;
	}) ; // 必要計画又は公式配布対象がある選択だけを復元前に照合します
	// 通常の単一INF選択では従来の復元準備順を使用します
	if( !required) {
		return 0 ;
	}

	// 同selectionの全索引routeを復旧/導入前に検証します
	for( const auto &identity : identities) {
		const auto route = std::ranges::find_if( routes_, [&]( const auto &r) {
			return r.candidate.identity == identity ;
		}) ; // 元表示IDです
		// 別Providerは既存dispatcherに委ね、index権限へ変換しません
		if( route == routes_.end()) {
			continue ;
		}

		// 未表示/異scan/同device重複を復旧前に拒否します
		if( route->recordIndex >= records_.size() || !route->candidate.installable ||
		   !devices.insert( route->deviceIdentity).second) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		const auto &record = records_[route->recordIndex] ;	// 元byte/期限です
		// 別scanの導入を許可しません
		if( session != record.task.scanSessionId) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 全選択の参照/ordinal不正をhost callbackより先に拒否します
		if( !record.lookup || route->referenceIndex >= references_.size() ||
		   route->relationIndex >= record.lookup->relations().size() ||
		   references_[route->referenceIndex].target != record.task.target ||
		   references_[route->referenceIndex].hint.deviceIdentity != route->deviceIdentity ||
		   std::ranges::find( references_[route->referenceIndex].relationIndices,
							 route->relationIndex) ==
			   references_[route->referenceIndex].relationIndices.end()) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 専用の閉包かトークンがある候補は同じ私有計画で再照合します
		if( record.scopedInspection || route->scopedQualification) {
			// 復元準備前に元取得と同じ端末の実選択を確認します
			const auto error = reverifyScopedRoute( owner, store, services, record, *route) ;
			// 専用候補の元条件が失われた場合は復元準備を始めません
			if( error != 0U) {
				return error ;
			}

			continue ;
		}

		// 通常候補も全選択の所有を観測前に確認します
		auto error = route->hardwareScoped
						 ? reverifyBoundScopedPair( owner, record, *route, services, false)
						 : reverifyRecordBinding( owner, record, services, false) ;
		// 元取得未確認では現在状態を導入権限へ使用しません
		if( error != 0U) {
			return error ;
		}

		// Installerは既存の作用集合とguardを維持します
		if( record.installerHandoff) {
			error = store.revalidateOfficialInstallerDeviceBinding( session, route->deviceIdentity,
																   route->installerToken) ;
		} else {
			// 所有範囲外INFを参照しません
			if( route->infOrdinal >= record.inspection.inspection.infs.size()) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}

			const auto &inf = record.inspection.inspection.infs[route->infOrdinal] ;	// 元閉包です
			// 独自クラスも元閉包と私有bindingの両方を復旧前に確認します
			if( route->requiredPlan) {
				error = store.revalidateRequiredInfInstallBinding(
					session, route->deviceIdentity, inf, route->requiredPlan, route->binding) ;
			}
			// 対象付きの行はここまでに同じINFの内容検査を済ませています
			else if( !route->hardwareScoped) {
				error = route->declarativeQualification ? reverifyCommonDriverInfContent( inf)
														: reverifyCommonDriverInf( inf) ;
			}

			// 必要役割のない同選択INFも元状態を確認します
			if( error == 0U && !route->requiredPlan) {
				error = store.revalidateOfficialInfInstallBinding(
					session, route->deviceIdentity, *inf.workspace, inf.closure.packages.front(),
					route->binding) ;
			}
		}

		// 一候補の不足を全選択の復旧前停止へ保持します
		if( error != 0U) {
			return error ;
		}
	}

	// 全選択の純粋検証後だけ同所有hostを再観測します
	for( const auto &identity : identities) {
		const auto route = std::ranges::find_if( routes_, [&]( const auto &value) {
			return value.candidate.identity == identity ;
		}) ; // 別Providerは既dispatcherへ委ねます
		// 同selectionに存在する元index routeだけを観測します
		if( route != routes_.end()) {
			// 検証済みの選択に対応する元取得記録です
			const auto &record = records_[route->recordIndex] ;
			// 専用候補と通常候補をそれぞれの元権限で再確認します
			const auto	error =
				 route->scopedQualification ? authorizeScopedRoute( owner, record, *route, services)
				 : record.wixInspection		? reverifyRecordBinding( owner, record, services)
											: reverifyRecord( owner, record, services) ;
			// 同所有hostの元拒否を復旧前へ返します
			if( error != 0U) {
				return error ;
			}
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本体保護境界内で元選択routeだけを指定導入します
 * @param[in,out] owner 元取得と内容の私有owner
 * @param[in,out] store 同workerのDriver Store
 * @param[in] services Worker固定service
 * @param[in] session 元scan session
 * @param[in] identities 本体が許可した元表示/選択ID
 * @param[in] parentWindowNative 最終dialog親window
 * @param[in] progress 確定件数の通知先
 * @param[in] wixConsents 同じ操作の全選択に結合されたWiXの元同意です
 * @return 元選択順の独立取得/導入/元HRESULTと再起動結果
 */
//------------------------------------------------------------------------------
InstallResult SignedIndexCandidateBindingSession::executeBoundInstall(
	SignedIndexScanSession &owner, DriverStoreProvider &store,
	const provider_worker_index_detail::Services &services, const ScanSessionId session,
	const std::span<const std::wstring> identities, const std::uintptr_t parentWindowNative,
	const ProviderProgressCallback &progress, const std::span<const WixInstallConsent> wixConsents)
{
	// 復元前に確認した全員の元同意が導入入口にも届いた場合だけ処理します
	if( !validateWixInstallConsents( session, identities, wixConsents)) {
		return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
	}

	std::vector<std::size_t> selected ;	// 元selection順のprivate route ordinal
	std::set<std::wstring>	 devices ;	// 一device一基本driver
	// 全選択の元record/実seal/全file/rank/tokenを変更開始前に再検証します
	for( const auto &identity : identities) {
		const auto route = std::find_if( routes_.begin(), routes_.end(), [&]( const auto &value) {
			return value.candidate.identity == identity ;
		}) ; // 元表示IDへ完全一致したrouteだけ
		// 未公開・範囲外・同device重複・非導入候補を導入前に拒否します
		if( route == routes_.end() || route->recordIndex >= records_.size() ||
		   !devices.insert( route->deviceIdentity).second || !route->candidate.installable) {
			return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		const auto &record = records_[route->recordIndex] ;	// 元claim取得
		// 異scanと所有INF範囲外の選択を拒否します
		if( session != record.task.scanSessionId ||
		   (!record.installerHandoff && !record.scopedInspection && !route->scopedQualification &&
			route->infOrdinal >= record.inspection.inspection.infs.size())) {
			return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		// 原route/全ordinalもhost callbackより先に検証します
		if( route->referenceIndex >= references_.size() || !record.lookup ||
		   route->relationIndex >= record.lookup->relations().size() ||
		   references_[route->referenceIndex].target != record.task.target ||
		   references_[route->referenceIndex].hint.deviceIdentity != route->deviceIdentity ||
		   std::ranges::find( references_[route->referenceIndex].relationIndices,
							 route->relationIndex) ==
			   references_[route->referenceIndex].relationIndices.end()) {
			return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		// 専用候補は通常INFの保持配列へ参照を移しません
		if( record.scopedInspection || route->scopedQualification) {
			// 導入開始前に同じ端末・原閉包・トークンを読み直します
			const auto error = reverifyScopedRoute( owner, store, services, record, *route) ;
			// 一件でも元選択に戻れなければこの一括導入を始めません
			if( error != 0U) {
				return rejectedInstall( identities, error) ;
			}

			selected.push_back( static_cast<std::size_t>( route - routes_.begin())) ;
			continue ;
		}

		NativeError error =
			// 元expiryとseal/byteです
			reverifyRecordBinding( owner, record, services, false) ;
		// Installerでは同present/current guardだけを照合し、INF rankへ偽装しません
		if( record.installerHandoff) {
			// 原署名・byte再照合に成功した対象だけ現在状態を確認します
			if( error == 0) {
				error = store.revalidateOfficialInstallerDeviceBinding(
					session, route->deviceIdentity, route->installerToken) ;
			}

			// 一対象の事前拒否でも、全selectionを起動前に拒否します
			if( error != 0) {
				return rejectedInstall( identities, error) ;
			}

			selected.push_back( static_cast<std::size_t>( route - routes_.begin())) ;
			continue ;
		}

		const auto &inf = record.inspection.inspection.infs[route->infOrdinal] ;	// 同所有閉包です
		// 同seal再照合に成功した場合だけ全INF memberを再検査します
		if( error == 0U) {
			error = route->declarativeQualification ? reverifyCommonDriverInfContent( inf)
													: reverifyCommonDriverInf( inf) ;
		}

		// 内容再検査に成功した場合だけ固有Windows bindingを再検証します
		if( error == 0U) {
			error =
				route->requiredPlan
					? store.revalidateRequiredInfInstallBinding( session, route->deviceIdentity, inf,
																route->requiredPlan, route->binding)
					: store.revalidateOfficialInfInstallBinding(
						  session, route->deviceIdentity, *inf.workspace,
						  inf.closure.packages.front(), route->binding) ;
		}

		// 事前一括検証の失敗時はProvider導入を呼びません
		if( error != 0U) {
			return rejectedInstall( identities, error) ;
		}

		selected.push_back( static_cast<std::size_t>( route - routes_.begin())) ;
	}

	// 共有installerは原作用集合全体が明示選択済みの場合だけ一回引継ぎます
	for( const auto ordinal : selected) {
		// 元明示選択の私有routeだけを借用します
		const auto &route = routes_[ordinal] ;
		// 同routeの原取得・署名・全byteの所有recordです
		const auto &record = records_[route.recordIndex] ;
		// 標準INFの個別device導入へ共有installer制約を流用しません
		if( !record.installerHandoff) {
			continue ;
		}

		// 終端または元集合の有限必要数です。成功数を推測しません
		const auto count = std::ranges::count_if( selected, [&]( const auto value) {
			return routes_[value].recordIndex == route.recordIndex ;
		}) ;
		// 未選択deviceを同payloadの和集合として変更しません
		if( static_cast<std::size_t>( count) != record.task.target.deviceCount) {
			return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
		}
	}

	// 全元selection検証後だけhostを観測し、不正な後続選択で前の権限を消費しません
	for( const auto ordinal : selected) {
		// 元端末とトークンを保持する選択済み候補です
		const auto &route = routes_[ordinal] ;
		// 同じ選択が所有する元取得と閉包です
		const auto &record = records_[route.recordIndex] ;
		// 登録を始める前に元端末条件と期限を再確認します
		const auto	error = route.scopedQualification
								? authorizeScopedRoute( owner, record, route, services)
								: reverifyRecord( owner, record, services) ;
		// 全選択成立後のhost拒否ではProviderを開始しません
		if( error != 0U) {
			return rejectedInstall( identities, error) ;
		}
	}

	std::vector<std::wstring> selectedDevices ;	// 元routeの選択subsetだけです
	// 元選択に属するdeviceだけを一回scopeへ渡します
	for( const auto ordinal : selected) {
		selectedDevices.push_back( routes_[ordinal].deviceIdentity) ;
	}

	// 元Sだけの借用を所有し、scope終了時に解放します
	const auto proofScope = store.beginIndexInstallProofScope(
		owner.context_, store.activeInstallOperation(), selectedDevices) ;
	// 新resolverを閉じた同worker/scanのscopeがなければ指定導入を開始しません
	if( !proofScope.active()) {
		return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
	}

	InstallResult result ;	// 個別取得成功/導入成功・失敗を分離します
	result.downloadOutcome = OutcomeCode::SUCCESS ;
	std::size_t successes{} ;									// 実指定install成功だけ
	bool		changedRole{} ;									// 指定した役割のAPI完了があり全計画完了ではない事実です
	std::map<std::size_t, UpdateExecutionResult> handedOff ;	// 同payloadは一回だけ起動します
	// 元選択順で直前rank/bindingを再取得し、同期API待ちで進捗を増やしません
	for( const auto ordinal : selected) {
		const auto			 &route	 = routes_[ordinal] ;				// 同private token
		const auto			 &record = records_[route.recordIndex] ;	// 元取得・内容所有
		UpdateExecutionResult update{.identity = route.candidate.identity,
									 .downloadOutcome =
										 OutcomeCode::SUCCESS} ;	// 取得と導入を同一状態にしません
		// Installer引継ぎの原終了結果を保持し、driver導入成功へ変換しません
		if( record.installerHandoff) {
			const auto previous = handedOff.find( route.recordIndex) ;	// 同原record集合の結果です
			// 同payloadの後続原deviceは一回だけの原引継ぎ結果を保持します
			if( previous != handedOff.end()) {
				update			= previous->second ;
				update.identity = route.candidate.identity ;
			} else {
				update.installerHandoff = true ;
				const InstallerReadFile file{
					record.input.inspectionPath} ;	// 終端まで実byteを固定します
				// 直前の原Windows診断を保持し、後続処理で消しません
				NativeError error =
					!file.valid() ? static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError()))
								  : 0 ;
				// 起動前から終端まで元全byteを固定し、元期限・署名・全選択guardを再検証します
				if( error == 0) {
					error = reverifyRecord( owner, record, services) ;
				}

				// 原共有集合の全guardを一度だけ消費し、再起動操作への再利用を拒否します
				for( const auto selectedOrdinal : selected) {
					const auto &member = routes_[selectedOrdinal] ;	// 原selectionだけです
					// 別payloadのguardを消費しません
					if( error == 0 && member.recordIndex == route.recordIndex) {
						error = store.consumeOfficialInstallerDeviceBinding(
							session, member.deviceIdentity, member.installerToken) ;
					}
				}

				// 全原byte・署名・作用範囲・元選択・復旧が有効な場合だけ非silent UIを起動します
				if( error == 0) {
					error =
						launchOfficialInstaller( record.input.inspectionPath, record.msi,
												update.installerExitCode, update.rebootRequired) ;
				}

				update.handoffOutcome = error == 0 ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
				update.handoffError	  = error ;
				handedOff.emplace( route.recordIndex, update) ;
			}

			successes += update.handoffOutcome == OutcomeCode::SUCCESS ? 1U : 0U ;
			result.rebootRequired |= update.rebootRequired ;
			// 原引継ぎ失敗を後続成功で消しません
			if( result.installError == 0 && update.handoffError != 0) {
				result.installError = update.handoffError ;
			}

			result.updates.push_back( std::move( update)) ;
			// 起動完了をdriver導入済み件数として通知しません
			if( progress) {
				progress(
					{ProviderStage::INSTALLING,
					 static_cast<std::uint32_t>( result.updates.size() * 100U / selected.size()),
					 result.updates.size(), selected.size()}) ;
			}

			continue ;
		}

		// 各対象の元エラーを後段の導入結果へ反映します
		NativeError error{} ;
		// WiXの元規約と取得票を同じ単一起動の指定INFだけに結びます
		if( record.wixInspection) {
			const auto authorize = [&]() {
				return reverifyRecordBinding( owner, record, services) ;
			} ; // 同期の登録・適用直前まで、元取得の所有権と同意表示を保ちます
			error = authorize() ;
			// 先行候補の処理後も当該候補の元期限と端末を確認します
			if( error == 0U) {
				const auto &inf =
					record.inspection.inspection.infs[route.infOrdinal] ;	// 同じ元閉包です
				update.windowsComponentRegistrationRequired =
					route.requiredPlan->delayedRegistration_ ;
				error = store.installBoundRequiredInfPlan(
					session, route.deviceIdentity, inf, route.requiredPlan, route.binding,
					parentWindowNative, update.requiredRoles, update.requiredImports,
					update.rebootRequired, authorize) ;
			}
		}
		// 専用計画がある対象は同じトークンと同期の承認を渡します
		else if( route.scopedQualification) {
			error = reverifyScopedRoute( owner, store, services, record, route) ;
			// その対象の元バイトと実選択が有効な場合だけ登録と適用へ進みます
			if( error == 0U) {
				// 直前の選択検査で所有を確認済みのINFです
				const auto						  &inf = record.scopedInspection->infs.front() ;
				// Driver Storeの登録および適用直前で使う元取得の承認確認です
				const std::function<NativeError()> authorization = [&]() {
					// 当該操作の元保護ファイルが改変されていないか確認します
					const auto byteError = reverifyRecordBinding( owner, record, services, false) ;
					return byteError != 0U ? byteError
										   : authorizeScopedRoute( owner, record, route, services) ;
				} ;
				error = store.installBoundOfficialInfImpl(
					session, route.deviceIdentity, *inf.workspace, inf.closure.packages.front(),
					route.binding, parentWindowNative, update.rebootRequired, nullptr, nullptr,
					nullptr, &authorization, nullptr) ;
			}
		} else {
			const auto &inf =
				record.inspection.inspection.infs[route.infOrdinal] ;	// 元閉包を保持するINF
			const bool declarative =
				// 独自クラスの私有計画
				static_cast<bool>( route.declarativeQualification) ;
			error =
				// 二対象目も元期限を延長しません
				reverifyRecord( owner, record, services) ;
			// 独自クラスは後段で全閉包と元Modelsを検査し、選択行の順位はbindingで確認します
			if( error == 0U && !declarative) {
				error = reverifyCommonDriverInf( inf) ;

				OfficialDriverRankAudit audit ;	// 標準導入でのWindows順位
				// 内容が有効な対象だけ直前のWindows順位を取得します
				if( error == 0U) {
					error =
						store.auditOfficialInfRank( session, route.deviceIdentity, *inf.workspace,
												   inf.closure.packages.front(), audit) ;
				}

				// 順位照会の成功だけでは端末に適合したと判断しません
				if( error == 0U && audit.decision != OfficialDriverRankDecision::APPLICABLE) {
					error = static_cast<NativeError>( E_ACCESSDENIED) ;
				}
			}

			// 固有bindingで元端末と選択行、Windows順位を再検証します
			if( error == 0U) {
				error = store.revalidateOfficialInfInstallBinding(
					session, route.deviceIdentity, *inf.workspace, inf.closure.packages.front(),
					route.binding) ;
			}

			// 実executorは本体の指定INF bindingだけを使用し、メーカーprofileへ偽装しません
			if( error == 0U) {
				error = reverifyBoundScopedPair( owner, record, route,
												services) ;	// 最終Models/hostまで照合します
			}

			// 未選択対象や更新したgrant期限から導入を開始しません
			if( error == 0U) {
				update.windowsComponentRegistrationRequired =
					route.requiredPlan && route.requiredPlan->delayedRegistration_ ;
				const auto &package = inf.closure.packages.front() ;	// 元署名recordに結合した同じINF
				// 元署名を直前にも検査する単一INFと、独自クラスの原閉包を渡します
				if( declarative || (route.hardwareScoped && !route.requiredPlan &&
								   !package.hasExternalDependencies)) {
					const std::function<NativeError()> authorization = [&]() {
						return reverifyBoundScopedPair( owner, record, route, services) ;
					} ; // 署名済み元レコードと実UTCを二時点で読み直す
					error = store.installBoundOfficialInfImpl(
						session, route.deviceIdentity, *inf.workspace, package, route.binding,
						parentWindowNative, update.rebootRequired, nullptr, nullptr, nullptr,
						&authorization, declarative ? &inf : nullptr) ;
				}
				// 通常の指定導入は必要構成の既存経路へ渡します
				else if( route.requiredPlan) {
					error = store.installBoundRequiredInfPlan(
						session, route.deviceIdentity, inf, route.requiredPlan, route.binding,
						parentWindowNative, update.requiredRoles, update.requiredImports,
						update.rebootRequired,
						[&]() { return reverifyBoundScopedPair( owner, record, route, services) ; }) ;
				} else {
					error = store.installBoundOfficialInf(
						session, route.deviceIdentity, *inf.workspace, package, route.binding,
						parentWindowNative, update.rebootRequired) ;
				}
			}
		}

		update.installOutcome = error == 0U ? OutcomeCode::SUCCESS
								: error == static_cast<NativeError>( S_FALSE)
									? OutcomeCode::SUCCEEDED_WITH_ERRORS
									: OutcomeCode::FAILURE ;
		update.installError	  = error ;
		successes += error == 0U ? 1U : 0U ;
		changedRole |= std::ranges::any_of( update.requiredRoles, []( const auto &role) {
			return role.reflection == DriverPlanReflectionState::INSTALL_API_COMPLETED ||
				   (role.sharedCopy &&
					(role.sharedCopy->renameSucceeded != 0U || role.sharedCopy->queueStarted)) ;
		}) ;
		changedRole |= std::ranges::any_of( update.requiredImports, []( const auto &import) {
			return import.outcome == OutcomeCode::SUCCESS ;
		}) ;
		result.rebootRequired |= update.rebootRequired ;
		// 最初の指定導入失敗を保持し、後続結果で消しません
		if( result.installError == 0U && error != 0U) {
			result.installError = error ;
		}

		result.updates.push_back( std::move( update)) ;
		// 終了した選択件数だけを決定型進捗へ通知します
		if( progress) {
			progress( {ProviderStage::INSTALLING,
					  static_cast<std::uint32_t>( result.updates.size() * 100U / selected.size()),
					  result.updates.size(), selected.size()}) ;
		}
	}

	result.succeeded	  = !selected.empty() && successes == selected.size() ;
	result.installOutcome = result.succeeded				 ? OutcomeCode::SUCCESS
							: successes != 0U || changedRole ? OutcomeCode::SUCCEEDED_WITH_ERRORS
															 : OutcomeCode::FAILURE ;
	return result ;
}
} // namespace drivercrate
