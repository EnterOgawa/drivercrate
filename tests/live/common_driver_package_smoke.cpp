//------------------------------------------------------------------------------
/**
 * @file common_driver_package_smoke.cpp
 * @brief 明示local archiveの共通内容・署名・Windows適合を非導入で検査する。
 * @version 01.05.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/10/04  保守比較用の個別INF内容hash観測を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/05  四軸の保守評価と合格0件の未検査診断を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/07  旧四軸を保持し、構造・参照・部分署名・依存の独立観測を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/08  研究compile専用入口で同run v2実byteと別sidecarを結合。
 * Ver.01.05.00 Shunji Ogawa  2026/10/08  固定54 modeの残件細分類を同一通常v2実byteへ結合。
 * </pre>
 *
 * @note 明示optionでだけ起動する。入力と展開物を実行せず、install・staging・復旧APIを呼ばない。
 *       Networkを開始せず、生ID・表示名・path・payloadを出力しない。署名APIのOS trust照会は維持する。
 * @see docs/adr/0151-common-package-content-and-origin-separation.md
 * @see docs/adr/0239-individual-inf-content-evidence-for-reference-comparison.md
 * @see docs/adr/0311-maintenance-inf-structure-and-install-policy-separation.md
 */
//------------------------------------------------------------------------------

#include "core/update_types.h"
#include "platform/com_raii.h"
#include "platform/common_driver_package.h"
#include "platform/driver_store_provider.h"
#include "platform/inf_dependency_plan.h"
#include "platform/official_driver_package.h"
#include "platform/official_zip.h"
#include "platform/windows_product_type.h"

// 通常smokeへ研究入口・collector・writerを接続しない。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
#include "maintenance_reached_reference_observation.h"
#endif

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace {

/**
 * @brief SHA-256のASCII表記だけをJSON用に正規化する。
 * @param[in] hash 検査済み内容の64桁hex表記。
 * @return 有効なら小文字ASCII、長さ・文字種不正なら空のoptional。
 * @note PathやIDを受理せず、JSON文字列への任意文字混入を拒否する。
 */
[[nodiscard]] std::optional<std::string> narrowHash( const std::wstring_view hash)
{
	// 固定長でない内部結果を出力可能としない。
	if( hash.size() != 64U) {
		return std::nullopt ;
	}

	std::string result ;	// 検証成功までは呼出し側へ公開しないASCII hash。
	// 全64文字を検査し、大文字hexだけを小文字へ正規化する。
	for( const wchar_t character : hash) {
		// ASCII数字とhex文字以外をJSONへ流さない。
		if( !((character >= L'0' && character <= L'9') || (character >= L'a' && character <= L'f') ||
			 (character >= L'A' && character <= L'F'))) {
			return std::nullopt ;
		}

		const wchar_t normalized = character >= L'A' && character <= L'F'
									   ? character + (L'a' - L'A')
									   : character ;	// 検査済みASCII範囲の正規化。
		result.push_back( static_cast<char>( normalized)) ;
	}

	return result ;
}

/**
 * @brief 全再検証完了後に合格INFのhashだけを研究用JSONとして出す。
 * @param[in] inspection 固定archiveと個別合格閉包を所有する検査結果。
 * @return 内部整合と出力flush成功ならtrue。部分JSONを合格結果としない。
 * @note INF出現ごとに閉包のhashを読む。並び順やpathを外部のIDへ結合しない。
 */
[[nodiscard]] bool exportInspectionEvidence(
	const drivercrate::CommonDriverPackageInspection &inspection)
{
	const auto archiveHash = narrowHash( inspection.archiveSha256) ;	// 固定入力の内容identity。
	// 全体失敗と欠損identityを研究用合格へ昇格させない。
	if( inspection.error != 0 || !archiveHash.has_value()) {
		return false ;
	}

	std::string rows ;			// 全整合確認後に一度だけstdoutへ出す個別列。
	std::size_t verified{} ;	// 再検証済みのINF出現数。固有hash数ではない。
	// 合格閉包だけを列挙し、各選択INFに一致する唯一の内容entryを要求する。
	for( const drivercrate::CommonInfInspection &inf : inspection.infs) {
		// 拒否INFには内容hashの合格証拠を生成しない。
		if( inf.state != drivercrate::CommonInfInspectionState::VERIFIED) {
			continue ;
		}

		std::optional<std::string> infHash ;	// Pathはscope内照合だけに使う。
		// 閉包entryから選択INFのhashを取り、曖昧な重複entryを拒否する。
		for( const drivercrate::OfficialZipEntry &entry : inf.closure.entries) {
			// 関係ないCATやSYSのhashをINF hashとして出さない。
			if( entry.relativePath == inf.infRelativePath) {
				// 唯一のINF entryだけを受理する。
				if( infHash.has_value()) {
					return false ;
				}

				infHash = narrowHash( entry.sha256) ;
			}
		}

		// 成功閉包の契約不一致を出力で補完しない。
		if( !infHash.has_value() || inf.error != 0 || inf.closure.packages.size() != 1U ||
		   inf.closure.archiveDepth > 1U) {
			return false ;
		}

		// 同一hashの複数出現も別の閉包観測として保持する。
		if( verified != 0U) {
			rows += ',' ;
		}

		rows += "{\"infSha256\":\"" + *infHash + "\",\"hasExternalDependencies\":" ;
		rows += inf.closure.packages.front().hasExternalDependencies ? "true" : "false" ;
		rows += ",\"archiveDepth\":" + std::to_string( inf.closure.archiveDepth) + "}" ;
		++verified ;
	}

	// 合格0件を内容証拠として返さない。
	if( verified == 0U) {
		return false ;
	}

	const std::string output =
		"{\"schema\":\"dc-native-inf-content-observation-v1\",\"archiveSha256\":\"" + *archiveHash +
		"\",\"archiveBytes\":" + std::to_string( inspection.archiveBytes) +
		",\"osBuild\":" + std::to_string( drivercrate::currentWindowsBuildNumber()) +
		",\"infCount\":" + std::to_string( inspection.infs.size()) +
		",\"verifiedInfCount\":" + std::to_string( verified) +
		",\"rejectedInfCount\":" + std::to_string( inspection.infs.size() - verified) +
		",\"verifiedInfs\":[" + rows + "]}\n" ;	// 内容同一性と個数だけの公開前研究観測。
	return std::printf( "%s", output.c_str()) >= 0 && std::fflush( stdout) == 0 ;
}

/**
 * @brief 保守評価の有限enumを固定のJSON文字列へ変換する。
 * @param[in] state 保守用の一軸状態。
 * @return 四つの固定識別子。未定義値はINVALID。
 */
const char *maintenanceStateName( const drivercrate::MaintenanceInspectionState state) noexcept
{
	// 有限状態だけを出し、任意文字列やpathを出力しない。
	switch( state) {
		case drivercrate::MaintenanceInspectionState::NOT_CHECKED:	// 未検査を不適合としない。
			return "NOT_CHECKED" ;
		case drivercrate::MaintenanceInspectionState::PASSED:	// この一軸だけの通過。
			return "PASSED" ;
		case drivercrate::MaintenanceInspectionState::FAILED:	// 実施した検査の失敗。
			return "FAILED" ;
		case drivercrate::MaintenanceInspectionState::UNSUPPORTED:	// 現経路の方式未対応。
			return "UNSUPPORTED" ;
		default:	// 不正enumを既知状態に変換しない。
			return "INVALID" ;
	}
}

/**
 * @brief 一軸状態とHRESULTをpathなしJSONへ変換する。
 * @param[in] finding 検査器が保持する一軸結果。
 * @return 状態と診断値だけのJSON object。
 */
std::string maintenanceFindingJson( const drivercrate::MaintenanceInspectionFinding &finding)
{
	return "{\"state\":\"" + std::string( maintenanceStateName( finding.state)) +
		   "\",\"error\":" + std::to_string( finding.error) + "}" ;
}

/**
 * @brief 保守専用の非実行結果を四軸JSONとして出力する。
 * @param[in] archivePath 明示された元archiveの絶対local path。
 * @return 全評価と出力完了0、全体失敗1。個別合格0でも評価完了と合格を混同しない。
 * @note 実device列挙・導入は行わず、元byteに結んだ内容hashだけを保持する。
 */
int inspectMaintenanceArchive( const std::wstring_view archivePath)
{
	constexpr drivercrate::ScanSessionId SESSION = 4102U ;				// この明示一回だけのsession。
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// 同一MTAで署名APIを使う。
	// 初期化失敗を検査可能としない。
	if( FAILED( apartment.result())) {
		return 1 ;
	}

	drivercrate::OfficialDownloadWorkspace	 workspace ;	// 元copyだけを最後まで所有する。
	drivercrate::DriverArchiveInput			 input ;		// 固定内容identity。
	drivercrate::OfficialDriverArchiveFormat format{} ;		// Copyが確定する非実行形式。
	const drivercrate::NativeError			 copyError = drivercrate::copyLocalDriverArchive(
		  archivePath, SESSION, workspace, input, format) ;	// 従来と同じ入力境界。
	// 元file直読みや実行へfallbackしない。
	if( copyError != 0) {
		std::fprintf( stderr, "Copy error=0x%08X\n", copyError) ;
		return 1 ;
	}

	drivercrate::MaintenanceDriverPackageInspection result ;	// 導入用結果と互換でない。
	const drivercrate::NativeError					error =
		// 有限四軸評価。
		drivercrate::inspectMaintenanceDriverPackage( input, format, result) ;
	const auto archiveHash = narrowHash( result.archiveSha256) ;	// 元identityのASCII表記。
	// 全体失敗では部分JSONを合格として返さない。
	if( error != 0 || !archiveHash) {
		std::fprintf( stderr, "Assessment error=0x%08X\n", error) ;
		return 1 ;
	}

	std::string rows ;			// 個別失敗を含む全INF。IDとpathを含めない。
	std::size_t verified{} ;	// 内容署名だけの合格数。
	// 各独立findingを出し、未検査を0件不適合へ変換しない。
	for( const drivercrate::MaintenanceInfInspection &inf : result.infs) {
		const auto hash = inf.infSha256.empty()
							  ? std::optional<std::string>{}
							  : narrowHash( inf.infSha256) ;	// 未解析ならhashなしのまま保持する。
		// 内部hash不整合を出力で補完しない。
		if( !inf.infSha256.empty() && !hash) {
			return 1 ;
		}

		// 全INFの順序を維持する。
		if( !rows.empty()) {
			rows += ',' ;
		}

		rows += "{\"infSha256\":" + (hash ? "\"" + *hash + "\"" : "null") +
				",\"archiveDepth\":" + std::to_string( inf.archiveDepth) +
				",\"parser\":" + maintenanceFindingJson( inf.parser) +
				",\"integrity\":" + maintenanceFindingJson( inf.integrity) +
				",\"applicability\":" + maintenanceFindingJson( inf.applicability) +
				",\"installRoute\":" + maintenanceFindingJson( inf.installRoute) +
				",\"dependenciesChecked\":" + (inf.dependenciesChecked ? "true" : "false") +
				",\"hasExternalDependencies\":" + (inf.hasExternalDependencies ? "true" : "false") +
				",\"inspectedBytes\":" + std::to_string( inf.inspectedBytes) + "}" ;
		// 合格数は内容署名軸だけで決め、導入可能数とは扱わない。
		if( inf.integrity.state == drivercrate::MaintenanceInspectionState::PASSED) {
			++verified ;
		}
	}

	// 全軸と件数をまとめて出力し、部分的なJSONを合格証拠にしない。
	const std::string output =
		"{\"schema\":\"dc-maintenance-package-assessment-v1\","
		"\"researchOnly\":true,\"publishable\":false,\"installAuthorized\":false,\"archiveSha256\":\"" +
		*archiveHash + "\",\"archiveBytes\":" + std::to_string( result.archiveBytes) +
		",\"osBuild\":" + std::to_string( drivercrate::currentWindowsBuildNumber()) +
		",\"parser\":" + maintenanceFindingJson( result.parser) +
		",\"inventoryFileCount\":" + std::to_string( result.inventoryFileCount) +
		",\"infCount\":" + std::to_string( result.infs.size()) +
		",\"contentVerifiedInfCount\":" + std::to_string( verified) +
		",\"inspectedBytes\":" + std::to_string( result.inspectedBytes) + ",\"infs\":[" + rows +
		"]}\n" ;
	return std::printf( "%s", output.c_str()) >= 0 && std::fflush( stdout) == 0 ? 0 : 1 ;
}

/**
 * @brief 保守内容構造を固定文字列へ変換する。
 * @param[in] kind 構造検査で観測した内容区分。
 * @return 定義済み区分の固定文字列。未定義値はnullptr。
 */
[[nodiscard]] const char *maintenanceContentKindName(
	const drivercrate::MaintenanceInfContentKind kind) noexcept
{
	// UNKNOWNを有効な未確定観測として保持し、不正enumとは区別する。
	switch( kind) {
		case drivercrate::MaintenanceInfContentKind::UNKNOWN:	// 未確定を合格へ昇格しない。
			return "UNKNOWN" ;
		case drivercrate::MaintenanceInfContentKind::PACKAGE_FILES:	// Package内fileの構造。
			return "PACKAGE_FILES" ;
		case drivercrate::MaintenanceInfContentKind::NULL_DRIVER:	// 限定したnull構造。
			return "NULL_DRIVER" ;
		case drivercrate::MaintenanceInfContentKind::INBOX_DEPENDENCY:	// 別検査済みinbox由来。
			return "INBOX_DEPENDENCY" ;
		case drivercrate::MaintenanceInfContentKind::MIXED:	// 複数構造の混在。
			return "MIXED" ;
		default:	// 不正値をUNKNOWNで補完しない。
			return nullptr ;
	}
}

/**
 * @brief 参照coverageを固定文字列へ変換する。
 * @param[in] coverage 実byteへ結合した全必要参照の確認状態。
 * @return 定義済み状態の固定文字列。未定義値はnullptr。
 */
[[nodiscard]] const char *maintenanceReferenceCoverageName(
	const drivercrate::MaintenanceInfReferenceCoverage coverage) noexcept
{
	// 未検査と検査済みの不完全を混同しない。
	switch( coverage) {
		case drivercrate::MaintenanceInfReferenceCoverage::NOT_CHECKED:	// 全参照は未検査。
			return "NOT_CHECKED" ;
		case drivercrate::MaintenanceInfReferenceCoverage::COMPLETE:	// 全必要byteを結合済み。
			return "COMPLETE" ;
		case drivercrate::MaintenanceInfReferenceCoverage::INCOMPLETE:	// 未追跡・欠落等が残る。
			return "INCOMPLETE" ;
		default:	// 不正値を未検査へ丸めない。
			return nullptr ;
	}
}

/**
 * @brief 依存summaryの状態を固定文字列へ変換する。
 * @param[in] state 同一OS観測の依存状態。
 * @return 定義済み状態の固定文字列。未定義値はnullptr。
 */
[[nodiscard]] const char *maintenanceDependencyStateName(
	const drivercrate::MaintenanceInfDependencyState state) noexcept
{
	// 棚卸し・観測・照会完了を独立した状態として保持する。
	switch( state) {
		case drivercrate::MaintenanceInfDependencyState::NOT_CHECKED:	// 棚卸しまたは照会未実施。
			return "NOT_CHECKED" ;
		case drivercrate::MaintenanceInfDependencyState::NONE:	// 明示依存なしを棚卸し済み。
			return "NONE" ;
		case drivercrate::MaintenanceInfDependencyState::OBSERVED:	// 明示参照だけを観測済み。
			return "OBSERVED" ;
		case drivercrate::MaintenanceInfDependencyState::UNRESOLVED:	// 照会済みで未解決。
			return "UNRESOLVED" ;
		case drivercrate::MaintenanceInfDependencyState::
			RESOLVED_CURRENT_OS:	// 同OSの辺を検証済み。
			return "RESOLVED_CURRENT_OS" ;
		default:	// 不正値を不在または解決へ昇格しない。
			return nullptr ;
	}
}

/**
 * @brief 依存の保留理由を固定文字列へ変換する。
 * @param[in] reason 依存検査器が保持する元理由。
 * @return 定義済み理由の固定文字列。未定義値はnullptr。
 */
[[nodiscard]] const char *maintenanceDependencyReasonName(
	const drivercrate::InfDependencyReason reason) noexcept
{
	// 理由と元errorを独立して出し、状態から理由を推測しない。
	switch( reason) {
		case drivercrate::InfDependencyReason::NONE:	// 保留理由なし。
			return "NONE" ;
		case drivercrate::InfDependencyReason::NOT_CHECKED:	// 当該照会未実施。
			return "NOT_CHECKED" ;
		case drivercrate::InfDependencyReason::MISSING:	// 照会済みで未発見。
			return "MISSING" ;
		case drivercrate::InfDependencyReason::AMBIGUOUS:	// 一意に結合できない。
			return "AMBIGUOUS" ;
		case drivercrate::InfDependencyReason::CYCLE:	// 再帰中の循環。
			return "CYCLE" ;
		case drivercrate::InfDependencyReason::EVIDENCE_INCOMPLETE:	// byte・由来・署名の確認不足。
			return "EVIDENCE_INCOMPLETE" ;
		case drivercrate::InfDependencyReason::INVALID_NAME:	// 元参照名が不正。
			return "INVALID_NAME" ;
		default:	// 不正enumを既知の理由に変換しない。
			return nullptr ;
	}
}

/**
 * @brief 独立観測の全enumとhashを検査し、公開前研究用JSONを構築する。
 * @param[in] inspection 元archiveと全INFの独立した保守観測。
 * @return 全整合確認済みJSON。不正hash・enum・全体失敗なら空のoptional。
 * @note 全rowを保持し、元errorを状態から補完しない。ID・file名・pathは受け取らない。
 */
[[nodiscard]] std::optional<std::string> maintenanceObservationJson(
	const drivercrate::MaintenanceDriverPackageInspection &inspection)
{
	const auto archiveHash = narrowHash( inspection.archiveSha256) ;	// 固定入力の内容identity。
	// 全体失敗と未定義状態のJSONを出力しない。
	if( inspection.error != 0 || !archiveHash ||
	   std::string_view( maintenanceStateName( inspection.parser.state)) == "INVALID") {
		return std::nullopt ;
	}

	std::string rows ;		// 不正値を一つでも見つけた場合は全列を破棄する。
	std::size_t passed{} ;	// 全integrity軸の通過数。導入可能数ではない。
	// 不合格・未検査も含む全rowを同じ順序で保持する。
	for( const drivercrate::MaintenanceInfInspection &inf : inspection.infs) {
		const auto	hash		= inf.infSha256.empty() ? std::optional<std::string>{}
														: narrowHash( inf.infSha256) ;	// 未解析hashはnull。
		const char *contentKind = maintenanceContentKindName( inf.contentKind) ;		// 固定構造名。
		const char *coverage =
			// 固定確認名。
			maintenanceReferenceCoverageName( inf.referenceCoverage) ;
		const char *dependencyState =
			// 固定依存名。
			maintenanceDependencyStateName( inf.dependency.state) ;
		const char *dependencyReason =
			// 元理由。
			maintenanceDependencyReasonName( inf.dependency.reason) ;
		// 定義済み未検査は許可し、未定義enumと不正な非空hashだけを拒否する。
		if( (!inf.infSha256.empty() && !hash) || contentKind == nullptr || coverage == nullptr ||
		   dependencyState == nullptr || dependencyReason == nullptr ||
		   std::string_view( maintenanceStateName( inf.parser.state)) == "INVALID" ||
		   std::string_view( maintenanceStateName( inf.rootIntegrity.state)) == "INVALID" ||
		   std::string_view( maintenanceStateName( inf.integrity.state)) == "INVALID" ||
		   std::string_view( maintenanceStateName( inf.applicability.state)) == "INVALID" ||
		   std::string_view( maintenanceStateName( inf.installRoute.state)) == "INVALID") {
			return std::nullopt ;
		}

		// JSON区切りは二行目から付け、未解析rowも除外しない。
		if( !rows.empty()) {
			rows += ',' ;
		}

		rows +=
			"{\"infSha256\":" + (hash ? "\"" + *hash + "\"" : "null") +
			",\"archiveDepth\":" + std::to_string( inf.archiveDepth) +
			",\"parser\":" + maintenanceFindingJson( inf.parser) + ",\"contentKind\":\"" +
			contentKind + "\",\"referenceCoverage\":\"" + coverage +
			"\",\"rootIntegrity\":" + maintenanceFindingJson( inf.rootIntegrity) +
			",\"fullIntegrity\":" + maintenanceFindingJson( inf.integrity) +
			",\"dependency\":{\"state\":\"" + dependencyState + "\",\"reason\":\"" +
			dependencyReason + "\",\"error\":" + std::to_string( inf.dependency.error) +
			",\"observedReferenceCount\":" + std::to_string( inf.dependency.observedReferenceCount) +
			",\"resolvedInfCount\":" + std::to_string( inf.dependency.resolvedInfCount) + "}" +
			",\"applicability\":" + maintenanceFindingJson( inf.applicability) +
			",\"installRoute\":" + maintenanceFindingJson( inf.installRoute) +
			",\"dependenciesChecked\":" + (inf.dependenciesChecked ? "true" : "false") +
			",\"hasExternalDependencies\":" + (inf.hasExternalDependencies ? "true" : "false") +
			",\"inspectedBytes\":" + std::to_string( inf.inspectedBytes) + "}" ;
		// 全integrityの通過だけを数え、root署名や依存解決で代用しない。
		if( inf.integrity.state == drivercrate::MaintenanceInspectionState::PASSED) {
			++passed ;
		}
	}

	return "{\"schema\":\"dc-maintenance-package-observation-v2\","
		   "\"researchOnly\":true,\"publishable\":false,\"installAuthorized\":false,\"archiveSha256\":\"" +
		   *archiveHash + "\",\"archiveBytes\":" + std::to_string( inspection.archiveBytes) +
		   ",\"osBuild\":" + std::to_string( drivercrate::currentWindowsBuildNumber()) +
		   ",\"error\":" + std::to_string( inspection.error) +
		   ",\"parser\":" + maintenanceFindingJson( inspection.parser) +
		   ",\"inventoryFileCount\":" + std::to_string( inspection.inventoryFileCount) +
		   ",\"infCount\":" + std::to_string( inspection.infs.size()) +
		   ",\"fullIntegrityPassedInfCount\":" + std::to_string( passed) +
		   ",\"inspectedBytes\":" + std::to_string( inspection.inspectedBytes) + ",\"infs\":[" +
		   rows + "]}\n" ;
}

/**
 * @brief 新modeだけで構造・参照・署名・依存の独立観測を出力する。
 * @param[in] archivePath 明示された元archiveの絶対local path。
 * @return 評価と全JSON出力完了0、全体検査・内部整合・出力失敗1。
 * @note 評価完了は内容合格ではない。通常候補・端末照合・導入へ接続しない。
 */
int inspectMaintenanceObservationArchive( const std::wstring_view archivePath)
{
	constexpr drivercrate::ScanSessionId SESSION = 4103U ;					// 新modeの明示一回だけのsession。
	const drivercrate::ComApartment		 apartment( COINIT_MULTITHREADED) ;	// 同一MTAの署名検査。
	// COM初期化失敗を評価完了として出力しない。
	if( FAILED( apartment.result())) {
		return 1 ;
	}

	drivercrate::OfficialDownloadWorkspace	 workspace ;	// 元byteの保護copyを最後まで所有する。
	drivercrate::DriverArchiveInput			 input ;		// Copyが確定する固定入力identity。
	drivercrate::OfficialDriverArchiveFormat format{} ;		// 非実行のarchive形式。
	const drivercrate::NativeError			 copyError = drivercrate::copyLocalDriverArchive(
		  archivePath, SESSION, workspace, input, format) ;	// 既存と同じ入力境界。
	// 元archive直読や別形式へのfallbackを行わない。
	if( copyError != 0) {
		std::fprintf( stderr, "Copy error=0x%08X\n", copyError) ;
		return 1 ;
	}

	drivercrate::MaintenanceDriverPackageInspection result ;	// 導入用DTOでない独立観測。
	const drivercrate::NativeError					error =
		// 既存の有限評価。
		drivercrate::inspectMaintenanceDriverPackage( input, format, result) ;
	// 全体評価失敗を個別結果のJSONとして公開しない。
	if( error != 0) {
		std::fprintf( stderr, "Observation error=0x%08X\n", error) ;
		return 1 ;
	}

	const auto output = maintenanceObservationJson( result) ;	// 出力前に全hash・enumを確認する。
	// 内部不整合でもpathや例外本文を診断へ混入させない。
	if( !output) {
		std::fprintf( stderr, "Observation serialization failed.\n") ;
		return 1 ;
	}

	return std::printf( "%s", output->c_str()) >= 0 && std::fflush( stdout) == 0 ? 0 : 1 ;
}

// 同じCLI sourceから研究EXE内だけの明示modeを作る。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
/** @brief 元loop一回のv2と同scope最終参照を別新規sidecarへ結ぶ。
 * @param[in] archivePath 元二ZIPの明示絶対path。
 * @param[in] sidecarPath Runnerが固定した新53の絶対保存先。
 * @param[in] runId 有限ASCII run識別子。
 * @param[in] mode CLIで検査済みの元53または新54研究mode。
 * @return 元評価・独立計測・全出力成功0、それ以外1。
 */
int inspectReachedObservationArchive( const std::wstring_view				 archivePath,
									 const std::wstring_view				 sidecarPath,
									 const std::wstring_view				 runId,
									 const drivercrate::ReachedReferenceMode mode)
{
	// 引数を本文・path・tokenへ拡張せず有限ASCIIへ限定する。
	if( runId.empty() || runId.size() > 64U || !std::ranges::all_of( runId, []( const wchar_t value) {
		   return (value >= L'a' && value <= L'z') || (value >= L'0' && value <= L'9') ||
				  value == L'-' ;
	   })) { // 引数借用は本呼出し中だけ。
		return 1 ;
	}

	std::string id ;	// 検証済みASCIIだけ。
	// 値域確認済み文字を明示変換し、暗黙narrowingを残さない。
	for( const wchar_t value : runId) {
		id.push_back( static_cast<char>( value)) ;
	}

	constexpr drivercrate::ScanSessionId SESSION = 4103U ;					// 元v2と同一のsession契約。
	const drivercrate::ComApartment		 apartment( COINIT_MULTITHREADED) ;	// 元署名処理の同MTA。
	// 元COM失敗を観測の成功へ変換しない。
	if( FAILED( apartment.result())) {
		return 1 ;
	}

	drivercrate::OfficialDownloadWorkspace	 workspace ;	// 元固定copyの所有者。
	drivercrate::DriverArchiveInput			 input ;		// 同run内容identity。
	drivercrate::OfficialDriverArchiveFormat format{} ;		// 元非実行形式。
	const auto copyError = drivercrate::copyLocalDriverArchive( archivePath, SESSION, workspace,
															   input, format) ;	// 元保護取込み。
	// 元copy失敗では部分観測を出さない。
	if( copyError != 0) {
		std::fprintf( stderr, "Copy error=0x%08X\n", copyError) ;
		return 1 ;
	}

	drivercrate::MaintenanceDriverPackageInspection result ;	// 通常v2の同一DTO。
	drivercrate::ReachedReferenceCollector collector( mode) ;	// この一同期scopeだけの具体的所有者。
	const auto error = drivercrate::inspectReachedMaintenanceDriverPackage(
		input, format, result, collector) ;	// 各INF extract一回だけ。
	// 元失敗は元HRESULTを保持して空出力にする。
	if( error != 0) {
		std::fprintf( stderr, "Observation error=0x%08X\n", error) ;
		return 1 ;
	}

	const auto output = maintenanceObservationJson( result) ;	// 本文・schemaを変えない元serializer。
	// 独立計測不整合を元判定の合格へ混入させない。
	if( !output || collector.error() != 0 || output->empty() || output->back() != '\n') {
		std::fprintf( stderr, "Reached observation measurement failed.\n") ;
		return 1 ;
	}

	std::string bytes = *output ;	// 元CRT text modeが送った終端CRLFを一度だけ確定する。
	bytes.pop_back() ;
	bytes += "\r\n" ;
	const auto sidecar = collector.serialize( id, result, bytes) ;	// 実送信全byteのCNG hashへ結ぶ。
	// 全serializationと共同上限成功前にはfileを作らない。
	if( !sidecar) {
		std::fprintf( stderr, "Reached observation serialization failed.\n") ;
		return 1 ;
	}

	const auto writeError = drivercrate::writeReachedReferenceSidecar(
		sidecarPath, id, *sidecar, mode) ;	// modeごとの正確な新規保存先だけ。
	// 部分fileは上書き・再送せずrunner receiptで未受入にする。
	if( writeError != 0) {
		std::fprintf( stderr, "Sidecar error=0x%08X\n", writeError) ;
		return 1 ;
	}

	return drivercrate::writeReachedReferenceStdout( bytes) == 0 ? 0 : 1 ;
}
#endif

/**
 * @brief 従来modeの共通検査と明示端末照合を実行する。
 * @param[in] archivePath 明示元archiveのlocal絶対path。
 * @param[in] matchPresent trueの場合だけ端末を列挙する。
 * @param[in] exportEvidence trueの場合は従来schemaの合格hashを出力する。
 * @return 従来内容検査と再検証に合格した場合0、それ以外1。
 */
int inspectArchive( const std::wstring_view archivePath, const bool matchPresent,
				   const bool exportEvidence)
{
	constexpr drivercrate::ScanSessionId SESSION = 4101U ;				// この一回実行だけのsession。
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// 全APIを同じMTAで使用する。
	// COM初期化に失敗した環境を検査可能としない。
	if( FAILED( apartment.result())) {
		std::printf( "COM error=0x%08X\n", static_cast<unsigned int>( apartment.result())) ;
		return 1 ;
	}

	drivercrate::OfficialDownloadWorkspace	 inputWorkspace ;	// 閉包より長く生存する保護copy。
	drivercrate::DriverArchiveInput			 input ;			// 内容identityだけを保持する。
	drivercrate::OfficialDriverArchiveFormat format{} ;			// Copy成功時に確定する形式。
	drivercrate::NativeError				 error = drivercrate::copyLocalDriverArchive(
		archivePath, SESSION, inputWorkspace, input, format) ;	// Productionと同じ有限取込み。
	// Copy失敗時は元archiveを直接検査するfallbackを行わない。
	if( error != 0) {
		std::printf( "Copy error=0x%08X\n", error) ;
		return 1 ;
	}

	drivercrate::CommonDriverPackageInspection inspection ;	// Scope内だけの全INF結果。
	error = drivercrate::inspectCommonDriverPackage( input, format, inspection) ;
	// 従来modeでは集計を保持し、証拠modeの成功出力はJSONだけに限定する。
	if( !exportEvidence || error != 0) {
		std::printf( "Inspection error=0x%08X files=%zu infs=%zu retained=%llu os_build=%u\n", error,
					inspection.inventoryFileCount, inspection.infs.size(),
					static_cast<unsigned long long>( inspection.retainedBytes),
					drivercrate::currentWindowsBuildNumber()) ;
	}

	// 全体エラーでは部分内容を合格扱いにしない。
	if( error != 0) {
		return 1 ;
	}

	std::size_t verified{} ;	// 実署名と再検証の合格INF数。
	std::size_t rejected{} ;	// 個別の閉包または署名拒否数。
	std::size_t infIndex{} ;	// Pathに代わるこの出力内だけの連番。
	// 全INFの個別結果を記録し、合格した閉包は同じpolicyで再検証する。
	for( const drivercrate::CommonInfInspection &inf : inspection.infs) {
		++infIndex ;
		// 証拠modeは合格hashだけを全再検証後にまとめて出す。
		if( !exportEvidence) {
			std::printf( "INF=%zu state=%u error=0x%08X\n", infIndex,
						static_cast<unsigned int>( inf.state), inf.error) ;
		}

		// 拒否されたINFを再検証やdevice照合へ渡さない。
		if( inf.state != drivercrate::CommonInfInspectionState::VERIFIED) {
			++rejected ;
			continue ;
		}

		error = drivercrate::reverifyCommonDriverInf( inf) ;
		// 検査後の差替えや署名失敗を破棄して照合を続けない。
		if( error != 0) {
			std::printf( "Reverify INF=%zu error=0x%08X\n", infIndex, error) ;
			return 1 ;
		}

		++verified ;
	}

	// 従来の内容集計は証拠mode以外で保持する。
	if( !exportEvidence) {
		std::printf( "Content verified=%zu rejected=%zu\n", verified, rejected) ;
	}

	// 全拒否は「driverなし」や内容合格ではなく、live検査の不合格として残す。
	if( verified == 0) {
		return 1 ;
	}

	// 内容証拠を明示した実行ではdevice inventoryを一切読まない。
	if( exportEvidence) {
		return exportInspectionEvidence( inspection) ? 0 : 1 ;
	}

	// Device読取りを明示しなかった実行ではinventory APIを呼ばない。
	if( !matchPresent) {
		return 0 ;
	}

	drivercrate::DriverStoreProvider provider ;	// Native IDを同一threadの内部mapだけに保持する。
	const drivercrate::ProviderProgressCallback progress =
		[]( const drivercrate::ProviderProgress &) {
		} ; // 進捗契約を満たす非捕捉callback。機器情報を出力しない。
	const drivercrate::ScanResult inventory =
		// 非導入のlocal列挙。
		provider.scan( SESSION, {}, progress) ;
	// Inventory失敗は適合0件へ縮小しない。
	if( !inventory.succeeded || inventory.error != 0) {
		std::printf( "Inventory error=0x%08X\n", inventory.error) ;
		return 1 ;
	}

	std::set<std::wstring> deviceIdentities ;	// 出力しないopaque device集合。
	// 現在行のdeviceを一意化し、過去版行を重複照合しない。
	for( const drivercrate::UpdateCandidate &candidate : inventory.candidates) {
		// 有効な現在代表行だけを照合に用いる。
		if( candidate.current && !candidate.deviceIdentity.empty()) {
			deviceIdentities.insert( candidate.deviceIdentity) ;
		}
	}

	std::size_t			   pairs{} ;		// Windowsへ照合済みの組合せ数。
	std::size_t			   matches{} ;		// 一致したINFとdeviceの組合せ数。
	std::size_t			   failures{} ;		// 一致なしとは別のWindows API失敗数。
	std::set<std::wstring> matchedDevices ;	// 複数INF間で重複しないdevice数だけを出力する。
	infIndex = 0 ;
	// 合格INFごとに全present代表行を有限回照合する。
	for( const drivercrate::CommonInfInspection &inf : inspection.infs) {
		++infIndex ;
		// 個別拒否は照合によって署名合格へ昇格させない。
		if( inf.state != drivercrate::CommonInfInspectionState::VERIFIED) {
			continue ;
		}

		std::size_t infMatches{} ;	// このINFと一致したdevice件数。
		// 端末内のopaque identityだけをWindows観測へ渡す。
		for( const std::wstring &identity : deviceIdentities) {
			// 上限に達したら未検査部分を正常終了として隠さない。
			if( pairs >= 32768U) {
				std::printf( "Matching pair limit reached.\n") ;
				return 1 ;
			}

			++pairs ;
			std::optional<std::uint32_t> rank ;	// Windowsが返した一致nodeだけを保持する。
			error = provider.observeInfCandidateRank( SESSION, identity, *inf.workspace,
													 inf.closure.packages.front(), rank) ;
			// API失敗は不適合と区別して最終結果を失敗にする。
			if( error != 0) {
				++failures ;
			}
			// Windowsの一致nodeがある場合だけ件数へ加える。
			else if( rank.has_value()) {
				++matches ;
				++infMatches ;
				matchedDevices.insert( identity) ;
			}
		}

		// 一致したINFだけの連番と件数を示し、生IDと表示名は出力しない。
		if( infMatches != 0) {
			std::printf(
				"Matching INF=%zu devices=%zu dependencies=%u\n", infIndex, infMatches,
				static_cast<unsigned int>( inf.closure.packages.front().hasExternalDependencies)) ;
		}
	}

	std::printf( "Matching devices=%zu pairs=%zu matched_pairs=%zu matched_devices=%zu errors=%zu\n",
				deviceIdentities.size(), pairs, matches, matchedDevices.size(), failures) ;
	return failures == 0 ? 0 : 1 ;
}

} // namespace

/**
 * @brief 明示optionとlocal pathが揃った場合だけread-only実検査を開始する。
 * @param[in] argumentCount 実行名を含む引数数。
 * @param[in] arguments 明示検査modeと元archive絶対path。
 * @return 検査成功または保守評価出力完了0、検査失敗1、引数不正2、例外3。
 * @note 引数不正時に実fileやdeviceを読まず、例外本文に含まれ得るpathを出力しない。
 */
int wmain( const int argumentCount, wchar_t *arguments[])
{
// 研究EXEは明示新modeだけを受理し、通常modeへfallbackしない。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
	// 引数不正ではarchiveを読み取らず有限契約を拒否する。
	if( argumentCount != 5 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[2] == nullptr || arguments[3] == nullptr || arguments[4] == nullptr ||
	   (std::wstring_view( arguments[1]) != L"--maintenance-reached-observation" &&
		std::wstring_view( arguments[1]) != L"--maintenance-residual-observation")) {
		return 2 ;
	}

	try {
		const auto mode = std::wstring_view( arguments[1]) == L"--maintenance-residual-observation"
							  ? drivercrate::ReachedReferenceMode::RESIDUAL
							  : drivercrate::ReachedReferenceMode::REACHED ;	// 固定二modeだけ。
		return inspectReachedObservationArchive( arguments[2], arguments[3], arguments[4], mode) ;
	} catch( ...) {
		std::fprintf( stderr, "Reached observation aborted.\n") ;
		return 3 ;
	}
#else
	// 暗黙の既定path・全device読取り・導入modeを設けない。
	if( argumentCount != 3 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[2] == nullptr || arguments[2][0] == L'\0') {
		std::printf(
			"Usage: common_driver_package_smoke --inspect-only|--match-present|--inspect-evidence|--maintenance-evidence|--maintenance-observation <archive>\n") ;
		return 2 ;
	}

	const std::wstring_view mode( arguments[1]) ;	// 引数配列を呼出し中だけ借用する。
	// 未知optionで意図しないinventory読取りを開始しない。
	if( mode != L"--inspect-only" && mode != L"--match-present" && mode != L"--inspect-evidence" &&
	   mode != L"--maintenance-evidence" && mode != L"--maintenance-observation") {
		return 2 ;
	}

	try {
		// 新schemaも保守用評価だけを使い、端末照合へfallbackしない。
		if( mode == L"--maintenance-observation") {
			return inspectMaintenanceObservationArchive( arguments[2]) ;
		}

		// 保守用型だけを使用し、端末照合や既存導入結果へ接続しない。
		if( mode == L"--maintenance-evidence") {
			return inspectMaintenanceArchive( arguments[2]) ;
		}

		return inspectArchive( arguments[2], mode == L"--match-present",
							  mode == L"--inspect-evidence") ;
	} catch( ...) {
		std::printf( "Read-only inspection aborted by an exception.\n") ;
		return 3 ;
	}
#endif
}
