//------------------------------------------------------------------------------
/**
 * @file maintenance_reached_reference_observation.cpp
 * @brief 最終保守参照の有限射影と同run sidecarの新規保存。
 * @version 01.01.02
 * @date 2026/10/08
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/08  最終closure借用・元診断と有限新規出力を実装。
 * Ver.01.01.00 Shunji Ogawa  2026/10/08  最終directive・作用gapの独立細分類と固定54保存を追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.01.02 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note stack collectorだけが同期借用します。名前は射影scopeの終了時に失われます。
 * 全seed因果・途中履歴・helper拒否細分は推測せずNOT_OBSERVEDへ残します。
 * @see docs/adr/0315-maintenance-reached-reference-observation-boundary.md
 */
//------------------------------------------------------------------------------

#include <vector>
#include "maintenance_reached_reference_observation.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <SetupAPI.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

// 通常platformに研究実装と保管workspaceを組み込まない。
#ifndef DRIVERCRATE_REACHED_REFERENCE_RESEARCH
#error This source requires the isolated reached reference research target.
#endif

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 研究射影の固定語と出力上限。
//------------------------------------------------------------------------------

constexpr std::size_t SIDECAR_BYTES = 1024U * 1024U ;									// 全packageのserialized上限。
constexpr std::size_t STDOUT_BYTES	= 256U * 1024U ;									// 元v2全byteの上限。
constexpr std::array  STATES{"NOT_CHECKED", "PASSED", "FAILED", "UNSUPPORTED"} ;		// 元状態。
constexpr std::array  COVERAGE{"NOT_CHECKED", "COMPLETE", "INCOMPLETE"} ;				// 元位置棚卸し。
constexpr std::array  LOCATIONS{"NOT_CHECKED", "LOCATED", "MISSING", "UNSUPPORTED"} ;	// 元位置。
constexpr std::array  ORIGINS{"PACKAGE", "SYSTEM"} ;									// 元境界。
constexpr std::array  EVIDENCE{"NOT_CHECKED", "VERIFIED", "FAILED"} ;					// 元独立証拠。
constexpr std::array  DIRECTIVES{"INCLUDE", "NEEDS"} ;									// 元辺種類。
constexpr std::array EDGE_STATES{"OBSERVED",	"RESOLVED_PACKAGE", "RESOLVED_SYSTEM", "UNRESOLVED",
								 "NOT_CHECKED", "INVALID_REFERENCE"} ;	// 元辺到達。
constexpr std::array REASONS{"NONE",  "NOT_CHECKED",		 "MISSING",		"AMBIGUOUS",
							 "CYCLE", "EVIDENCE_INCOMPLETE", "INVALID_NAME"} ;	// 元辺理由。
constexpr std::array READ_STATES{"NOT_CHECKED", "MISSING", "PRESENT"} ;			// 元節照会。
constexpr std::array GAP_KINDS{"UNFOLLOWED_SECTION_REFERENCES",
							   "UNFOLLOWED_SERVICE_EVENTLOG",
							   "SOFTWARE_INSTALLATION_NOT_ASSESSED",
							   "UNKNOWN_DIRECTIVE",
							   "DATA_ROWS_NOT_INTERPRETED",
							   "REGISTRY_SCOPE_NOT_ASSESSED"} ;	// readerの元enum順の固定語。

/** @brief append前に全serialized量を守る射影専用builder。 */
class ReachedJson	 final {
public:
	   /** @brief 固定語・検査済みhash・数だけを上限確認後に追加する。
	 * @param[in] value 任意の元file値を含まないbyte列。
	 * @throws std::length_error 全1 MiB上限を超える場合。
	 */
	   void add( const std::string_view value)
	   {
		   // 切捨てと分割で全package上限を回避しない。
		   if( value.size() > SIDECAR_BYTES - text.size()) {
			   throw std::length_error( "observation limit") ;
		   }

		   text.append( value) ;
	   }
	   /// 呼出し側へ移動する検証済み射影byte。
	   std::string text ;
} ;

/** @brief 未知enumを既存語へ変換せず拒否する。
 * @tparam Enum 元の固定enum型。
 * @tparam Count 固定語数。
 * @param[in] value 元値。
 * @param[in] names 順序が元enumと一致する固定語集合。
 * @return 既知の固定語。
 * @throws std::invalid_argument 未知enumの場合。
 */
template <typename Enum, std::size_t Count>
std::string_view enumName( const Enum value, const std::array<const char *, Count> &names)
{
	const auto index = static_cast<std::size_t>( value) ;	// 未知値は範囲外で拒否する。
	// 未知をNOT_CHECKED等へ補完しない。
	if( index >= Count) {
		throw std::invalid_argument( "observation enum") ;
	}

	return names[index] ;
}

/** @brief 原byte hashだけを安全なJSON文字列へ変換する。
 * @param[in] hash 空または小文字64桁hash。
 * @return 空ならnull、既知hashなら引用済みASCII。
 * @throws std::invalid_argument 不正な非空hashの場合。
 */
std::string hashJson( const std::wstring_view hash)
{
	// 元未解析のhashを捏造しない。
	if( hash.empty()) {
		return "null" ;
	}

	// 名前と任意本文をhash欄へ流さない。
	if( hash.size() != 64U || !std::ranges::all_of( hash, []( const wchar_t value) {
		   return (value >= L'0' && value <= L'9') || (value >= L'a' && value <= L'f') ;
	   })) { // 固定文字種だけを同期確認する。
		throw std::invalid_argument( "observation hash") ;
	}

	std::string result = "\"" ;	// 検証済みASCIIだけを明示的にnarrowingする。
	// 全64文字は文字種確認済みで、値を変えずにbyteへ変換する。
	for( const wchar_t value : hash) {
		result.push_back( static_cast<char>( value)) ;
	}

	result += '"' ;
	return result ;
}

/** @brief 有限run IDだけを許可する。
 * @param[in] runId Runnerが決めた識別子。
 * @return 1～64文字の小文字ASCII・数字・ハイフンならtrue。
 */
bool validRunId( const std::string_view runId) noexcept
{
	return !runId.empty() && runId.size() <= 64U &&
		   std::ranges::all_of( runId, []( const char value) {
			   return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
					  value == '-' ;
		   }) ; // 名前やpathを識別子として受理しない。
}

/** @brief 原HRESULTを元状態と組にした固定JSONへ変換する。
 * @param[in] finding 元独立判定。
 * @return 元stateとHRESULTだけのJSON。
 */
std::string findingJson( const MaintenanceInspectionFinding &finding)
{
	return "{\"state\":\"" + std::string( enumName( finding.state, STATES)) +
		   "\",\"error\":" + std::to_string( finding.error) + "}" ;
}

/** @brief 名前を保存せず、元全値同士の完全一致だけでopaque節IDを割り当てる。
 * @param[in,out] sections この参照scopeだけの非所有名前一覧。
 * @param[in] value 同期借用する原全値。
 * @return 空なら0、それ以外は1起点opaque ID。
 * @throws std::length_error 同scopeの4,096項目上限を超えた場合。
 */
std::size_t sectionId( std::vector<std::wstring_view> &sections, const std::wstring_view value)
{
	// 元空値を実在節へ補完しない。
	if( value.empty()) {
		return 0U ;
	}

	const auto found = std::ranges::find( sections, value) ;	// 大文字小文字も原全値のまま比較する。
	// 元全値が同じときだけ同IDを共有する。
	if( found != sections.end()) {
		return static_cast<std::size_t>( found - sections.begin()) + 1U ;
	}

	// 未保持の節名を切り捨てて成功としない。
	if( sections.size() >= 4096U) {
		throw std::length_error( "observation sections") ;
	}

	sections.push_back( value) ;
	return sections.size() ;
}

/** @brief readerが保持したdirectiveだけを固定用途へ分類する。
 * @param[in] file 元用途。原値を保存しない。
 * @return metadata／localの固定用途名。
 */
std::string_view useKind( const MaintenanceInfFileReference &file)
{
	// 欠落local節をbinary欠落と混同しない。
	if( file.error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND))) {
		return file.directive == L"SeedSection" ? "SEED_SECTION" : "LOCAL_SECTION_MISSING" ;
	}

	// 以下の明示既知語だけを保存し、未知directive本文を出さない。
	if( file.directive == L"INF") {
		return "INF" ;
	}

	// CAT自身のmetadataと実payload用途を区別する。
	if( file.directive == L"CatalogFile") {
		return "CAT" ;
	}

	// source全宣言は到達使用先とは別分母へ残す。
	if( file.directive == L"SourceDisksFiles") {
		return "SOURCE_DECLARATION" ;
	}

	// Queue外のVersion参照をlocal到達としない。
	if( file.directive == L"LayoutFile") {
		return "LAYOUT" ;
	}

	// named listの元source用途。
	if( file.directive == L"CopyFileSource") {
		return "COPY_SOURCE" ;
	}

	// readerが保持するCopyFiles用途は直接参照だけ。
	if( file.directive == L"CopyFiles") {
		return "DIRECT_COPY" ;
	}

	// SCM用途は服務名を保存せず固定語へ分ける。
	if( file.directive == L"ServiceBinary") {
		return "SERVICE_BINARY" ;
	}

	// UMDF binary用途を独立して残す。
	if( file.directive == L"UmdfServiceBinary") {
		return "UMDF_BINARY" ;
	}

	// Event-log binary用途を独立して残す。
	if( file.directive == L"EventMessageFile") {
		return "EVENT_MESSAGE" ;
	}

	// registryは全file用途を未評価として残す。
	if( file.directive == L"RegistryFileUsesNotAssessed" ||
	   file.directive == L"RegistryFileUseNotAssessed") {
		return "REGISTRY_FILE_USES_UNASSESSED" ;
	}

	return "OTHER_UNSUPPORTED_USE" ;
}

/** @brief 同INF内の保持済み節・directiveをreaderと同じWindows規則で比較する。
 * @param[in] left 同期借用の元値。
 * @param[in] right 同期借用の元値。
 * @return 大文字小文字を区別しない全文一致ならtrue。
 * @note 元opaque用途IDの割当て規則を変更せず、外部へ文字列を保存しない。
 */
bool residualEqual( const std::wstring_view left, const std::wstring_view right) noexcept
{
	// 空値同士は一致として扱うが、後続の対応は実在節を別に要求する。
	if( left.empty() || right.empty()) {
		return left.empty() && right.empty() ;
	}

	// Windows比較APIへ範囲外の長さをnarrowingしない。
	if( left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/** @brief 元用途を先に割当てた辞書へgapの節だけを追加する。
 * @param[in,out] sections 元用途のopaque順を保持する同参照の借用辞書。
 * @param[in] value 保持済みgapの元節。
 * @return 元節とのreader一致ID、なければ有限な追加ID。空は0。
 * @throws std::length_error 用途とgapの共同4,096節を超える場合。
 */
std::size_t gapSectionId( std::vector<std::wstring_view> &sections, const std::wstring_view value)
{
	// 既存用途の最初のopaque IDを優先し、case違いだけで別節を捏造しない。
	for( std::size_t index = 0U; index < sections.size(); ++index) {
		// readerの同節一致を用途側IDへ結ぶ。
		if( residualEqual( sections[index], value)) {
			return index + 1U ;
		}
	}

	return sectionId( sections, value) ;
}

/** @brief 保持済み用途とgapの対応範囲を固定し、行の因果を作らない。
 * @param[in] file 元用途。位置・HRESULTを再判定しない。
 * @param[in] gap 元の作用不足。
 * @return 同節のmarkerならSAME_SECTION_ONLY、同directiveならSAME_SECTION_DIRECTIVE_ONLY、他はNOT_OBSERVED。
 */
std::string_view residualGapBinding( const MaintenanceInfFileReference	&file,
									const OfficialInfInstallCoverageGap &gap) noexcept
{
	// 未保持の節と別節を推測で結ばない。
	if( file.section.empty() || !residualEqual( file.section, gap.section)) {
		return "NOT_OBSERVED" ;
	}

	// registryの全節markerとdata候補は行番号を持たず、節一致だけを許可する。
	if( (residualEqual( file.directive, L"RegistryFileUsesNotAssessed") ||
		residualEqual( file.directive, L"RegistryFileUseNotAssessed")) &&
	   gap.directive.empty() &&
	   gap.kind == OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED) {
		return "SAME_SECTION_ONLY" ;
	}

	// opaque data行も節全体gapとの対応に限定する。
	if( residualEqual( file.directive, L"DataRowsNotInterpreted") && gap.directive.empty() &&
	   gap.kind == OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED) {
		return "SAME_SECTION_ONLY" ;
	}

	// 既知不足と未知directiveを元kindまで検査し、矛盾した種類は結ばない。
	if( !file.directive.empty() && residualEqual( file.directive, gap.directive)) {
		constexpr std::array<std::wstring_view, 7U> UNFOLLOWED{
			L"AddProperty", L"DelProperty",		L"LogConfig", L"ProfileItems",
			L"UpdateInis",	L"UpdateIniFields", L"Ini2Reg"} ;	// readerが保持する未追跡七directive。
		const bool known = std::ranges::any_of( UNFOLLOWED, [&file]( const auto name) {
			return residualEqual( file.directive, name) ;
		}) ; // 名前を保存しない同期比較。
		// 対応する既知不足だけを全ordinalへ残す。
		if( (known && gap.kind == OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES) ||
		   (residualEqual( file.directive, L"AddService") &&
			gap.kind == OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG) ||
		   (residualEqual( file.directive, L"AddSoftware") &&
			gap.kind == OfficialInfInstallCoverageKind::SOFTWARE_INSTALLATION_NOT_ASSESSED) ||
		   (!known && !residualEqual( file.directive, L"AddService") &&
			!residualEqual( file.directive, L"AddSoftware") &&
			gap.kind == OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE)) {
			return "SAME_SECTION_DIRECTIVE_ONLY" ;
		}
	}

	return "NOT_OBSERVED" ;
}

/** @brief 元UNSUPPORTED用途を保持済みdirective・作用・参照の範囲だけで細分類する。
 * @param[in] file 元位置と元directive。値の形やHRESULTは分類根拠にしない。
 * @param[in] inventory 同INFの既存最終棚卸し。一回借用する。
 * @return 元UNSUPPORTED以外は空、根拠がある固定分類、根拠不足はOTHER_UNSUPPORTED_USE。
 */
std::string_view residualClassification( const MaintenanceInfFileReference &file,
										const OfficialInfInstallInventory &inventory)
{
	// metadata・成功・未検査・欠落を新しい未対応用途へ昇格させない。
	if( file.location != MaintenanceInfFileLocation::UNSUPPORTED) {
		return {} ;
	}

	// reader自身が保持した特殊markerの種類を値の見た目で補完しない。
	if( residualEqual( file.directive, L"RegistryFileUsesNotAssessed")) {
		return "REGISTRY_SCOPE_MARKER_UNASSESSED" ;
	}

	// registry data候補は実file用途の認定ではない。
	if( residualEqual( file.directive, L"RegistryFileUseNotAssessed")) {
		return "REGISTRY_DATA_FILE_CANDIDATE_UNASSESSED" ;
	}

	// 非解釈data行をpayloadの不在証明へ変換しない。
	if( residualEqual( file.directive, L"DataRowsNotInterpreted")) {
		return "OPAQUE_DATA_ROW_UNASSESSED" ;
	}

	// named構造不足の元固定markerをそのまま分ける。
	if( residualEqual( file.directive, L"NamedServiceStructureNotAssessed")) {
		return "NAMED_SERVICE_STRUCTURE_UNASSESSED" ;
	}

	// associated構成不足をbinary不足へ変換しない。
	if( residualEqual( file.directive, L"NamedServiceAssociationNotAssessed")) {
		return "NAMED_SERVICE_ASSOCIATION_UNASSESSED" ;
	}

	// 全一致gapの固定種類だけを利用し、最初の行を因果として採用しない。
	for( const auto &gap : inventory.coverageGaps) {
		// 対応なしと矛盾するgapは分類根拠へ使わない。
		if( residualGapBinding( file, gap) == "SAME_SECTION_DIRECTIVE_ONLY") {
			// 元enumから新分類への固定対応を使う。
			switch( gap.kind) {
				case OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES:
					// 保持済み未追跡参照。
					return "UNFOLLOWED_SECTION_REFERENCES" ;
				case OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG:
					// 第4 field未評価。
					return "UNFOLLOWED_SERVICE_EVENTLOG" ;
				case OfficialInfInstallCoverageKind::SOFTWARE_INSTALLATION_NOT_ASSESSED:
					// software作用未評価。
					return "SOFTWARE_INSTALLATION_UNASSESSED" ;
				case OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE:
					// 未知の元作用。
					return "UNKNOWN_DIRECTIVE_OR_FILE_SEMANTICS" ;
				default:
					// 節markerは上の固定分類へ限定する。
					break ;
			}
		}
	}

	const bool reference = std::ranges::any_of( inventory.references, [&file]( const auto &item) {
		return residualEqual( item.section, file.section) &&
			   residualEqual( item.directive, file.directive) &&
			   ((residualEqual( file.directive, L"CopyINF") &&
				 item.kind == OfficialInfInstallReferenceKind::COPY_INF) ||
				(residualEqual( file.directive, L"AddComponent") &&
				 item.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION)) ;
	}) ; // 元参照の存在までで、充足・採用を推論しない。
	// CopyINFは保持されたpackage参照だけへ結ぶ。
	if( reference && residualEqual( file.directive, L"CopyINF")) {
		return "COPYINF_PACKAGE_DEPENDENCY" ;
	}

	const bool effect = std::ranges::any_of( inventory.effects, [&file]( const auto &item) {
		return residualEqual( item.section, file.section) &&
			   residualEqual( item.directive, file.directive) &&
			   item.kind == OfficialInfInstallEffectKind::EXPLICIT_DEPENDENCY ;
	}) ; // componentの元作用だけを同期確認する。
	// componentは名前だけでbinaryへ縮約しない。
	if( (reference || effect) && residualEqual( file.directive, L"AddComponent")) {
		return "COMPONENT_DEPENDENCY_UNASSESSED" ;
	}

	const bool unknown = std::ranges::any_of( inventory.effects, [&file]( const auto &item) {
		return !file.section.empty() && residualEqual( item.section, file.section) &&
			   residualEqual( item.directive, file.directive) &&
			   item.kind == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE ;
	}) ; // 元UNKNOWN作用が保持された場合だけ。
	// 保持済み未知作用を固定語へ分けても安全判定にはしない。
	if( unknown) {
		return "UNKNOWN_DIRECTIVE_OR_FILE_SEMANTICS" ;
	}

	return "OTHER_UNSUPPORTED_USE" ;
}

/** @brief 新modeだけの独立分類と全一致gap ordinalを有限JSONへ追加する。
 * @param[in,out] out 全serialized上限を共有するbuilder。
 * @param[in] file 元用途。
 * @param[in] inventory 同INF内の最終保持済み棚卸し。
 * @note 同節・directiveの一致であり行因果は保持しない。
 */
void appendResidualUse( ReachedJson &out, const MaintenanceInfFileReference &file,
					   const OfficialInfInstallInventory &inventory)
{
	const auto classification = residualClassification( file, inventory) ;	// Uだけの固定細分類。
	out.add(
		",\"classification\":" +
		(classification.empty() ? std::string( "null") : "\"" + std::string( classification) + "\"") +
		",\"coverageGapOrdinals\":[") ;
	bool			 first	 = true ;			// 全一致ordinalを保持し、一件へ縮約しない。
	std::string_view binding = "NOT_OBSERVED" ;	// 未保持の対応は推測しない。
	// 元gap順で全一致を追加し、別INFや別行への因果を作らない。
	for( std::size_t index = 0U; index < inventory.coverageGaps.size(); ++index) {
		const auto match =
			// 固定一致範囲。
			residualGapBinding( file, inventory.coverageGaps[index]) ;
		// 一致した全gapを保持し、矛盾・一致なしは配列へ入れない。
		if( match != "NOT_OBSERVED") {
			// 区切りもserialized上限へ含める。
			if( !first) {
				out.add( ",") ;
			}

			out.add( std::to_string( index)) ;
			first	= false ;
			binding = match ;
		}
	}

	out.add( "],\"coverageGapBinding\":\"" + std::string( binding) + "\"") ;
}

/** @brief 展開後の値の形だけを分類しliteralやhelper分岐を逆証明しない。
 * @param[in] target 保持済み元展開後値。
 * @return 有限形態語。
 */
std::string_view outputShape( const std::wstring_view target) noexcept
{
	// 明示空を無参照へ変換しない。
	if( target.empty()) {
		return "EMPTY" ;
	}

	// 未展開DIRID13の形だけを示す。
	if( target.starts_with( L"%13%\\")) {
		return "RAW_DIRID13" ;
	}

	// 成功した形も個別helper経路のtraceではない。
	if( target.starts_with( L".\\")) {
		return "DOT_RELATIVE" ;
	}

	// 残るtokenの内容を保存しない。
	if( target.find( L'%') != std::wstring_view::npos) {
		return "OTHER_TOKEN" ;
	}

	// 実絶対位置は固定形態だけへ射影する。
	if( target.size() >= 3U && target[1] == L':') {
		return "DRIVE_ABSOLUTE" ;
	}

	return target.find_first_of( L"\\/") == std::wstring_view::npos ? "LEAF" : "OTHER_RELATIVE" ;
}

/** @brief 保持済みentryへの一意な全値対応だけを位置IDにする。
 * @param[in] closure 同scopeの保持済みclosure。
 * @param[in] path 元全relativePath。外部へ保存しない。
 * @return 一意な固定位置の1起点ordinal、それ以外0。
 */
std::size_t positionId( const MaintenanceDriverClosure &closure, const std::wstring_view path)
{
	std::size_t identity{} ;	// 同hash別位置も別entry ordinalへ残す。
	std::size_t count{} ;		// 複数候補を先頭へ絞らない。
	// 元全位置を固定entry全集合へ照合し、basenameを逆算しない。
	for( std::size_t index = 0U; index < closure.content.entries.size(); ++index) {
		// 全値一致だけを対応として数える。
		if( !path.empty() && closure.content.entries[index].relativePath == path) {
			identity = index + 1U ;
			++count ;
		}
	}

	return count == 1U ? identity : 0U ;
}

/** @brief 元最終rootを再照会なしでprivacy保持のJSONへ射影する。
 * @param[in] closure 同scopeで生存する最終結果。
 * @param[in] row 同じrootの通常row。
 * @param[in] ordinal Archive順root位置。
 * @param[in] residual trueの場合だけ元UNSUPPORTED用途と作用gapの独立細分類を追加する。
 * @return 原値を含まない有限JSON。
 * @throws std::exception 容量、元opaque整合、enum/hash不正の場合。
 */
std::string rootJson( const MaintenanceDriverClosure &closure, const MaintenanceInfInspection &row,
					 const std::size_t ordinal, const bool residual)
{
	const auto &graph = closure.dependency.dependency ;	// 保持済み同runのgraphだけを借用する。
	// 原共同予算を拡張せず、各配列のappend前に確認する。
	if( closure.references.size() > 64U || closure.content.entries.size() > 256U ||
	   graph.documents.size() > 64U || graph.sections.size() > 1024U ||
	   graph.edges.size() > 4096U || closure.dependency.findings.size() > 64U ||
	   closure.dependency.fileUses.size() > 4096U || closure.dependency.fixedFileCount > 256U ||
	   closure.dependency.fixedByteCount > 128ULL * 1024U * 1024U) {
		throw std::length_error( "observation root") ;
	}

	// 生存中の通常rowが違う結果へ結び付く場合は独立計測だけを拒否する。
	if( !closure.references.empty() &&
	   (row.infSha256 != closure.structure.infSha256 ||
		row.referenceCoverage != closure.structure.referenceCoverage ||
		row.integrity.state != closure.integrity.state ||
		row.integrity.error != closure.integrity.error)) {
		throw std::invalid_argument( "observation row binding") ;
	}

	ReachedJson out ;	// 全構築成功までcollectorへ移動しない。
	out.add(
		"{\"rootOrdinal\":" + std::to_string( ordinal) +
		",\"archiveDepth\":" + std::to_string( row.archiveDepth) +
		",\"infSha256\":" + hashJson( row.infSha256) + ",\"parser\":" + findingJson( row.parser) +
		",\"referenceCoverage\":\"" + std::string( enumName( row.referenceCoverage, COVERAGE)) +
		"\",\"rootIntegrity\":" + findingJson( row.rootIntegrity) +
		",\"fullIntegrity\":" + findingJson( row.integrity) +
		",\"allRootSeeds\":\"NOT_OBSERVED\",\"rootSeedExistenceGate\":\"NOT_OBSERVED\","
		"\"intermediateRescans\":\"NOT_OBSERVED\",\"helperRejectionDetails\":\"NOT_OBSERVED\",\"packageReferences\":[") ;
	std::size_t incomplete{} ;	// 非COMPLETE参照数。元coverageの拒否事実で排他的原因数ではない。
	std::size_t nonLocated{} ;	// 非LOCATED用途数。source metadataも区別して全用途を残す。
	// 最終reader結果だけをroot内の順序で射影し、未採用候補を消さない。
	for( std::size_t index = 0U; index < closure.references.size(); ++index) {
		const auto &reference = closure.references[index] ;	// この一参照だけの原値を同期借用する。
		// 原共同readerの上限を増やさず、上限＋1は全計測拒否とする。
		if( reference.files.size() > 4096U || reference.inventory.visitedSections.size() > 1024U ||
		   reference.inventory.scannedLines > 4096U ||
		   reference.inventory.references.size() > 4096U ||
		   (residual &&
			(reference.inventory.effects.size() > 4096U ||
			 reference.inventory.coverageGaps.size() > 4096U - reference.files.size()))) {
			throw std::length_error( "observation references") ;
		}

		std::uint64_t graphIdentity{} ;									// hash対応が複数なら0／NOT_OBSERVED。
		std::size_t	  matches{} ;										// 同hash複数位置を併合しないための分母。
		const auto	  referenceHash = hashJson( reference.infSha256) ;	// 元INF hashを先に検査する。
		// graph側の同hashpackage候補を全集合で照合する。
		for( const auto &document : graph.documents) {
			// SYSTEMや別hashはpackage位置へ結び付けない。
			if( document.origin == InfDependencyOrigin::PACKAGE &&
			   document.sha256 == reference.infSha256) {
				graphIdentity = document.identity ;
				++matches ;
			}
		}

		// 参照側にも同hash別位置があればgraph対応を未観測へ残す。
		if( matches != 1U ||
		   std::ranges::count_if( closure.references, [&reference]( const auto &item) {
			   return item.infSha256 == reference.infSha256 ;
		   }) != 1) { // 保持済み全候補を同期照合する。
			graphIdentity = 0U ;
		}

		std::vector<std::wstring_view> sections ;	// この参照内だけのopaque節対応。保存しない。
		const auto					   seed =
			// 最初の実在seedだけ。
			sectionId( sections, reference.inventory.selectedInstallSection) ;
		// 配列区切りを元ordinalへ対応させる。
		if( index != 0U) {
			out.add( ",") ;
		}

		out.add(
			"{\"infOrdinal\":" + std::to_string( index) + ",\"infSha256\":" + referenceHash +
			",\"role\":\"" +
			(reference.infRelativePath == closure.structure.infRelativePath
				 ? std::string( "ROOT")
				 : std::string( "PACKAGE_CANDIDATE")) +
			"\",\"positionId\":" + std::to_string( positionId( closure, reference.infRelativePath)) +
			",\"graphIdentity\":" + std::to_string( graphIdentity) + ",\"graphBinding\":\"" +
			(graphIdentity == 0U ? std::string( "NOT_OBSERVED")
								 : std::string( "UNIQUE_CONTENT_HASH")) +
			"\",\"nativeAdoption\":\"NOT_OBSERVED\",\"sourceSectionPresent\":" +
			(reference.sourceSectionPresent ? "true" : "false") + ",\"referenceCoverage\":\"" +
			std::string( enumName( reference.referenceCoverage, COVERAGE)) + "\",\"scannedLines\":" +
			std::to_string( reference.inventory.scannedLines) + ",\"visitedSectionCount\":" +
			std::to_string( reference.inventory.visitedSections.size()) +
			",\"firstPresentSeedId\":" + std::to_string( seed) + ",\"seedObservation\":\"" +
			(seed == 0U ? std::string( "NOT_OBSERVED") : std::string( "FIRST_PRESENT_SEED_ONLY")) +
			"\",\"uses\":[") ;
		// 各原用途を消さず、source宣言と使用先を分けて射影する。
		for( std::size_t use = 0U; use < reference.files.size(); ++use) {
			const auto &file	 = reference.files[use] ;						// 原値の寿命はこのscopeだけ。
			const auto	kind	 = useKind( file) ;								// 保存する固定語。
			const auto	position = positionId( closure, file.relativePath) ;	// 全元位置一致だけ。
			const bool	metadata = kind == "INF" || kind == "CAT" || kind == "SOURCE_DECLARATION" ||
								  // Queue外のmetadata。
								  kind == "LAYOUT" ;
			// 同じfileの複数用途にも異なるordinalを残す。
			if( use != 0U) {
				out.add( ",") ;
			}

			out.add(
				"{\"useOrdinal\":" + std::to_string( use) + ",\"kind\":\"" + std::string( kind) +
				"\",\"scope\":\"" +
				(metadata ? std::string( "METADATA")
						  : (kind == "SEED_SECTION" ? std::string( "SEED_ABSENCE")
													: std::string( "LOCAL_READER_USE"))) +
				"\",\"sectionId\":" + std::to_string( sectionId( sections, file.section)) +
				",\"seedCausality\":\"NOT_OBSERVED\",\"shape\":\"" +
				std::string( outputShape( file.target)) + "\",\"location\":\"" +
				std::string( enumName( file.location, LOCATIONS)) +
				"\",\"error\":" + std::to_string( file.error) +
				",\"positionId\":" + std::to_string( position) + ",\"positionBinding\":\"" +
				(position == 0U ? std::string( "NOT_OBSERVED") : std::string( "EXACT_FIXED_ENTRY")) +
				"\",\"sourceMetadataUseOrdinals\":[") ;
			bool first = true ;	// 同位置の元source全宣言を消さず残す。
			// 全元source用途へ照合し、一意性やhelper採用を再判定しない。
			for( std::size_t source = 0U; source < reference.files.size(); ++source) {
				const auto &candidate = reference.files[source] ;	// 原全値だけを借用する。
				// 固定entryへ結んだ全位置が一致したsource宣言だけを対応させる。
				if( position != 0U && candidate.directive == L"SourceDisksFiles" &&
				   candidate.relativePath == file.relativePath) {
					// 複数のsource宣言を最初の一件へ絞らない。
					if( !first) {
						out.add( ",") ;
					}

					out.add( std::to_string( source)) ;
					first = false ;
				}
			}

			out.add( "]") ;
			// 元modeのfield集合とbyteを保持し、新modeだけ独立分類を追加する。
			if( residual) {
				appendResidualUse( out, file, reference.inventory) ;
			}

			out.add( "}") ;
			// 元非LOCATEDをHRESULTから細分化しない。
			if( file.location != MaintenanceInfFileLocation::LOCATED) {
				++nonLocated ;
			}
		}

		out.add( "]") ;
		// 全用途のopaque IDを割当てた後でgapだけの節を辞書へ追加する。
		if( residual) {
			out.add( ",\"coverageGaps\":[") ;
			// 元gap全件の順序と固定種類を別集合に残し、不足総数へ足さない。
			for( std::size_t gap = 0U; gap < reference.inventory.coverageGaps.size(); ++gap) {
				const auto &item = reference.inventory.coverageGaps[gap] ;	// 元scopeだけの借用。
				// 区切りも全serialized上限に含める。
				if( gap != 0U) {
					out.add( ",") ;
				}

				out.add( "{\"gapOrdinal\":" + std::to_string( gap) + ",\"kind\":\"" +
						std::string( enumName( item.kind, GAP_KINDS)) + "\",\"sectionId\":" +
						std::to_string( gapSectionId( sections, item.section)) + "}") ;
			}

			out.add( "]") ;
		}

		out.add( "}") ;
		// 元参照が未完了である事実だけを数える。
		if( reference.referenceCoverage != MaintenanceInfReferenceCoverage::COMPLETE) {
			++incomplete ;
		}
	}

	out.add( "],\"documents\":[") ;
	// graph documentはhash別位置を維持し、元三証拠をそのまま残す。
	for( std::size_t index = 0U; index < graph.documents.size(); ++index) {
		const auto &document = graph.documents[index] ;	// 元run内のidentity。
		// opaque identityの重複と0を計測整合失敗にする。
		if( document.identity == 0U ||
		   std::ranges::count_if( graph.documents, [&document]( const auto &item) {
			   return item.identity == document.identity ;
		   }) != 1) { // 元全documentを照合する。
			throw std::invalid_argument( "observation identity") ;
		}

		// graph配列の区切りを元位置に対応させる。
		if( index != 0U) {
			out.add( ",") ;
		}

		out.add( "{\"identity\":" + std::to_string( document.identity) +
				",\"sha256\":" + hashJson( document.sha256) +
				",\"byteCount\":" + std::to_string( document.byteCount) + ",\"origin\":\"" +
				std::string( enumName( document.origin, ORIGINS)) + "\",\"byteBinding\":\"" +
				std::string( enumName( document.byteBinding, EVIDENCE)) + "\",\"provenance\":\"" +
				std::string( enumName( document.provenance, EVIDENCE)) + "\",\"signature\":\"" +
				std::string( enumName( document.signature, EVIDENCE)) + "\"}") ;
	}

	out.add( "],\"edges\":[") ;
	std::size_t unresolved{} ;	// 排他的な全原因数には合算しない。
	std::size_t invalid{} ;		// 元INVALID_REFERENCEの数。
	std::size_t unchecked{} ;	// 元NOT_CHECKEDの数。
	std::size_t targetZero{} ;	// 他の辺不足と重なる元target0の数。
	// 元辺のstate／reason／候補数を残し、節名と対象名は保存しない。
	for( std::size_t index = 0U; index < graph.edges.size(); ++index) {
		const auto &edge = graph.edges[index] ;	// 同graphの有限元辺。
		// 未知documentや候補上限を固定値へ補完しない。
		if( edge.candidateCount > 64U ||
		   !std::ranges::any_of( graph.documents,
								[&edge]( const auto &document) {
									return document.identity == edge.sourceIdentity ;
								}) ||
		   (edge.targetIdentity != 0U &&
			!std::ranges::any_of( graph.documents, [&edge]( const auto &document) {
				return document.identity == edge.targetIdentity ;
			}))) { // 原全document内でのみ結ぶ。
			throw std::invalid_argument( "observation edge binding") ;
		}

		// 全辺を元順に出す。
		if( index != 0U) {
			out.add( ",") ;
		}

		out.add( "{\"edgeOrdinal\":" + std::to_string( index) +
				",\"sourceIdentity\":" + std::to_string( edge.sourceIdentity) +
				",\"targetIdentity\":" + std::to_string( edge.targetIdentity) + ",\"directive\":\"" +
				std::string( enumName( edge.directive, DIRECTIVES)) + "\",\"state\":\"" +
				std::string( enumName( edge.state, EDGE_STATES)) + "\",\"reason\":\"" +
				std::string( enumName( edge.reason, REASONS)) +
				"\",\"candidateCount\":" + std::to_string( edge.candidateCount) + "}") ;
		// 重なる拒否事実を独立に残す。
		if( edge.state == InfDependencyState::UNRESOLVED) {
			++unresolved ;
		}

		// 不正参照は未照会と区別する。
		if( edge.state == InfDependencyState::INVALID_REFERENCE) {
			++invalid ;
		}

		// 未照会を未発見に変換しない。
		if( edge.state == InfDependencyState::NOT_CHECKED) {
			++unchecked ;
		}

		// target0を特定の欠落理由へ変換しない。
		if( edge.targetIdentity == 0U) {
			++targetZero ;
		}
	}

	out.add( "],\"sections\":[") ;
	// 元存在観測だけを保持し、root全seedのgateを再計算しない。
	for( std::size_t index = 0U; index < graph.sections.size(); ++index) {
		const auto &section = graph.sections[index] ;	// 名前は元scopeだけで借用する。
		// 未知identityを他documentへ結び直さない。
		if( !std::ranges::any_of( graph.documents, [&section]( const auto &document) {
			   return document.identity == section.identity ;
		   })) { // 同graphの元全集合。
			throw std::invalid_argument( "observation section binding") ;
		}

		// graph節の順序をopaque ordinalへ残す。
		if( index != 0U) {
			out.add( ",") ;
		}

		out.add( "{\"sectionOrdinal\":" + std::to_string( index) +
				",\"identity\":" + std::to_string( section.identity) + ",\"state\":\"" +
				std::string( enumName( section.state, READ_STATES)) + "\"}") ;
	}

	out.add( "],\"findings\":[") ;
	// 元署名と由来のHRESULTをUNKNOWN等へ上書きしない。
	for( std::size_t index = 0U; index < closure.dependency.findings.size(); ++index) {
		const auto &finding = closure.dependency.findings[index] ;	// 同runの原診断。
		// 診断identityを未知documentへ保存しない。
		if( !std::ranges::any_of( graph.documents, [&finding]( const auto &document) {
			   return document.identity == finding.identity ;
		   })) { // 同graphの全集合で結ぶ。
			throw std::invalid_argument( "observation finding binding") ;
		}

		// 元診断をすべて独立に残す。
		if( index != 0U) {
			out.add( ",") ;
		}

		out.add( "{\"identity\":" + std::to_string( finding.identity) +
				",\"signatureError\":" + std::to_string( finding.signatureError) +
				",\"provenanceError\":" + std::to_string( finding.provenanceError) + "}") ;
	}

	out.add( "],\"nativeUses\":[") ;
	// native用途はpackage reader用途と別分母にする。
	for( std::size_t index = 0U; index < closure.dependency.fileUses.size(); ++index) {
		const auto &use = closure.dependency.fileUses[index] ;	// 名前は同期借用だけ。
		// 用途identityを未知documentへ保存しない。
		if( !std::ranges::any_of( graph.documents, [&use]( const auto &document) {
			   return document.identity == use.identity ;
		   })) { // 同graphの全集合。
			throw std::invalid_argument( "observation native binding") ;
		}

		const MaintenanceInfFileReference file{use.section, use.directive,
											   use.target} ;	// 分類だけの短命借用copy。
		// metadata／native用途も順序と複数用途を消さない。
		if( index != 0U) {
			out.add( ",") ;
		}

		out.add( "{\"useOrdinal\":" + std::to_string( index) + ",\"identity\":" +
				std::to_string( use.identity) + ",\"kind\":\"" + std::string( useKind( file)) +
				"\",\"shape\":\"" + std::string( outputShape( use.target)) +
				"\",\"payloadLocation\":\"NOT_OBSERVED\",\"seedCausality\":\"NOT_OBSERVED\"}") ;
	}

	std::size_t systemTargets{} ;	// 実Needs辺が対象としたSYSTEM document数。
	// 未採用SYSTEM候補を全payload不足へ加算しない。
	for( const auto &document : graph.documents) {
		// 実Needs対象のSYSTEMだけを拒否事実へ数える。
		if( document.origin == InfDependencyOrigin::SYSTEM &&
		   std::ranges::any_of( graph.edges, [&document]( const auto &edge) {
			   return edge.directive == InfDependencyDirective::NEEDS &&
					  edge.targetIdentity == document.identity ;
		   })) { // 元同graphの辺だけを照合する。
			++systemTargets ;
		}
	}

	out.add( "],\"rejectionFacts\":{\"nonCompletePackageReferences\":" + std::to_string( incomplete) +
			",\"nonLocatedPackageUses\":" + std::to_string( nonLocated) +
			",\"dependencyDocumentsEmpty\":" + (graph.documents.empty() ? "true" : "false") +
			",\"systemNeedsTargetDocuments\":" + std::to_string( systemTargets) +
			",\"unresolvedEdges\":" + std::to_string( unresolved) + ",\"invalidReferenceEdges\":" +
			std::to_string( invalid) + ",\"notCheckedEdges\":" + std::to_string( unchecked) +
			",\"targetIdentityZeroEdges\":" + std::to_string( targetZero) +
			",\"exclusiveCauseTotal\":\"NOT_OBSERVED\"}}") ;
	return std::move( out.text) ;
}

/** @brief 研究writerが所有するHANDLEだけを必ず解放する。 */
struct ReachedHandleCloser {
	/** @brief 正常取得したhandleを閉じる。
	 * @param[in] handle 所有対象。Nullはunique_ptrが呼ばない。
	 */
	void operator()( void *handle) const noexcept
	{
		CloseHandle( handle) ;
	}
} ;
/**
 * @brief parent／fileの単独所有。
 */
using ReachedHandle = std::unique_ptr<void, ReachedHandleCloser> ;

/** @brief 同じ保持handleの最終pathとreparse属性を確認する。
 * @param[in] handle 呼出し全期間所有された通常handle。
 * @param[in] path 完全一致すべきDOS絶対path。
 * @return 最終path／非reparse一致true。
 */
bool fixedHandlePath( const HANDLE handle, const std::wstring &path)
{
	FILE_ATTRIBUTE_TAG_INFO attributes{} ;			// handle自身の属性。path再照会を正本にしない。
	std::vector<wchar_t>	finalPath( 32768U) ;	// 原絶対path上限内だけ。
	const DWORD				size =
		GetFinalPathNameByHandleW( handle, finalPath.data(), static_cast<DWORD>( finalPath.size()),
								  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 実handle最終path。
	return GetFileInformationByHandleEx( handle, FileAttributeTagInfo, &attributes,
										sizeof( attributes)) != FALSE &&
		   (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U && size != 0U &&
		   size < finalPath.size() &&
		   std::wstring_view( finalPath.data(), size) == L"\\\\?\\" + path ;
}

/** @brief 部分writeを含む元OS診断を失わず全byteを送る。
 * @param[in] handle 保存先の保持handle。
 * @param[in] bytes 上限確認済み有限byte。
 * @return 全送信0、元write失敗／0進捗のHRESULT。
 */
NativeError writeBytes( const HANDLE handle, const std::string_view bytes)
{
	std::size_t offset{} ;	// 完了したbyteだけから進捗を得る。
	// 実際に全byteを送るか元write失敗で止まる。無条件再試行はしない。
	while( offset < bytes.size()) {
		DWORD written{} ;	// このwriteでOSが完了したbyte数。
		// 失敗した部分fileを成功artifactへ昇格しない。
		if( WriteFile( handle, bytes.data() + offset, static_cast<DWORD>( bytes.size() - offset),
					 &written, nullptr) == FALSE) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		// 0進捗では無限writeを行わない。
		if( written == 0U) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WRITE_FAULT)) ;
		}

		offset += written ;
	}

	return 0 ;
}
} // namespace

ReachedReferenceCollector::ReachedReferenceCollector( const ReachedReferenceMode mode) noexcept
	: mode_( mode)
{
	// 未知modeを元観測へ補完せず、archive処理とは独立した計測拒否にする。
	if( mode != ReachedReferenceMode::REACHED && mode != ReachedReferenceMode::RESIDUAL) {
		error_ = static_cast<NativeError>( E_INVALIDARG) ;
	}
}

void ReachedReferenceCollector::append( const MaintenanceDriverClosure &closure,
									   const MaintenanceInfInspection &row,
									   const std::size_t			   ordinal) noexcept
{
	// 独立失敗以後は元処理だけを進め、観測部分を残さない。
	if( error_ != 0) {
		return ;
	}

	try {
		// 再利用・順序差・全128root上限を独立計測拒否にする。
		if( committed_ || ordinal != roots_.size() || roots_.size() >= 128U) {
			throw std::invalid_argument( "observation root ordinal") ;
		}

		std::string root = rootJson( closure, row, ordinal,
									// raw値は残さない。
									mode_ == ReachedReferenceMode::RESIDUAL) ;
		// 全package射影上限は移動前に確認する。
		if( root.size() > SIDECAR_BYTES - bytes_) {
			throw std::length_error( "observation package") ;
		}

		bytes_ += root.size() ;
		roots_.push_back( std::move( root)) ;
		hashes_.push_back( row.infSha256) ;
	} catch( const std::length_error &) {
		error_ = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
	} catch( const std::bad_alloc &) {
		error_ = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		error_ = static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 失敗した計測の全仮結果を破棄し、元HRESULTを変更しない。
	if( error_ != 0) {
		roots_.clear() ;
		hashes_.clear() ;
		bytes_ = 0U ;
	}
}

void ReachedReferenceCollector::finish(
	const MaintenanceDriverPackageInspection &inspection) noexcept
{
	// 元失敗・取消しでは部分射影を確定しない。
	if( inspection.error != 0 || error_ != 0) {
		roots_.clear() ;
		hashes_.clear() ;
		bytes_	   = 0U ;
		committed_ = false ;
		return ;
	}

	// 元rowと一対一でない計測を受理しない。
	if( inspection.infs.size() != roots_.size() || hashes_.size() != roots_.size()) {
		error_ = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	// Archive順と元hashを再確認し、同hash別位置のrowを消さない。
	for( std::size_t index = 0U; error_ == 0 && index < hashes_.size(); ++index) {
		// 異なる元rowへの対応を拒否する。
		if( hashes_[index] != inspection.infs[index].infSha256) {
			error_ = static_cast<NativeError>( E_UNEXPECTED) ;
		}
	}

	committed_ = error_ == 0 ;
	// 元成功でも独立計測不整合なら仮結果を破棄する。
	if( !committed_) {
		roots_.clear() ;
		hashes_.clear() ;
		bytes_ = 0U ;
	}
}

NativeError ReachedReferenceCollector::error() const noexcept
{
	return error_ ;
}
std::size_t ReachedReferenceCollector::rootCount() const noexcept
{
	return roots_.size() ;
}

std::optional<std::string> ReachedReferenceCollector::serialize(
	const std::string_view runId, const MaintenanceDriverPackageInspection &inspection,
	const std::string_view stdoutBytes) const noexcept
{
	// 元失敗・未確定・出力量違反でsidecarを構築しない。
	if( !committed_ || error_ != 0 || inspection.error != 0 || !validRunId( runId) ||
	   stdoutBytes.empty() || stdoutBytes.size() > STDOUT_BYTES || !stdoutBytes.ends_with( "\r\n") ||
	   inspection.infs.size() != roots_.size()) {
		return std::nullopt ;
	}

	try {
		std::wstring hash ;	// 送信する全byteと同一CNG hash。
		// 改行を除去・正規化してhashを救済しない。
		if( computeBytesSha256( stdoutBytes, hash) != 0) {
			return std::nullopt ;
		}

		ReachedJson out ;	// Header・区切りを含む全1 MiBをappend前に守る。
		out.add( "{\"schema\":\"" +
				std::string( mode_ == ReachedReferenceMode::RESIDUAL
								? "dc-maintenance-residual-reference-observation-v1"
								: "dc-maintenance-reached-reference-observation-v1") +
				"\",\"researchOnly\":true,"
				"\"publishable\":false,\"installAuthorized\":false,\"runId\":\"" +
				std::string( runId) +
				"\",\"observationKind\":\"FINAL_RETAINED_CLOSURE_ONLY\",\"archiveSha256\":" +
				hashJson( inspection.archiveSha256) + ",\"archiveBytes\":" +
				std::to_string( inspection.archiveBytes) + ",\"stdoutSha256\":" + hashJson( hash) +
				",\"stdoutBytes\":" + std::to_string( stdoutBytes.size()) +
				",\"rootCount\":" + std::to_string( roots_.size()) + ",\"roots\":[") ;
		// 元全rowを同順で保持し、途中失敗で成功sidecarを返さない。
		for( std::size_t index = 0U; index < roots_.size(); ++index) {
			// 再利用された通常結果へ結び直さない。
			if( hashes_[index] != inspection.infs[index].infSha256) {
				return std::nullopt ;
			}

			// 配列の区切りも全serialized上限へ含める。
			if( index != 0U) {
				out.add( ",") ;
			}

			out.add( roots_[index]) ;
		}

		out.add( "]}\n") ;
		return std::move( out.text) ;
	} catch( ...) {
		return std::nullopt ;
	} // 独立serialization失敗で元判定を変更しない。
}

NativeError writeReachedReferenceSidecar( const std::wstring_view path, const std::string_view runId,
										 const std::string_view		bytes,
										 const ReachedReferenceMode mode) noexcept
{
	// 入力不正ではpathをopenせず、任意位置や巨大byteを受理しない。
	if( !validRunId( runId) || bytes.empty() || bytes.size() > SIDECAR_BYTES ||
	   (mode != ReachedReferenceMode::REACHED && mode != ReachedReferenceMode::RESIDUAL)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::wstring parent =
			mode == ReachedReferenceMode::RESIDUAL
				? DRIVERCRATE_RESIDUAL_WORKSPACE
				: DRIVERCRATE_REACHED_WORKSPACE ;	// CMake PRIVATEの固定二workspaceだけ。
		std::ranges::replace( parent, L'/', L'\\') ;
		const std::wstring expected = parent +
									  (mode == ReachedReferenceMode::RESIDUAL
										   ? L"\\20261008-maintenance-residual-reference-54-"
										   : L"\\20261008-maintenance-reached-reference-53-") +
									  std::wstring( runId.begin(), runId.end()) +
									  L"-sidecar.json" ;	// 正確なstem／run ID。
		// 相対・逸脱・別stem・別workspaceは正規化して救済しない。
		if( path != expected || parent.size() < 4U || parent[1] != L':' || parent[2] != L'\\') {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::vector<ReachedHandle> parents ;	// 全祖先の非delete共有handleを保存完了まで保持する。
		std::size_t				   end = 3U ;	// drive rootから一つずつ祖先を固定する。
		// 最終親まで固定し、各open時と保持handleの最終pathで付替えを拒否する。
		while( end <= parent.size()) {
			const std::wstring current = parent.substr( 0U, end) ;	// 原全絶対pathだけ。
			const HANDLE	   raw	   = CreateFileW(
				  current.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
				  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
				  nullptr) ;	// rename／deleteを共有しない。
			// 親取得失敗を別pathへfallbackしない。
			if( raw == INVALID_HANDLE_VALUE) {
				return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
			}

			ReachedHandle held( raw) ;	// 各失敗経路でも必ず閉じる。
			// 最終位置と非reparseを同handleで確認する。
			if( !fixedHandlePath( raw, current)) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			parents.push_back( std::move( held)) ;
			// 最終親の確認を一度だけ行って終了する。
			if( end == parent.size()) {
				break ;
			}

			const auto next = parent.find( L'\\', end + (end == 3U ? 0U : 1U)) ;	// 次の原祖先境界。
			end				= next == std::wstring::npos ? parent.size() : next ;
		}

		const HANDLE raw =
			CreateFileW( expected.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
						nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr) ;	// 既存は必ず拒否する。
		// 既存fileや作成失敗を上書き／再試行しない。
		if( raw == INVALID_HANDLE_VALUE) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		ReachedHandle file( raw) ;	// 部分fileはreceipt付き未受入として残す。
		// 作成handleの最終位置も同じ原全pathへ固定する。
		if( !fixedHandlePath( raw, expected)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const NativeError error = writeBytes( raw, bytes) ;	// 同byteを一度だけ送信する。
		// 部分write診断をflush結果で上書きしない。
		if( error != 0) {
			return error ;
		}

		return FlushFileBuffers( raw) != FALSE
				   ? 0U
				   : static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

NativeError writeReachedReferenceStdout( const std::string_view bytes) noexcept
{
	// 研究stdoutも全byte上限と元CRLFを要求する。
	if( bytes.empty() || bytes.size() > STDOUT_BYTES || !bytes.ends_with( "\r\n")) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	return writeBytes( GetStdHandle( STD_OUTPUT_HANDLE), bytes) ;
}
} // namespace drivercrate
