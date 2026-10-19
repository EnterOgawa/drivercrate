//------------------------------------------------------------------------------
/**
 * @file maintenance_inf_integrity_tests.cpp
 * @brief 保守INFの部分署名・全参照と通常導入policyを専用link境界で検証する。
 * @version 01.09.00
 * @date 2026/10/07
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/07  専用署名応答と実閉包・射影の不足回帰を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/07  keyなし登録行と正規Software Type 2の作用policy回帰を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/07  named構造・DIRID展開形の位置不足と既知FAILED保持を回帰。
 * Ver.01.03.00 Shunji Ogawa  2026/10/07  明示named導入先・source別名と全署名／未知・失敗保持を回帰。
 * Ver.01.03.01 Shunji Ogawa  2026/10/07  未staging named13のrelative展開は未知として元FAILED保持を回帰。
 * Ver.01.04.00 Shunji Ogawa  2026/10/07  一意な相対named13の元source成功とroot／依存FAILEDの独立保持を回帰。
 * Ver.01.05.00 Shunji Ogawa  2026/10/08  同run最終参照の16条件群と元判定不変・出力拒否を回帰。
 * Ver.01.06.00 Shunji Ogawa  2026/10/08  元16群を保持し、残件細分類・共同容量・固定54保存の八群を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/08  同行eventlog親marker分離の九群と子U・全軸・私有容量保持を回帰。
 * Ver.01.08.00 Shunji Ogawa  2026/10/08  合成INFのAPI全値境界12群42構成と元byte結合を観測。
 * Ver.01.09.00 Shunji Ogawa  2026/10/08  同元byteと全値・caller・named13の52合成構成と元失敗保持を回帰。
 * </pre>
 *
 * @note 一同期scopeで架空署名とnative観測を借用する。実署名・PnP・導入の合格ではない。
 * 実archive・INF読取・hash再確認は既存sourceを使い、通常libraryへ注入口を追加しない。
 * @see docs/adr/0311-maintenance-inf-structure-and-install-policy-separation.md
 */
//------------------------------------------------------------------------------

// 専用名へのlink置換を持たない通常targetへこのfixtureを混入させない。
#ifndef DRIVERCRATE_MAINTENANCE_INTEGRITY_TESTING
#error This source is restricted to the isolated maintenance integrity test target.
#endif

#include "platform/common_driver_package.h"
#include "platform/common_inf_plan.h"
#include "platform/inf_dependency_native.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "core/update_types.h"
#include "test_framework.h"
#include "maintenance_reached_reference_observation.h"

#include <Windows.h>
#include <WinTrust.h>
#include <setupapi.h>
#include <miniz.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

// 内容署名の架空成功も候補・私有計画・通常検査への型変換を追加しない。
static_assert( !std::is_convertible_v<MaintenanceInfInspection, UpdateCandidate>) ;
static_assert( !std::is_constructible_v<UpdateCandidate, MaintenanceInfInspection>) ;
static_assert( !std::is_constructible_v<CommonInfInstallPlan, MaintenanceInfInspection>) ;
static_assert( !std::is_constructible_v<CommonInfInspection, MaintenanceInfInspection>) ;

constexpr NativeError SIGNATURE_FAILURE = static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;	// 原診断。
constexpr NativeError UNSUPPORTED_ERROR =
	// 元未対応診断。
	static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
constexpr std::array CONTENT_CLASSES{std::wstring_view( L"Ports"), std::wstring_view( L"System"),
									 // 架空内容Class名だけのpolicy。
									 std::wstring_view( L"MultiPortSerial")} ;
constexpr std::array INF_SIGNATURES{std::wstring_view( L"$Windows NT$")} ;	// 構文値。
constexpr OfficialDriverClosurePolicy CONTENT_POLICY{
	.zipPolicy				   = {1024U * 1024U, 1024U * 1024U, 4U * 1024U * 1024U, 16U},
	.cabPolicy				   = {1024U * 1024U, 1024U * 1024U, 4U * 1024U * 1024U, 16U},
	.infPolicy				   = {.maximumHardwareIds					= 16U,
								  .maximumSourceFiles					= 16U,
								  .acceptedClasses						= CONTENT_CLASSES,
								  .acceptedSignatures					= INF_SIGNATURES,
								  .acceptAnyProvider					= true,
								  .requireDriverBinary					= false,
								  .rejectUnreferencedPrograms			= false,
								  .rejectInstallActions					= false,
								  .rejectExternalDependencies			= false,
								  .allowReferencedExecutablesForContent = true},
	.maximumInfCount		   = 1U,
	.maximumClosureFiles	   = 16U,
	.maximumClosureBytes	   = 4U * 1024U * 1024U,
	.maximumExpansionRatio	   = 200U,
	.maximumNestedArchiveDepth = 1U} ;	// 一runの架空有限予算。

/** @brief 署名と全payloadを区別するための架空native応答種類。 */
enum class NativeMode {
	/// 明示依存なし。
	NONE,
	/// 実package INF自身は架空署名成功、裸local由来は未検査。
	PACKAGE,
	/// 明示参照先は照会済み未発見。
	MISSING,
	/// SYSTEM INF自身の三証拠だけが架空成功、全payloadは不明。
	SYSTEM,
	/// SYSTEM INF自身の既知署名失敗。
	SYSTEM_FAILED,
	/// Package依存INF自身の既知署名失敗。
	PACKAGE_FAILED,
} ;

/** @brief 閉じた元ZIPの一memberと実byte固定値。 */
struct FixtureMember {
	/// 元ZIP内のASCII相対名。scope終了まで所有する。
	std::string	 name ;
	/// 架空fileの原byte。実driverは含まない。
	std::string	 bytes ;
	/// 実CNGで固定した小文字SHA-256。
	std::wstring hash ;
} ;

/** @brief 署名helperへ渡った原member集合の記録。外部へ出力しない。 */
struct SignatureRequest {
	/// 同じ元memberのINF名。
	std::wstring			  inf ;
	/// 同じ元memberのCAT名。
	std::wstring			  catalog ;
	/// INF自身以外の全local参照集合。
	std::vector<std::wstring> sources ;
} ;

/** @brief 一つの不足matrixの構成と期待。 */
struct MatrixCase {
	/// DDInstallの追加宣言。本文はfixture内だけに保持する。
	std::string						install ;
	/// source宣言とCopyFilesをrootへ付加する場合true。
	bool							rootSource{true} ;
	/// 架空FixtureCopy節のkeyなしfile行を使う場合true。既定は直接参照。
	bool							rootCopyList{} ;
	/// 宣言されたroot SYSが元ZIPへ存在する場合true。
	bool							rootFile{true} ;
	/// empty名・flags 2のnull serviceを追加する場合true。
	bool							nullService{} ;
	/// 宣言された依存SYSが元ZIPへ存在する場合true。
	bool							peerFile{true} ;
	/// 架空native応答。名称を由来の根拠にしない。
	NativeMode						nativeMode{NativeMode::NONE} ;
	/// 新観測fixtureだけでInclude資料のseedなしを作る。
	bool							includeOnly{} ;
	/// 新観測fixtureだけで依存先へ共有seedを追加する。
	bool							sharedNeed{} ;
	/// root全member検査の架空HRESULT。0でも実署名成功ではない。
	NativeError						rootError{} ;
	/// 依存全member検査の架空HRESULT。
	NativeError						peerError{} ;
	/// 全必要file位置の期待。
	MaintenanceInfReferenceCoverage coverage{MaintenanceInfReferenceCoverage::COMPLETE} ;
	/// rootと全参照の署名集約の期待。
	MaintenanceInspectionState		whole{MaintenanceInspectionState::PASSED} ;
	/// 全署名集約に保持される元診断。
	NativeError						wholeError{} ;
	/// 明示依存の独立summary期待。
	MaintenanceInfDependencyState	dependency{MaintenanceInfDependencyState::NONE} ;
} ;

/** @brief fixture writerだけを単独所有し、必ずCloseHandleする。 */
class FixtureHandle final {
public:
	/** @brief 未所有状態でwriterを作る。 */
	FixtureHandle() = default ;
	/** @brief 取得したwriterだけを閉じる。 */
	~FixtureHandle()
	{
		// 未取得writerをOSへ渡さない。
		if( value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
	/** @brief writerの二重所有を禁止する。
	 * @param[in] other 複写不能な元writer。
	 */
	FixtureHandle( const FixtureHandle &other) = delete ;
	/** @brief writerの複写代入を禁止する。
	 * @param[in] other 複写不能な元writer。
	 * @return 呼出し不能であり値を返さない。
	 */
	FixtureHandle &operator=( const FixtureHandle &other) = delete ;
	/// createFileが出力する所有writer。未取得時INVALID_HANDLE_VALUE。
	HANDLE		   value{INVALID_HANDLE_VALUE} ;
} ;

/** @brief 閉じたASCII fixture名をUTF-16へ変換する。
 * @param[in] name 静的なASCII相対名。
 * @return 正規化せず同じ文字列のUTF-16所有値。
 */
std::wstring wideName( const std::string_view name)
{
	return {name.begin(), name.end()} ;
}

/** @brief 追跡される架空fileをCREATE_NEWで作成する。
 * @param[in,out] workspace このscopeだけのfile所有領域。
 * @param[in] name 安全なfixture相対名。
 * @param[in] bytes 元byte列。
 * @return 全byte書込み成功true、拒否false。
 */
bool writeFixture( OfficialDownloadWorkspace &workspace, const std::wstring_view name,
				  const std::string_view bytes)
{
	// Win32長へ収まらない入力を切捨てない。
	if( bytes.size() > std::numeric_limits<DWORD>::max()) {
		return false ;
	}

	FixtureHandle file ;	// 全終了経路でwriterを閉じる。
	// 既存fileを暗黙上書きしない。
	if( workspace.createFile( name, file.value) != 0) {
		return false ;
	}

	DWORD written{} ;	// 実確定byte数。
	return WriteFile( file.value, bytes.data(), static_cast<DWORD>( bytes.size()), &written,
					 nullptr) != FALSE &&
		   written == bytes.size() ;
}

/** @brief 合成INF一件の元式と、APIから独立した生成時の全値を保持する。 */
struct FieldBoundaryCase {
	/// 1～12の有限条件群。元driver用途の群とは別集合。
	std::size_t group{} ;
	/// 第5fieldへそのまま保存するASCII式。quoteとcontinuationも元byteに含む。
	std::string expression ;
	/// 同じ元INFのStrings定義。外部localeの値を取り込まない。
	std::string definitions ;
	/// 生成時に独立に指定した、終端を含まない期待論理値。
	std::string expected ;
	/// locale選択の観測だけで比較する第二の完全値。空なら代替なし。
	std::string alternative ;
	/// Strings単値またはliteralの元論理文字数。quoteと終端を含まない。
	std::size_t sourceCharacters{} ;
	/// keyなし行をSetupGetLineByIndexで照会する場合true。
	bool		keyless{} ;
} ;

/** @brief query、全取得、不足bufferを一つの同HINF観測として保持する。 */
struct FieldApiObservation {
	/// 必要長照会のBOOL。API成功と全値一致を分離する。
	BOOL		 querySuccess{} ;
	/// 照会直後のGetLastError。成功時のstale値もそのまま記録する。
	DWORD		 queryError{} ;
	/// 照会が返した終端込みWCHAR容量。未更新時はsentinel。
	DWORD		 queryRequired{} ;
	/// 照会容量による全取得のBOOL。
	BOOL		 readSuccess{} ;
	/// 全取得直後のGetLastError。
	DWORD		 readError{} ;
	/// 全取得が返した終端込みWCHAR容量。
	DWORD		 readRequired{} ;
	/// 有限buffer内で確認した、終端を含まない実取得値。
	std::wstring value ;
	/// 成功bufferの終端と前後guardが保持された場合true。
	bool		 terminatedAndGuarded{} ;
	/// 一文字不足bufferによる取得のBOOL。
	BOOL		 shortSuccess{} ;
	/// 一文字不足bufferによる取得直後のGetLastError。
	DWORD		 shortError{} ;
	/// 一文字不足bufferが返した終端込み容量。
	DWORD		 shortRequired{} ;
	/// 不足bufferの全sentinelが変更されなかった場合true。
	bool		 shortUnchanged{} ;
	/// 不足bufferの外側guardが変更されなかった場合true。
	bool		 shortGuarded{} ;
	/// 不足bufferでsentinelから変更された全WCHAR要素数。guardも別に検査する。
	std::size_t	 shortChangedElements{} ;
} ;

/** @brief 一scopeの合成INF handleだけを単独所有する。 */
class FieldInfHandle final {
public:
	/** @brief 未取得のhandleを初期化する。 */
	FieldInfHandle() = default ;
	/** @brief 成功した合成INFのhandleを全終了経路で閉じる。 */
	~FieldInfHandle()
	{
		// 未取得をSetupAPIへ渡して元診断を上書きしない。
		if( value != INVALID_HANDLE_VALUE) {
			SetupCloseInfFile( value) ;
		}
	}
	/** @brief handleの二重所有を禁止する。
	 * @param[in] other 複写不能な所有者。
	 */
	FieldInfHandle( const FieldInfHandle &other) = delete ;
	/** @brief handleの複写代入を禁止する。
	 * @param[in] other 複写不能な所有者。
	 * @return 呼出し不能であり値を返さない。
	 */
	FieldInfHandle &operator=( const FieldInfHandle &other) = delete ;
	/// 合成INFだけの所有handle。未取得時INVALID_HANDLE_VALUE。
	HINF			value{INVALID_HANDLE_VALUE} ;
} ;

/** @brief 64桁ASCII hexだけを検証後に表示用charへ明示変換する。
 * @param[in] hash CNGまたは既存file helperの小文字SHA-256。
 * @return 全64桁が小文字ASCII hexなら所有値、不正なら空。
 */
std::string narrowFieldHash( const std::wstring_view hash)
{
	// hash以外の広い文字列を表示用の暗黙narrowingへ流さない。
	if( hash.size() != 64U || !std::ranges::all_of( hash, []( const wchar_t character) {
		   return (character >= L'0' && character <= L'9') ||
				  (character >= L'a' && character <= L'f') ;
	   })) {
		return {} ;
	}

	std::string result( hash.size(), '0') ;	// 全要素を検査済みASCIIだけで埋める。
	std::ranges::transform( hash, result.begin(), []( const wchar_t character) {
		return static_cast<char>( character) ;
	}) ; // hashとresultをこの呼出し中だけ参照する。
	return result ;
}

/** @brief 既知の全UTF-16LE要素を、終端を含めずSHA-256へ結ぶ。
 * @param[in] value 同期scope内の全値。空ならhashを作らない。
 * @return 小文字hash、空値または計算失敗時は空。
 * @note Windows x64のWCHAR実byteを正規化せず検査する。
 */
std::string fieldValueHash( const std::wstring_view value)
{
	// 空を別の内容へ置き換えてhashを捏造しない。
	if( value.empty()) {
		return {} ;
	}

	std::wstring		   hash ;	// 全byteの実CNG計算結果。
	// wchar_tのobject representationをhashする境界だけでbyte viewへ変換する。
	const std::string_view bytes( reinterpret_cast<const char *>( value.data()),
								 value.size() * sizeof( wchar_t)) ;
	// 計算失敗を全値一致の証拠として返さない。
	if( computeBytesSha256( bytes, hash) != 0) {
		return {} ;
	}

	return narrowFieldHash( hash) ;
}

/** @brief 同contextの必要長・全取得・一文字不足を有限bufferで観測する。
 * @param[in,out] line SetupAPIが返した同HINFの借用context。呼出し中だけ使う。
 * @param[in] lineText trueならcompact行、falseなら指定fieldを照会する。
 * @param[in] fieldIndex field照会の1始まりindex。lineText時は使わない。
 * @return APIのBOOL、直後error、終端込み容量と全取得値。失敗値も保持する。
 * @note buffer上限は16,384 WCHAR。元製品readerの上限や判定は変更しない。
 */
FieldApiObservation observeFieldApi( INFCONTEXT &line, const bool lineText,
									const DWORD fieldIndex = 5U)
{
	constexpr DWORD		ERROR_SENTINEL	= 0xDEAD0001U ;	// 成功時stale観測用。失敗codeにしない。
	constexpr DWORD		SIZE_SENTINEL	= 0xDEAD0002U ;	// APIが必要長を未更新なら残る。
	constexpr wchar_t	BUFFER_SENTINEL = L'\x25A1' ;	// 合成値にないguard文字。
	FieldApiObservation result ;						// 三呼出しの結果を分離して保持する。
	// この呼出し中だけlineを借用し、二APIへ同じbuffer契約を適用する。
	const auto retrieve = [&line, lineText, fieldIndex]( wchar_t *buffer, const DWORD capacity,
														DWORD *required) {
		// compact値とfield値を同じ観測record型で比較する。
		if( lineText) {
			return SetupGetLineTextW( &line, nullptr, nullptr, nullptr, buffer, capacity, required) ;
		}

		return SetupGetStringFieldW( &line, fieldIndex, buffer, capacity, required) ;
	} ;
	result.queryRequired = SIZE_SENTINEL ;
	SetLastError( ERROR_SENTINEL) ;
	result.querySuccess = retrieve( nullptr, 0U, &result.queryRequired) ;
	result.queryError	= GetLastError() ;
	// 失敗・未更新・観測容量外を切捨てて成功bufferにしない。
	if( result.querySuccess == FALSE || result.queryRequired == 0U ||
	   result.queryRequired > 16384U) {
		return result ;
	}

	std::vector<wchar_t> buffer( result.queryRequired + 2U, BUFFER_SENTINEL) ;	// 前後guard付き。
	result.readRequired = SIZE_SENTINEL ;
	SetLastError( ERROR_SENTINEL) ;
	result.readSuccess = retrieve( buffer.data() + 1U, result.queryRequired, &result.readRequired) ;
	result.readError   = GetLastError() ;
	const auto end	   = std::find( buffer.begin() + 1, buffer.end() - 1, L'\0') ;	// 有限終端探索。
	result.terminatedAndGuarded = end != buffer.end() - 1 && buffer.front() == BUFFER_SENTINEL &&
								  buffer.back() == BUFFER_SENTINEL ;
	// 成功してbuffer内で終端を確認した全要素だけを記録する。
	if( result.readSuccess != FALSE && result.terminatedAndGuarded) {
		result.value.assign( buffer.begin() + 1, end) ;
	}

	std::vector<wchar_t> shortBuffer( result.queryRequired + 1U, BUFFER_SENTINEL) ;	// 一文字不足。
	result.shortRequired = SIZE_SENTINEL ;
	SetLastError( ERROR_SENTINEL) ;
	result.shortSuccess =
		retrieve( shortBuffer.data() + 1U, result.queryRequired - 1U, &result.shortRequired) ;
	result.shortError	  = GetLastError() ;
	result.shortUnchanged = std::ranges::all_of( shortBuffer, []( const wchar_t character) {
		return character == BUFFER_SENTINEL ;
	}) ; // このscopeの所有buffer全体を同期比較する。
	result.shortGuarded =
		shortBuffer.front() == BUFFER_SENTINEL && shortBuffer.back() == BUFFER_SENTINEL ;
	result.shortChangedElements = static_cast<std::size_t>( std::ranges::count_if(
		shortBuffer, []( const wchar_t character) { return character != BUFFER_SENTINEL ; })) ;
	return result ;
}

/** @brief 12群42構成を生成時の全値とともに固定する。
 * @return 原式と独立referenceの有限集合。一般INF本文を解析しない。
 */
std::vector<FieldBoundaryCase> makeFieldBoundaryCases()
{
	std::vector<FieldBoundaryCase> cases ;	// 一runだけが所有する合成matrix。
	// casesをこの生成中だけ借用し、quote込み元式とquoteなしreferenceを分ける。
	const auto literal = [&cases]( const std::size_t group, const std::string &value) {
		cases.push_back( {group, "\"" + value + "\"", {}, value, {}, value.size(), false}) ;
	} ;
	// casesをこの生成中だけ借用し、Strings原単値とrowの短いtoken式を分ける。
	const auto token = [&cases]( const std::size_t group, const std::string &value) {
		cases.push_back( {group,
						 "%Value%",
						 "[Strings]\r\nValue=\"" + value + "\"\r\n",
						 value,
						 {},
						 value.size(),
						 false}) ;
	} ;
	// 終端込み四境界をliteralとStrings単値の独立群へ保存する。
	for( const std::size_t capacity : {512U, 513U, 4095U, 4096U}) {
		const std::string value( capacity - 1U, 'a') ;	// 終端を除いた全元値。
		literal( 1U, value) ;
		token( 2U, value) ;
	}

	literal( 3U, std::string( 4096U, 'a')) ;
	token( 3U, std::string( 4096U, 'a')) ;
	cases.push_back( {3U,
					 "%Value%%Tail%",
					 "[Strings]\r\nValue=\"" + std::string( 4095U, 'a') + "\"\r\nTail=b\r\n",
					 std::string( 4095U, 'a') + "b",
					 {},
					 4095U,
					 false}) ;
	// 旧512と現4096の境界後に意味を変える内容を置き、部分一致を認定へ転用しない。
	for( const std::size_t prefixLength : {511U, 4095U}) {
		const std::string prefix( prefixLength, 'a') ;	// 境界直前の全prefix。
		literal( 4U, prefix + ";second.dll") ;
		token( 4U, prefix + ";second.dll") ;
		cases.push_back( {5U,
						 "\"" + prefix + "%Tail%\"",
						 "[Strings]\r\nTail=TAIL\r\n",
						 prefix + "TAIL",
						 {},
						 prefixLength,
						 false}) ;
		cases.push_back( {5U,
						 "%Value%%Tail%",
						 "[Strings]\r\nValue=\"" + prefix + "\"\r\nTail=TAIL\r\n",
						 prefix + "TAIL",
						 {},
						 prefixLength,
						 false}) ;
		literal( 6U, prefix + ":bad") ;
		token( 6U, prefix + ":bad") ;
	}

	literal( 7U, "sample.dll,second.dll;third.dll") ;
	token( 7U, "sample.dll,second.dll;third.dll") ;
	cases.push_back( {7U, "\"\"\"sample.dll\"\"\"", {}, "\"sample.dll\"", {}, 12U, false}) ;
	cases.push_back( {7U,
					 "%Value%",
					 "[Strings]\r\nValue=\"\"\"sample.dll\"\"\"\r\n",
					 "\"sample.dll\"",
					 {},
					 12U,
					 false}) ;
	// 引用外の合法continuationと引用内の改行負例を分け、全値referenceを維持する。
	for( const std::size_t prefixLength : {255U, 2047U}) {
		const std::string prefix( prefixLength, 'a') ;				// 元前半の全値。
		const std::string continued = prefix + "\\\r\n tail.dll" ;	// 改行込み元式。
		// 同じ元値を引用外の正例、または引用内改行の負例へ結ぶ。
		const std::string expression = prefixLength == 255U ? continued : "\"" + continued + "\"" ;
		// 255文字位置だけ引用外の正例とし、引用内改行は元不足を残す。
		cases.push_back( {8U, expression, {}, prefix + "tail.dll", {}, prefixLength + 8U, false}) ;
		cases.push_back( {8U,
						 "%Value%",
						 "[Strings]\r\nValue=" + expression + "\r\n",
						 prefix + "tail.dll",
						 {},
						 prefixLength + 8U,
						 false}) ;
	}

	constexpr std::string_view HEX = "0123456789abcdef" ;			// locale装飾の四桁hex。
	const LANGID language		   = GetUserDefaultUILanguage() ;	// read-only、OS設定を変更しない。
	// default／現在UI言語／同primary neutral／無関係の装飾を別fixtureにする。
	for( const std::size_t variant : {0U, 1U, 2U, 3U}) {
		const LANGID selected =
			variant == 2U ? static_cast<LANGID>( language & 0x03FFU)
						  : (variant == 3U ? static_cast<LANGID>( 0x7FFFU) : language) ;	// 元装飾値。
		std::string suffix( 4U, '0') ;														// 安全な四桁表記だけ。
		// 四つのnibbleを上位から固定装飾へ結ぶ。
		for( std::size_t digit = 0U; digit < 4U; ++digit) {
			suffix[digit] = HEX[(selected >> ((3U - digit) * 4U)) & 0xFU] ;
		}

		std::string definitions = "[Strings]\r\nValue=default.dll\r\n" ;	// 完全なdefault値。
		// 装飾なしcontrolを保持し、他三構成だけ第二の全定義を追加する。
		if( variant != 0U) {
			definitions += "[Strings." + suffix + "]\r\nValue=localed.dll\r\n" ;
		}

		cases.push_back( {9U, "%Value%", definitions, "default.dll",
						 variant == 0U ? "" : "localed.dll", 11U, false}) ;
	}

	cases.push_back(
		{10U, "%missing%", "[Strings]\r\nValue=sample.dll\r\n", "%missing%", {}, 9U, false}) ;
	cases.push_back( {10U,
					 std::string( 511U, 'a') + "%missing%",
					 {},
					 std::string( 511U, 'a') + "%missing%",
					 {},
					 520U,
					 false}) ;
	cases.push_back(
		{10U, "%SystemRoot%\\sample.dll", {}, "%SystemRoot%\\sample.dll", {}, 23U, false}) ;
	cases.push_back(
		{10U, "%%SystemRoot%%\\sample.dll", {}, "%SystemRoot%\\sample.dll", {}, 25U, false}) ;
	cases.push_back( {11U, "sample.dll", {}, "sample.dll", {}, 10U, true}) ;
	cases.push_back( {12U, "sample.dll", {}, "sample.dll", {}, 10U, false}) ;
	cases.push_back( {12U, "sample.dll", {}, "sample.dll", {}, 10U, true}) ;
	return cases ;
}

/** @brief 全API観測をnumeric、opaque ordinalとhashだけで通知する。
 * @param[in] spec 元構成。本文とpathは出力しない。
 * @param[in] ordinal 0始まりの同run構成index。
 * @param[in] api 1ならfield、2ならcompact行。
 * @param[in] originalBytes 終端を含まない元INF全byte数。
 * @param[in] originalHash 同じ元INFのSHA-256。
 * @param[in] observation 同HINFのAPI結果。
 * @note 全値比較はこの通知以前に所有値全体へ実施する。
 */
void printFieldObservation( const FieldBoundaryCase &spec, const std::size_t ordinal,
						   const unsigned int api, const std::size_t originalBytes,
						   const std::wstring &originalHash, const FieldApiObservation &observation)
{
	const std::wstring expected	 = wideName( spec.expected) ;		// 生成時の独立全値。
	const std::wstring alternate = wideName( spec.alternative) ;	// localeだけの第二reference。
	const std::wstring linePrefix =
		L"HKR,,EventMessageFile,0x00020000," ;										// 全四fieldのcompact基準。
	const std::wstring reference = api == 1U ? expected : linePrefix + expected ;	// 全値基準。
	const std::wstring alternateReference =
		// locale全値基準。
		api == 1U ? alternate : linePrefix + alternate ;
	const bool exact =
		observation.readSuccess != FALSE && observation.value == reference ;	// 元全値一致。
	const bool alternateExact = !alternate.empty() && observation.readSuccess != FALSE &&
								// 部分一致をlocale一致にしない。
								observation.value == alternateReference ;
	std::cout << "{\"schema\":\"dc-inf-field59-observation-v1\",\"group\":" << spec.group
			  << ",\"configuration\":" << ordinal << ",\"api\":" << api
			  << ",\"originalBytesExcludingNul\":" << originalBytes << ",\"originalSha256\":\""
			  << narrowFieldHash( originalHash)
			  << "\",\"rowExpressionBytesExcludingNul\":" << spec.expression.size()
			  << ",\"sourceCharactersExcludingNul\":" << spec.sourceCharacters
			  << ",\"sourceCharactersIncludingNul\":" << spec.sourceCharacters + 1U
			  << ",\"referenceCharactersExcludingNul\":" << reference.size()
			  << ",\"referenceCharactersIncludingNul\":" << reference.size() + 1U
			  << ",\"querySuccess\":" << observation.querySuccess
			  << ",\"queryLastError\":" << observation.queryError
			  << ",\"queryRequiredIncludingNul\":" << observation.queryRequired
			  << ",\"readSuccess\":" << observation.readSuccess
			  << ",\"readLastError\":" << observation.readError
			  << ",\"readRequiredIncludingNul\":" << observation.readRequired
			  << ",\"returnedCharactersExcludingNul\":" << observation.value.size()
			  << ",\"terminatedAndGuarded\":" << observation.terminatedAndGuarded
			  << ",\"fullReferenceMatch\":" << exact
			  << ",\"fullAlternativeMatch\":" << alternateExact
			  << ",\"rawExpressionMatch\":" << (observation.value == wideName( spec.expression))
			  << ",\"containsValueToken\":"
			  << (observation.value.find( L"%Value%") != std::wstring::npos)
			  << ",\"containsMissingToken\":"
			  << (observation.value.find( L"%missing%") != std::wstring::npos)
			  << ",\"containsSemicolon\":" << (observation.value.find( L';') != std::wstring::npos)
			  << ",\"containsBadSuffix\":"
			  << (observation.value.find( L":bad") != std::wstring::npos)
			  << ",\"shortSuccess\":" << observation.shortSuccess
			  << ",\"shortLastError\":" << observation.shortError
			  << ",\"shortRequiredIncludingNul\":" << observation.shortRequired
			  << ",\"shortBufferUnchanged\":" << observation.shortUnchanged
			  << ",\"shortBufferGuarded\":" << observation.shortGuarded
			  << ",\"shortChangedElements\":" << observation.shortChangedElements
			  << ",\"shortResultConsumed\":0"
			  << ",\"referenceUtf16LeSha256ExcludingNul\":\"" << fieldValueHash( reference)
			  << "\",\"returnedUtf16LeSha256ExcludingNul\":\"" << fieldValueHash( observation.value)
			  << "\"}\n" ;
}

/** @brief 合成INFの全値とcompact境界を元byteへ結んで有限測定する。
 * @param[in,out] context このprocessだけのassertion集計。
 * @note 実inventory、原ZIP、network、registry作用、導入は行わない。
 */
void testFieldCompletenessBoundary( TestContext &context)
{
	const std::vector<FieldBoundaryCase> cases = makeFieldBoundaryCases() ;	// 元生成matrix。
	DRIVERCRATE_EXPECT( context, cases.size() == 42U) ;
	std::array<wchar_t, 32768U> modulePath{} ;							// 同processの実SetupAPI.dllだけを照会する。
	const HMODULE module	   = GetModuleHandleW( L"setupapi.dll") ;	// 借用module、解放しない。
	const DWORD	  moduleLength = GetModuleFileNameW( module, modulePath.data(),
													// 終端を除く実path長。
													static_cast<DWORD>( modulePath.size())) ;
	std::wstring  moduleHash ;	// 同loaded moduleに対応するfileの全byte hash。
	DRIVERCRATE_EXPECT(
		context,
		module != nullptr && moduleLength > 0U && moduleLength < modulePath.size() &&
			computeFileSha256( std::wstring_view( modulePath.data(), moduleLength), moduleHash) == 0) ;
	std::cout << "{\"schema\":\"dc-inf-field59-module-v1\",\"loadedSetupApiSha256\":\""
			  << narrowFieldHash( moduleHash) << "\",\"systemLanguage\":" << GetSystemDefaultLangID()
			  << ",\"userUiLanguage\":" << GetUserDefaultUILanguage() << "}\n" ;
	// 各構成を一度ずつ生成し、同じHINFで両APIを観測してから所有領域を破棄する。
	for( std::size_t ordinal = 0U; ordinal < cases.size(); ++ordinal) {
		const FieldBoundaryCase	 &spec = cases[ordinal] ;	// この反復中だけ借用する元構成。
		OfficialDownloadWorkspace workspace ;				// この構成の合成INFだけを所有する。
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"inf-field-boundary", 5900U + ordinal) == 0) ;
		const std::string bytes = "[Version]\r\nSignature=\"$Windows NT$\"\r\n[Probe]\r\n" +
								  std::string( spec.keyless ? "" : "Row=") +
								  "HKR,,EventMessageFile,0x00020000," + spec.expression + "\r\n" +
								  spec.definitions ;	// 終端を含まない全元ASCII byte。
		std::wstring expectedHash ;						// 元RAM byteの実CNG hash。
		std::wstring fileHash ;							// 書込み完了後の実file全hash。
		DRIVERCRATE_EXPECT( context,
						   writeFixture( workspace, L"synthetic.inf", bytes) &&
							   computeBytesSha256( bytes, expectedHash) == 0 &&
							   computeFileSha256( workspace.path( L"synthetic.inf"), fileHash) == 0 &&
							   expectedHash == fileHash) ;
		FieldInfHandle inf ;			// このfile一件だけのHINF所有者。
		UINT		   errorLine{} ;	// 開けない元行をnumericだけで保持する。
		SetLastError( 0xDEAD0001U) ;
		inf.value			  = SetupOpenInfFileW( workspace.path( L"synthetic.inf").c_str(), nullptr,
												  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, &errorLine) ;
		const DWORD openError = GetLastError() ;	// 次のAPIより先に保存する。
		std::cout << "{\"schema\":\"dc-inf-field59-open-v1\",\"group\":" << spec.group
				  << ",\"configuration\":" << ordinal
				  << ",\"opened\":" << (inf.value != INVALID_HANDLE_VALUE)
				  << ",\"lastError\":" << openError << ",\"errorLine\":" << errorLine << "}\n" ;
		// 開けない値を空fieldの成功へ補完せず、この構成の失敗観測を残す。
		if( inf.value == INVALID_HANDLE_VALUE) {
			DRIVERCRATE_EXPECT( context, spec.expected.size() + 1U > 4096U) ;
			continue ;
		}

		INFCONTEXT line{} ;	// 同HINFの最初の架空Probe行だけを借用する。
		const BOOL found =
			// 同HINFのcontext成否。
			SetupGetLineByIndexW( inf.value, L"Probe", 0U, &line) ;
		DRIVERCRATE_EXPECT( context, found != FALSE && SetupGetFieldCount( &line) == 5U) ;
		// context取得に失敗した場合は未初期化contextで読取りを続けない。
		if( found == FALSE) {
			continue ;
		}

		constexpr std::array<std::wstring_view, 4U> PREFIX_FIELDS{L"HKR", L"", L"EventMessageFile",
																  L"0x00020000"} ;	// 元全四field。
		// 第1～4fieldの全一致を確認し、dataだけ一致してrowを認定しない。
		for( DWORD field = 1U; field <= PREFIX_FIELDS.size(); ++field) {
			const FieldApiObservation prefix = observeFieldApi( line, false, field) ;	// 同row全値。
			DRIVERCRATE_EXPECT( context, prefix.readSuccess != FALSE &&
											prefix.terminatedAndGuarded &&
											prefix.value == PREFIX_FIELDS[field - 1U]) ;
		}

		// field全値とcompact全値を同じ元byte・ordinalへ別recordとして結ぶ。
		for( const unsigned int api : {1U, 2U}) {
			const FieldApiObservation observation =
				// 三API呼出し。
				observeFieldApi( line, api == 2U) ;
			printFieldObservation( spec, ordinal, api, bytes.size(), fileHash, observation) ;
			DRIVERCRATE_EXPECT(
				context, observation.querySuccess != FALSE && observation.readSuccess != FALSE &&
							 observation.terminatedAndGuarded &&
							 observation.queryRequired == observation.readRequired &&
							 observation.value.size() + 1U == observation.readRequired) ;
			DRIVERCRATE_EXPECT(
				context, observation.shortSuccess == FALSE &&
							 observation.shortError == ERROR_INSUFFICIENT_BUFFER &&
							 observation.shortRequired == observation.queryRequired &&
							 observation.shortGuarded && (api == 2U || observation.shortUnchanged)) ;
			// 仕様差のない小さい既知literal／tokenは、完全値の正例として固定する。
			if( api == 1U &&
			   ((spec.group <= 2U && spec.expected.size() < 512U) || spec.group == 12U ||
				(spec.group == 8U && spec.sourceCharacters == 263U))) {
				DRIVERCRATE_EXPECT( context, observation.value == wideName( spec.expected)) ;
			}
		}

		// 不在fieldを存在するdataに補完せず、keyなしのkey値も別観測にする。
		if( spec.group == 11U) {
			const FieldApiObservation missing = observeFieldApi( line, false, 6U) ;	// 未表示field。
			const FieldApiObservation key	  = observeFieldApi( line, false, 0U) ;	// keyなし行。
			DRIVERCRATE_EXPECT( context, missing.querySuccess == FALSE &&
											(key.querySuccess == FALSE || key.value.empty())) ;
			std::cout << "{\"schema\":\"dc-inf-field59-missing-v1\",\"configuration\":" << ordinal
					  << ",\"field6Success\":" << missing.querySuccess
					  << ",\"field6Error\":" << missing.queryError
					  << ",\"field6RequiredIncludingNul\":" << missing.queryRequired
					  << ",\"keySuccess\":" << key.querySuccess
					  << ",\"keyError\":" << key.queryError
					  << ",\"keyRequiredIncludingNul\":" << key.queryRequired << "}\n" ;
		}

		std::wstring afterHash ;	// 同HINF観測後の元file全hash。
		DRIVERCRATE_EXPECT( context,
						   computeFileSha256( workspace.path( L"synthetic.inf"), afterHash) == 0 &&
							   afterHash == expectedHash) ;
	}

	std::cout << "INF field boundary groups: 12, configurations: " << cases.size() << '\n' ;
}

/** @brief 架空Portsと任意内容Class名のINFを生成する。
 * @param[in] spec 一つの有限matrix構成。
 * @param[in] className Class名policy比較用。ClassGuidは固定する。
 * @param[in] extra 元INFへ追加する架空付随節。
 * @return ASCIIの架空INF。Windows全体のClass妥当性を意味しない。
 */
std::string makeRootInf( const MatrixCase &spec, const std::string_view className = "Ports",
						const std::string_view extra = {})
{
	std::string inf =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=" + std::string( className) +
		"\r\nClassGuid={4d36e978-e325-11ce-bfc1-08002be10318}\r\n"
		"Provider=Fictional Provider\r\nDriverVer=10/07/2026,1.0.0.0\r\n"
		"CatalogFile=sample.cat\r\n[Manufacturer]\r\nFictional=Models,NTamd64\r\n"
		"[Models.NTamd64]\r\nFictional=Install,ROOT\\FICTIONAL_INTEGRITY_0001\r\n" ;	// 原byte。
	// 宣言とfile存在を独立に指定し、missingを空sourceへ補完しない。
	if( spec.rootSource) {
		inf += "[SourceDisksNames.amd64]\r\n1=Fictional Disk,,,\r\n"
			   "[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n" ;
	}

	inf += "[Install.NT]\r\n" ;
	// CopyFilesの直接参照とkeyなしlistを同じsource宣言と組にして実位置を検査する。
	if( spec.rootSource) {
		inf += spec.rootCopyList ? "CopyFiles=FixtureCopy\r\n" : "CopyFiles=@sample.sys\r\n" ;
	}

	inf += spec.install ;
	// 依存名は各matrixの閉じた候補と結合し、実system名を使わない。
	if( spec.nativeMode != NativeMode::NONE) {
		inf += "Include=peer.inf\r\n" ;
		// Include-only資料をNeeds到達と混同しない。
		if( !spec.includeOnly) {
			inf += spec.sharedNeed ? "Needs=Shared,Additional\r\n" : "Needs=Shared\r\n" ;
		}
	}

	// 無参照nullと参照付きnullを別の構造として残す。
	if( spec.nullService) {
		inf += "[Install.NT.Services]\r\nAddService=,2\r\n" ;
	}

	inf += extra ;
	return inf ;
}

/** @brief 一runだけの元file・native応答・署名呼出しを所有する。 */
struct BoundaryFixture {
	/// 全原fileとその実hash。閉じた一元入力。
	std::vector<FixtureMember>	  files ;
	/// 元fileとZIPを単独所有し、破棄時に追跡対象だけを削除する。
	OfficialDownloadWorkspace	  source ;
	/// 実ZIPの固定入力。公式取得由来ではない。
	DriverArchiveInput			  input ;
	/// 署名へ渡すroot全local参照集合。
	std::vector<std::wstring>	  rootSources ;
	/// 署名へ渡す依存全local参照集合。
	std::vector<std::wstring>	  peerSources ;
	/// 原fixtureに明示したroot seedの完全な順序付き集合。
	std::vector<std::wstring>	  rootSeeds{L"Install.NT"} ;
	/// 閉じた架空native構成。
	NativeMode					  nativeMode{NativeMode::NONE} ;
	/// 原新観測fixtureがInclude-onlyである場合true。
	bool						  includeOnly{} ;
	/// 原新観測fixtureが追加の共有Needsを持つ場合true。
	bool						  sharedNeed{} ;
	/// root全memberの架空署名診断。
	NativeError					  rootError{} ;
	/// 依存payloadの架空署名診断。
	NativeError					  peerError{} ;
	/// 一scopeで実行した署名helperの順序付き入力集合。
	std::vector<SignatureRequest> signatureCalls ;
	/// native境界の同期呼出し回数。
	std::size_t					  nativeCalls{} ;

	/** @brief 閉じた架空memberを実ZIPへ固定する。
	 * @param[in] spec 一matrixだけの応答条件。
	 * @param[in] identity 非零のscope識別子。
	 * @param[in] className Class名policy比較用。
	 * @param[in] extra 追加する架空付随節。
	 * @throws std::runtime_error Fixture作成に失敗した場合。
	 */
	explicit BoundaryFixture( const MatrixCase &spec, const std::uint64_t identity,
							 const std::string_view className = "Ports",
							 const std::string_view extra	  = {})
		: nativeMode( spec.nativeMode), includeOnly( spec.includeOnly), sharedNeed( spec.sharedNeed),
		  rootError( spec.rootError), peerError( spec.peerError)
	{
		files = {{"sample.inf", makeRootInf( spec, className, extra), {}},
				 {"sample.cat", "catalog", {}}} ;
		// Fixtureの原宣言と実readerのseed集合を完全比較できるよう固定する。
		if( spec.nullService || extra.find( "[Install.NT.Services]") != std::string_view::npos) {
			rootSeeds.push_back( L"Install.NT.Services") ;
		}

		// この一caseだけのCoInstaller付随節を原構成へ結ぶ。
		if( extra.find( "[Install.NT.CoInstallers]") != std::string_view::npos) {
			rootSeeds.push_back( L"Install.NT.CoInstallers") ;
		}

		// 正規Type 2 fixtureが持つ同装飾Software節だけを原seedへ加える。
		if( extra.find( "[Install.NT.Software]") != std::string_view::npos) {
			rootSeeds.push_back( L"Install.NT.Software") ;
		}

		// 必要SYSの欠落はsource宣言を消さず実fileだけを欠落させる。
		if( spec.rootSource && spec.rootFile) {
			files.push_back( {"sample.sys", "driver", {}}) ;
			rootSources.push_back( L"sample.sys") ;
		}

		// Package依存だけを原ZIPへ置き、SYSTEM応答には実fileを複写しない。
		if( nativeMode == NativeMode::PACKAGE || nativeMode == NativeMode::PACKAGE_FAILED) {
			files.push_back(
				{"peer.inf",
				 "[Version]\r\nSignature=\"$Windows NT$\"\r\n"
				 "CatalogFile=peer.cat\r\n[SourceDisksNames.amd64]\r\n1=Fictional Disk,,,\r\n"
				 "[SourceDisksFiles.amd64]\r\npeer.sys=1\r\n[Shared]\r\nCopyFiles=@peer.sys\r\n",
				 {}}) ;
			files.push_back( {"peer.cat", "catalog", {}}) ;
			// 追加seedも同INFの原byteへ固定してからZIPを作る。
			if( sharedNeed) {
				files[files.size() - 2U].bytes += "[Additional]\r\nCopyFiles=@peer.sys\r\n" ;
			}

			// 依存payloadの欠落もINF／CAT自身の確認と分ける。
			if( spec.peerFile) {
				files.push_back( {"peer.sys", "driver", {}}) ;
				peerSources.push_back( L"peer.sys") ;
			}
		}

		// scope専用の所有領域がなければfake成功値を使わない。
		if( source.initialize( L"maint-integrity-src", identity) != 0) {
			throw std::runtime_error( "fixture workspace") ;
		}

		mz_zip_archive zip{} ;	// 架空ZIP builder。全終了でwriterを終了する。
		// Builderが失敗した入力を空ZIPへ変換しない。
		if( !mz_zip_writer_init_heap( &zip, 0U, 0U)) {
			throw std::runtime_error( "fixture zip") ;
		}

		bool ready = true ;	// 全memberの元byte固定とZIP保存の共同結果。
		// 一元memberを一度ずつ書込み、INF／CAT／SYS全byteのhashを固定する。
		for( auto &member : files) {
			const std::wstring name = wideName( member.name) ;	// 同名の実file位置。
			ready					= ready && writeFixture( source, name, member.bytes) &&
					computeFileSha256( source.path( name), member.hash) == 0 &&
					mz_zip_writer_add_mem( &zip, member.name.c_str(), member.bytes.data(),
										  member.bytes.size(), MZ_NO_COMPRESSION) != 0 ;
		}

		void  *data{} ;	// minizが返すheap所有。最終化後にmz_freeへ移す。
		size_t size{} ;	// 最終ZIPの実byte数。
		ready = ready && mz_zip_writer_finalize_heap_archive( &zip, &data, &size) != 0 ;
		mz_zip_writer_end( &zip) ;
		const std::unique_ptr<void, decltype( &mz_free)> owned( data, &mz_free) ;	// 全終了で解放する。
		// 不完全な元集合を署名検査へ持ち込まない。
		if( !ready || !owned ||
		   !writeFixture( source, L"payload.zip",
						 std::string_view( static_cast<const char *>( owned.get()), size))) {
			throw std::runtime_error( "fixture members") ;
		}

		input = {identity, source.path( L"payload.zip"), size, {}} ;
		// 元ZIPも実hashへ結び、表示hashだけの成功を作らない。
		if( computeFileSha256( input.inspectionPath, input.sha256) != 0) {
			throw std::runtime_error( "fixture archive hash") ;
		}
	}

	/** @brief 原member一件だけを照会する。
	 * @param[in] name 同期借用する相対名。
	 * @return 閉じた原memberまたはnullptr。外部探索しない。
	 */
	const FixtureMember *find( const std::wstring_view name) const
	{
		const auto member = std::ranges::find_if( files, [name]( const auto &file) {
			return wideName( file.name) == name ;
		}) ; // このscopeの原memberだけを同期借用する。
		return member == files.end() ? nullptr : &*member ;
	}
} ;

/**
 * @brief 同byte／全field／一意callerとnamed13だけを52合成構成で回帰する。
 * @param[in,out] context 元3119assertion後の有限集計。
 * @note 原ZIP／INFを読み直さず、架空workspaceだけで元readerを呼ぶ。導入とregistry作用は0。
 */
void testCompleteValueProof( TestContext &context)
{
	constexpr std::string_view BASE =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Ports\r\n"
		"Provider=Fictional Provider\r\nDriverVer=01/01/2026,1.0.0.0\r\nCatalogFile=sample.cat\r\n"
		"[SourceDisksNames.amd64]\r\n1=Fictional Disk,,,\r\n"
		"[SourceDisksFiles.amd64]\r\nsample.sys=1,payload\r\n"
		"[Install.NT]\r\nCopyFiles=FixtureCopy\r\n"
		"[Install.NT.Services]\r\nAddService=FictionalEventService,2,ServiceInstall,Events\r\n"
		"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
		"ServiceBinary=%13%\\payload\\sample.sys\r\n"
		"[Events]\r\nAddReg=EventRegistry\r\n[EventRegistry]\r\n"
		"HKR,,EventMessageFile,0x00020000,\"%13%\\payload\\sample.sys\"\r\n"
		"[FixtureCopy]\r\nsample.sys,,0\r\n[DestinationDirs]\r\nFixtureCopy=13,payload\r\n" ;	// 全条件を持つ架空一元byte。
	// 元12群48と追加4構成を一度だけ作り、成功・private保留・元whole failureを分ける。
	for( std::size_t index = 0U; index < 52U; ++index) {
		std::string	 inf( BASE) ;				// この構成だけの原byte。
		std::wstring relative = L"sample.inf" ;	// 元INFの安全相対位置。
		bool		 located  = true ;			// 新data一件の位置期待。
		NativeError	 expected{} ;				// 元全体失敗はHRESULTも固定する。
		std::size_t	 dataCount = 1U ;			// 同値rowも元用途として別に数える。
		bool		 utf16{} ;					// BOM付きUTF-16LEを選ぶ構成だけtrue。
		bool		 malformedUtf16{} ;			// comment内の不正surrogateをprivate保留する。
		bool		 missingSource{} ;			// 元宣言を保持したsource欠落。
		bool		 extraSource{} ;			// subdir不一致の既存元sourceを作る。
		// 同期借用するinfだけの一意spanを置換し、元fixtureを上書きしない。
		const auto	 replace = [&inf]( std::string_view before, std::string_view after) {
			  const auto position = inf.find( before) ;	// 一意な原構文範囲。
			  // 存在しないfixture範囲を黙って読み飛ばさない。
			  if( position == inf.npos) {
				  throw std::runtime_error( "complete value fixture span") ;
			  }

			  inf.replace( position, before.size(), after) ;
		} ;
		// 各有限構成を正負条件へ固定し、runtimeの結果から期待値を作らない。
		switch( index) {
			// 閉じたwriterの通常fileは基準正例。
			case 0U:
				break ;

			// 私有rootの既存write access競合はproofだけを保留する。
			case 1U:
				located = false ;
				break ;

			// 元fileの継続writerは既存hashにも競合し、元whole failureを保持する。
			case 2U:
				located	 = false ;
				expected = HRESULT_FROM_WIN32( ERROR_SHARING_VIOLATION) ;
				break ;

			// 元固定hashの改変はbyte整合全体失敗。
			case 3U:
				located	 = false ;
				expected = SIGNATURE_FAILURE ;
				break ;

			// 私有子componentと元INF親も同scopeで固定する。
			case 4U:
				relative = L"private\\sample.inf" ;
				break ;

			// 元size／EOFの不一致は保留ではなく全体拒否。
			case 5U:
				located	 = false ;
				expected = SIGNATURE_FAILURE ;
				break ;

			// 元fileなしは既存file読取HRESULTで拒否する。
			case 6U:
				located	 = false ;
				expected = HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ;
				break ;

			// 65componentではprivate proofだけを閉じ、元readerへ進む。
			case 7U:
				// rootを含めた64component上限を一つ超す原安全pathを作る。
				for( std::size_t component = 0U; component < 64U; ++component) {
					relative.insert( 0U, L"a\\") ;
				}

				located = false ;
				break ;

			// BOM UTF-16LE CRLFでも同じ全targetを証明する。
			case 8U:
				utf16 = true ;
				break ;

			// 非ASCII ANSIは通常INF parserを新たに拒否しない。
			case 9U:
				inf += ";encoding " + std::string( 1U, static_cast<char>( 0xe9)) + "\r\n" ;
				located = false ;
				break ;

			// 非ASCII UTF-8も推測decodeせずprivate保留。
			case 10U:
				inf += ";encoding \xc3\xa9\r\n" ;
				located = false ;
				break ;

			// 不正surrogateはprivate encoding証明だけを保留する。
			case 11U:
				utf16		   = true ;
				malformedUtf16 = true ;
				located		   = false ;
				break ;

			// case違い同名sectionのmerge ordinalを全値へ結ぶ。
			case 12U:
				replace( "ErrorControl=1", "[serviceinstall]\r\nErrorControl=1") ;
				break ;

			// 同値二rowを一設定行へ潰さない。
			case 13U:
				replace(
					"[FixtureCopy]",
					"[eventregistry]\r\nHKR,,EventMessageFile,0x00020000,\"%13%\\payload\\sample.sys\"\r\n[FixtureCopy]") ;
				located	  = false ;
				dataCount = 2U ;
				break ;

			// 原headerとAPI選択名の差をordinal補正で救済しない。
			case 14U:
				replace( "[Events]", "[ Events ]") ;
				located	  = false ;
				dataCount = 0U ;
				break ;

			// 別値名の未知rowは元用途として保持し、元row identityを混同しない。
			case 15U:
				replace( "[FixtureCopy]",
						"[EventRegistry]\r\nHKR,,OtherValue,0,opaque.dll\r\n[FixtureCopy]") ;
				dataCount = 2U ;
				break ;

			// outer quote／引用外comment／明示空fieldを全値として比較する。
			case 16U:
				replace( "HKR,,EventMessageFile", "\"HKR\",\"\",\"EventMessageFile\"") ;
				replace( "sample.sys\"\r\n[FixtureCopy]",
						"sample.sys\" ; source comment\r\n[FixtureCopy]") ;
				break ;

			// 引用内semicolonの複数pathはsplitして部分受理しない。
			case 17U:
				replace( "sample.sys\"", "sample.sys;second.sys\"") ;
				located = false ;
				break ;

			// 末尾empty fieldをstrict5へ縮めない。
			case 18U:
				replace( "sample.sys\"\r\n[FixtureCopy]", "sample.sys\",\r\n[FixtureCopy]") ;
				located = false ;
				break ;

			// Windowsの合法continuationをprivate scannerで推測処理しない。
			case 19U:
				replace( "0x00020000,\"", "0x00020000,\\\r\n\"") ;
				located = false ;
				break ;

			// 一段default Stringsを原data全体へ展開する。
			case 20U:
				replace( "%13%\\payload\\sample.sys\"", "%13%\\%Path%\\%Name%\"") ;
				inf += "[Strings]\r\nPath=payload\r\nName=sample.sys\r\n" ;
				break ;

			// 全decorated候補が同値ならlocale推測なしで全比較する。
			case 21U:
				replace( "%13%\\payload\\sample.sys\"", "%13%\\payload\\%Name%\"") ;
				inf +=
					"[Strings]\r\nName=sample.sys\r\n[Strings.0409]\r\nName=sample.sys\r\n[Strings.0411]\r\nName=sample.sys\r\n" ;
				break ;

			// 選ばないlocaleの異なる定義も除外しない。
			case 22U:
				replace( "%13%\\payload\\sample.sys\"", "%13%\\payload\\%Name%\"") ;
				inf += "[Strings]\r\nName=sample.sys\r\n[Strings.0411]\r\nName=other.sys\r\n" ;
				located = false ;
				break ;

			// nested／未解決／重複定義を一段成功へ補完しない。
			case 23U:
				replace( "%13%\\payload\\sample.sys\"", "%13%\\payload\\%Name%\"") ;
				inf += "[Strings]\r\nName=%Nested%\r\nNested=sample.sys\r\n" ;
				located = false ;
				break ;

			// 512超でも取得全値が独立原値へ一致するcontrol値は証明できる。
			case 24U:
				replace( "ServiceType=1", "DisplayName=%Long%\r\nServiceType=1") ;
				inf += "[Strings]\r\nLong=\"" + std::string( 513U, 'a') + "\"\r\n" ;
				break ;

			// 長いdataのdelimiter以後のsuffixを捨ててnamed targetへ合わせない。
			case 25U:
				replace( "sample.sys\"", "sample.sys" + std::string( 513U, 'a') + ";suffix\"") ;
				located = false ;
				break ;

			// 元sourceが未読のaux fieldだけの過長取得失敗は元成功を保持する。
			case 26U:
				replace( "sample.sys=1,payload", "sample.sys=1,payload,%Huge%%Huge%") ;
				inf += "[Strings]\r\nHuge=\"" + std::string( 4095U, 'a') + "\"\r\n" ;
				located = false ;
				break ;

			// 元data fieldの過長失敗は私有保留へ弱めない。
			case 27U:
				replace( "%13%\\payload\\sample.sys\"", "%Huge%%Huge%\"") ;
				inf += "[Strings]\r\nHuge=\"" + std::string( 4095U, 'a') + "\"\r\n" ;
				located	 = false ;
				expected = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				break ;

			// exact REG_EXPAND_SZ以外の型を対象へ広げない。
			case 28U:
				replace( "0x00020000,", "0,") ;
				located = false ;
				break ;

			// 別rootをHKR callerへ読み替えない。
			case 29U:
				replace( "HKR,,", "HKLM,,") ;
				located = false ;
				break ;

			// 別値名は同targetでも対象外。
			case 30U:
				replace( "EventMessageFile", "CategoryMessageFile") ;
				located = false ;
				break ;

			// 第3／第4fieldの取り違えを名称で補完しない。
			case 31U:
				replace( "2,ServiceInstall,Events", "2,Events,ServiceInstall") ;
				located = false ;
				break ;

			// DIRID13のrenameはsource同名成功へ混ぜない。
			case 32U:
				replace( "sample.sys,,0", "sample.sys,other.sys,0") ;
				located = false ;
				break ;

			// sourceとdestinationのsubdirは元全値一致を要求する。
			case 33U:
				replace( "sample.sys=1,payload", "sample.sys=1,other") ;
				extraSource = true ;
				located		= false ;
				break ;

			// source同名重複をSetupAPIの先頭選択で消さない。
			case 34U:
				replace( "sample.sys=1,payload", "sample.sys=1,payload\r\nsample.sys=1,payload") ;
				located = false ;
				break ;

			// 元sourceなしはnamed target一致だけで充足させない。
			case 35U:
				missingSource = true ;
				located		  = false ;
				break ;

			// 後からの共有callerも全queue終了まで認定へ反映する。
			case 36U:
				replace( "CopyFiles=FixtureCopy", "CopyFiles=FixtureCopy\r\nAddReg=EventRegistry") ;
				located = false ;
				break ;

			// DelRegをAddReg-only証明へ流用しない。
			case 37U:
				replace( "AddReg=EventRegistry", "DelReg=EventRegistry") ;
				located = false ;
				break ;

			// 未追跡directiveと作用gapは元Uへ保持する。
			case 38U:
				replace( "AddReg=EventRegistry", "UnknownEvent=EventRegistry") ;
				located	  = false ;
				dataCount = 0U ;
				break ;

			// optional securityの元scope不足を位置成功で削除しない。
			case 39U:
				inf += "[EventRegistry.security]\r\n\"D:P(A;;GA;;;SY)\"\r\n" ;
				break ;

			// 1MiB超の原byteは元4MiB契約を変えずprivate保留。
			case 40U:
				inf += ";" + std::string( 1024U * 1024U, 'a') + "\r\n" ;
				located = false ;
				break ;

			// data stage後の後続core項目がprivate共同予約を撤回する。
			case 41U:
				replace( "[FixtureCopy]", "[EventRegistry]\r\n[FixtureCopy]") ;
				// 同registryの後続600file用途を元共同容量内へ保持する。
				for( std::size_t row = 0U; row < 600U; ++row) {
					replace( "[FixtureCopy]",
							"HKR,,Other" + std::to_string( row) + ",0,opaque.dll\r\n[FixtureCopy]") ;
				}

				located	  = false ;
				dataCount = 601U ;
				break ;

			// field64は全bitmapで観測するがstrict5の対象にはしない。
			case 42U:
				replace( "sample.sys\"\r\n[FixtureCopy]",
						"sample.sys\"" + std::string( 59U, ',') + "\r\n[FixtureCopy]") ;
				located = false ;
				break ;

			// 元field65は既存readerの共同上限でwhole failure。
			case 43U:
				replace( "sample.sys\"\r\n[FixtureCopy]",
						"sample.sys\"" + std::string( 60U, ',') + "\r\n[FixtureCopy]") ;
				located	 = false ;
				expected = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				break ;

			// 元known FAILEDのbyte/HRESULTを元全体結果へ保持する。
			case 44U:
				located	 = false ;
				expected = SIGNATURE_FAILURE ;
				break ;

			// source欠落はprivate位置を成功へ変えない。
			case 45U:
				missingSource = true ;
				located		  = false ;
				break ;

			// 後続associated構造の矛盾はdata callerの早期trueを取り消す。
			case 46U:
				replace(
					"[ServiceInstall]",
					"AddService=SecondService,2,ServiceInstall,SecondEvents\r\n[ServiceInstall]") ;
				inf +=
					"[SecondEvents]\r\nAddReg=OtherRegistry\r\n[OtherRegistry]\r\nHKR,,Other,0,opaque\r\n" ;
				located = false ;
				break ;

			// DIRID13のStrings shadowはbuilt-inと同値でも推測選択しない。
			case 47U:
				inf += "[Strings]\r\n13=13\r\n" ;
				located = false ;
				break ;

			// AddService名の13をtarget fieldとして全値比較から除外しない。
			case 48U:
				replace( "AddService=FictionalEventService",
						"AddService=%13%\\FictionalEventService") ;
				located = false ;
				break ;

			// 第3fieldの13は元不正参照HRESULTを保留へ弱めない。
			case 49U:
				replace( "2,ServiceInstall,Events", "2,%13%\\ServiceInstall,Events") ;
				located	 = false ;
				expected = HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
				break ;

			// 空の不正Strings family headerも全locale候補から飛ばさない。
			case 50U:
				inf += "[Strings.]\r\n" ;
				located = false ;
				break ;

			// 不正LanguageIDの空sectionをdefault成功から除外しない。
			case 51U:
				inf += "[Strings.04GG]\r\n" ;
				located = false ;
				break ;

			// 登録済み48構成以外を黙って基準正例へしない。
			default:
				throw std::runtime_error( "complete value fixture index") ;
		}

		// UTF-16LEは元ASCII全byteを一度変換し、BOMと不正surrogate条件を固定する。
		if( utf16) {
			std::string encoded( "\xff\xfe", 2U) ;	// BOMを含む原byte。
			// 原fixtureのASCII code unitだけを順序どおりUTF-16LEへ変換する。
			for( const char value : inf) {
				encoded.push_back( value) ;
				encoded.push_back( '\0') ;
			}

			// 不正UTF-16条件はcomment本文にだけ置き、元構文を変更しない。
			if( malformedUtf16) {
				encoded += std::string( ";\0\0\xd8\r\0\n\0", 8U) ;
			}

			inf = std::move( encoded) ;
		}

		OfficialDownloadWorkspace workspace ;	// この構成だけの所有領域。
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"complete-value-test", 6100U + index) == 0) ;
		const auto		   separator = relative.find_last_of( L'\\') ;	// 元INF親をsourceへ合わせる。
		const std::wstring parent	 = separator == relative.npos
										   ? L""
										   : relative.substr( 0U, separator + 1U) ;	// 安全な相対親。
		std::vector<OfficialZipEntry> entries ;										// 架空memberの同元size／hash。
		// writerを閉じた元memberだけをentryへ固定する。raw本文を結果へ保存しない。
		const auto					  add = [&]( const std::wstring &name, std::string_view bytes) {
			   DRIVERCRATE_EXPECT( context, writeFixture( workspace, name, bytes)) ;
			   OfficialZipEntry entry ;	// 同fileの固定条件。
			   entry.relativePath	  = name ;
			   entry.uncompressedSize = bytes.size() ;
			   DRIVERCRATE_EXPECT( context, computeFileSha256( workspace.path( name), entry.sha256) == 0) ;
			   entries.push_back( std::move( entry)) ;
		} ;
		add( relative, inf) ;
		add( parent + L"sample.cat", "catalog") ;
		// source欠落では宣言を保持し、metadata entryも補完しない。
		if( !missingSource) {
			add( parent + L"payload\\sample.sys", "driver") ;
		}

		// subdir不一致は両方実在でも全値対応を保留する。
		if( extraSource) {
			add( parent + L"other\\sample.sys", "driver") ;
		}

		// 改変した元固定hashをsnapshot成功で上書きしない。
		if( index == 3U || index == 44U) {
			entries.front().sha256.assign( 64U, L'0') ;
		}

		// 元固定sizeの差をprivate未知へ弱めない。
		if( index == 5U) {
			++entries.front().uncompressedSize ;
		}

		// 元file読取不能のHRESULTを保持する。
		if( index == 6U) {
			DRIVERCRATE_EXPECT( context, workspace.discardFile( relative) == 0) ;
		}

		HANDLE held = INVALID_HANDLE_VALUE ;	// このscopeだけの競合open。設定／内容を書き換えない。
		// private rootのwrite access競合だけを保持する。
		if( index == 1U) {
			const auto path = workspace.path( relative) ;	// 既存private元path。
			const auto root =
				// 共有Tempを対象にしない。
				path.substr( 0U, path.size() - relative.size() - 1U) ;
			held = CreateFileW( root.c_str(), DELETE,
							   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
							   OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr) ;
			DRIVERCRATE_EXPECT( context, held != INVALID_HANDLE_VALUE) ;
		}

		// 元fileの継続writerは元hash失敗を再現する。
		if( index == 2U) {
			held = CreateFileW( workspace.path( relative).c_str(), GENERIC_WRITE, FILE_SHARE_READ,
							   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;
			DRIVERCRATE_EXPECT( context, held != INVALID_HANDLE_VALUE) ;
		}

		const std::array<std::wstring, 2U> seeds{L"Install.NT",
												 L"Install.NT.Services"} ;	// 元明示seedだけ。
		MaintenanceInfReferences		   result ;							// 全体成功時だけの結果。
		const NativeError				   error = inspectMaintenanceInfReferences(
			 workspace, entries, relative, seeds, CONTENT_POLICY.infPolicy,
			 result) ;	// 同元byte／同HINFの製品reader。
		// 同case0のkeyなし行だけを数値で切り分け、原field値を保存しない。
		if( index == 0U) {
			const HINF probe = SetupOpenInfFileW( workspace.path( relative).c_str(), nullptr,
												 INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
												 nullptr) ;	// 元reader終了後の合成診断handle。
			INFCONTEXT line{} ;								// 合成registry rowだけの借用。
			DRIVERCRATE_EXPECT(
				context, probe != INVALID_HANDLE_VALUE &&
							 SetupGetLineByIndexW( probe, L"EventRegistry", 0U, &line) != FALSE) ;
			DWORD required{} ;	// key有無の元query結果。
			SetLastError( ERROR_SUCCESS) ;
			const BOOL query =
				// 有限な補助一回。
				SetupGetStringFieldW( &line, 0U, nullptr, 0U, &required) ;
			const DWORD native = GetLastError() ;	// 元結果を次APIより前に固定する。
			std::cout << "Complete value keyless query: bool=" << query << ", error=" << native
					  << ", required=" << required << '\n' ;
			SetupCloseInfFile( probe) ;
		}

		// 所有した競合HANDLEだけを元reader終了後に解放する。
		if( held != INVALID_HANDLE_VALUE) {
			CloseHandle( held) ;
		}

		DRIVERCRATE_EXPECT( context, error == expected) ;
		// 元whole failureでは部分出力を一件も公開しない。
		if( expected != 0) {
			DRIVERCRATE_EXPECT( context, result.files.empty() && result.sourceFiles.empty() &&
											result.infSha256.empty()) ;
			std::cout << "Complete value configuration " << index << ": whole=" << error << '\n' ;
			continue ;
		}

		const auto data	 = std::ranges::find_if( result.files, []( const auto &file) {
			 return file.directive == L"RegistryFileUseNotAssessed" &&
					file.section == L"EventRegistry" ;
		 }) ; // 名前はfixture期待の検索に限り、製品のcaller証明へ転用しない。
		const auto found = std::ranges::count_if( result.files, []( const auto &file) {
			return file.directive == L"RegistryFileUseNotAssessed" &&
				   file.section == L"EventRegistry" ;
		}) ; // 同値rowも元用途の分母に残す。
		DRIVERCRATE_EXPECT( context, static_cast<std::size_t>( found) == dataCount) ;
		// 元data一件がある構成だけ位置・元identity・HRESULTを比較する。
		if( data != result.files.end()) {
			DRIVERCRATE_EXPECT( context, data->location ==
											(located ? MaintenanceInfFileLocation::LOCATED
													 : MaintenanceInfFileLocation::UNSUPPORTED)) ;
			DRIVERCRATE_EXPECT( context, data->error == (located ? 0 : UNSUPPORTED_ERROR)) ;
			DRIVERCRATE_EXPECT( context, data->relativePath ==
											(located ? parent + L"payload\\sample.sys" : L"")) ;
			std::cout << "Complete value configuration " << index
					  << ": location=" << static_cast<int>( data->location) << ", count=" << found
					  << '\n' ;
		}

		DRIVERCRATE_EXPECT( context,
						   result.referenceCoverage == MaintenanceInfReferenceCoverage::INCOMPLETE) ;
		DRIVERCRATE_EXPECT(
			context, std::ranges::any_of(
						 result.inventory.coverageGaps,
						 []( const auto &gap) {
							 return gap.kind ==
									OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED ;
						 }) ||
						 // 元未到達sectionにgapを捏造しない。
						 index == 38U || index == 14U) ;
		// 新位置成立を57の独立子Uへ便乗させず、元eventlog親を保持する。
		if( located) {
			DRIVERCRATE_EXPECT( context, std::ranges::any_of( result.files, []( const auto &file) {
								   return file.directive == L"AddService" &&
										  file.location ==
											  MaintenanceInfFileLocation::UNSUPPORTED &&
										  file.error == UNSUPPORTED_ERROR ;
							   })) ;
		}
	}

	std::cout
		<< "Complete value proof groups: 13, configurations: 52, original file observations: 0\n" ;
}

thread_local BoundaryFixture *activeFixture{} ;	// 同期scopeだけの非所有借用。製品には存在しない。

/** @brief test EXE内だけの応答所有者を一同期scopeへ結ぶ。 */
class BoundaryScope			  final {
public:
	  /** @brief 未設定slotだけへfixtureを借用する。
	 * @param[in,out] fixture scope終了まで生存する所有者。
	 * @throws std::runtime_error 再入した場合。
	 */
	  explicit BoundaryScope( BoundaryFixture &fixture)
	  {
		  // 再入で別fixtureの成功応答を流用しない。
		  if( activeFixture != nullptr) {
			  throw std::runtime_error( "fixture reentry") ;
		  }

		  activeFixture = &fixture ;
	  }
	  /** @brief 成功・例外にかかわらず借用slotを解除する。 */
	  ~BoundaryScope()
	  {
		  activeFixture = nullptr ;
	  }
	  /** @brief scopeの二重所有を禁止する。
	 * @param[in] other 複写不能な元scope。
	 */
	  BoundaryScope( const BoundaryScope &other) = delete ;
	  /** @brief scopeの複写代入を禁止する。
	 * @param[in] other 複写不能な元scope。
	 * @return 呼出し不能であり値を返さない。
	 */
	  BoundaryScope &operator=( const BoundaryScope &other) = delete ;
} ;

/** @brief 同じ原memberへ実byteを再照合する。
 * @param[in] workspace 今回抽出した保護領域。
 * @param[in] name 原memberの相対名。
 * @return 一致0、未設定・未知member・hash差のHRESULT。
 */
NativeError checkFixtureMember( const OfficialDownloadWorkspace &workspace,
							   const std::wstring_view			name)
{
	// 未設定境界は成功へfallbackしない。
	if( activeFixture == nullptr) {
		return E_UNEXPECTED ;
	}

	const auto member = activeFixture->find( name) ;	// 同じ元入力の固定値。
	// 未知fileをbasenameや表示名で補完しない。
	if( member == nullptr) {
		return E_UNEXPECTED ;
	}

	return verifyOfficialFileMetadata( workspace.path( name), {member->bytes.size(), member->hash}) ;
}
/** @brief 通常結果と研究結果の元field不変を確認する既存回帰へ接続する。
 * @param[in,out] context 元assertion集計。
 * @param[in] normal 観測なしの通常結果。
 * @param[in] observed 同じ入力の研究結果。
 */
void expectObservationUnchanged( TestContext								 &context,
								const MaintenanceDriverPackageInspection &normal,
								const MaintenanceDriverPackageInspection &observed) ;

/** @brief 保持済み構造だけから残件分類する有限八群の正負境界を確認する。
 * @param[in,out] context 元分母を保持したassertion集計。
 * @note 架空保持結果と実reader fixtureだけを使い、追加native照会や導入は行わない。
 */
void testResidualReferenceObservation( TestContext &context)
{
	constexpr std::string_view STDOUT =
		"{\"schema\":\"fixture-v2\"}\r\n" ;	// 実CRLF hashの固定byte。
	// 元16群を置換せず、新八群を各一回の有限fixtureで検査する。
	for( std::size_t group = 0U; group < 8U; ++group) {
		MaintenanceDriverPackageInspection inspection ;	// 通常DTOの元fieldを保持する。
		inspection.infs.resize( 1U) ;
		inspection.infs.front().infSha256 = std::wstring( 64U, L'a') ;
		MaintenanceDriverClosure closure ;	// 架空の最終保持結果。再読取りはしない。
		closure.structure.infSha256 =
			// 元row結合を満たす保持hash。
			inspection.infs.front().infSha256 ;
		closure.references.resize( 1U) ;
		auto &reference		= closure.references.front() ;	// 同INF内の保持根拠だけ。
		reference.infSha256 = inspection.infs.front().infSha256 ;
		reference.inventory.selectedInstallSection = L"Install.NT" ;
		const auto addUse						   = [&reference]( const std::wstring_view directive,
										  const std::wstring_view section = L"Install.NT") {
			 reference.files.push_back( {std::wstring( section),
										std::wstring( directive),
										{},
										{},
										MaintenanceInfFileLocation::UNSUPPORTED,
										UNSUPPORTED_ERROR}) ;
		} ; // 元UNSUPPORTEDの順序をscope内だけで追加する。
		// registry二markerと重なる全節gapを保持し、source有無を証明へ使わない。
		if( group == 0U) {
			addUse( L"RegistryFileUsesNotAssessed", L"Registry") ;
			addUse( L"RegistryFileUseNotAssessed", L"Registry") ;
			reference.inventory.coverageGaps.push_back(
				{L"Registry", {}, OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED}) ;
		}

		// 未追跡七directive、eventlog、software、依存を保持根拠へ結ぶ。
		if( group == 1U) {
			constexpr std::array<std::wstring_view, 7U> NAMES{
				L"AddProperty", L"DelProperty",		L"LogConfig", L"ProfileItems",
				L"UpdateInis",	L"UpdateIniFields", L"Ini2Reg"} ;	// 既存readerの有限語。
			// 各既知未追跡参照に対応gapを一件ずつ追加する。
			for( const auto name : NAMES) {
				addUse( name) ;
				reference.inventory.coverageGaps.push_back(
					{L"Install.NT", std::wstring( name),
					 OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES}) ;
			}

			addUse( L"AddService") ;
			addUse( L"AddSoftware") ;
			addUse( L"CopyINF") ;
			addUse( L"AddComponent") ;
			reference.inventory.coverageGaps.push_back(
				{L"Install.NT", L"AddService",
				 OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG}) ;
			reference.inventory.coverageGaps.push_back(
				{L"Install.NT", L"AddSoftware",
				 OfficialInfInstallCoverageKind::SOFTWARE_INSTALLATION_NOT_ASSESSED}) ;
			reference.inventory.references.push_back( {L"Install.NT", L"CopyINF", L"peer.inf",
													  OfficialInfInstallReferenceKind::COPY_INF}) ;
			reference.inventory.effects.push_back(
				{L"Install.NT", L"AddComponent",
				 OfficialInfInstallEffectKind::EXPLICIT_DEPENDENCY}) ;
		}

		// dataとnamed不足、元UNKNOWN、根拠なしfallbackを別固定語へ分ける。
		if( group == 2U) {
			addUse( L"DataRowsNotInterpreted", L"Data") ;
			addUse( L"NamedServiceStructureNotAssessed") ;
			addUse( L"NamedServiceAssociationNotAssessed") ;
			addUse( L"FictionalUnknown") ;
			addUse( L"FictionalFallback") ;
			reference.inventory.coverageGaps.push_back(
				{L"Data", {}, OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED}) ;
			reference.inventory.effects.push_back(
				{L"Install.NT", L"FictionalUnknown",
				 OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE}) ;
		}

		// 同節case・共有複数gapの全一致と矛盾／別節を確認する。
		if( group == 3U) {
			addUse( L"aDdPrOpErTy", L"iNsTaLl.nT") ;
			addUse( L"AddProperty", L"OtherSection") ;
			reference.inventory.coverageGaps = {
				{L"INSTALL.NT", L"ADDPROPERTY",
				 OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES},
				{L"install.nt", L"addproperty",
				 OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES},
				{L"Install.NT", L"AddProperty", OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE},
				{L"GapOnly", L"AddProperty",
				 OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES}} ;
		}

		// 実readerで未到達／別OS／seedなし、SYSTEMとFAILED、元byte／取消しを保持する。
		if( group == 4U || group == 5U) {
			// 各正負fixtureは同じ元条件で通常と研究を比較する。
			for( std::size_t variant = 0U; variant < 5U; ++variant) {
				MatrixCase spec ;	// 元matrixの分母と既定を保持する。
				spec.install = "AddReg=Registry\r\n" ;
				std::string extra =
					"[Registry]\r\nHKR,,FictionalValue,0,sample.dll\r\n"
					"[Unreached]\r\nFictionalOnly=sample.sys\r\n"
					"[Install.NTx86]\r\nFictionalOtherOS=sample.sys\r\n" ;	// 架空本文は保存しない。
				// source有無がregistry markerの非file証明にならない。
				if( group == 4U) {
					spec.rootSource	 = variant != 1U ;
					spec.includeOnly = variant == 2U ;
					spec.nativeMode	 = variant == 2U ? NativeMode::PACKAGE : NativeMode::NONE ;
				}

				// root／依存の既知失敗とSYSTEMの全payload未評価を保持する。
				if( group == 5U) {
					spec.rootError	= variant == 0U ? SIGNATURE_FAILURE : 0U ;
					spec.nativeMode = variant == 1U
										  ? NativeMode::PACKAGE_FAILED
										  : (variant == 2U ? NativeMode::SYSTEM : NativeMode::NONE) ;
				}

				BoundaryFixture fixture( spec, 5500U + group * 10U + variant, "Ports",
										extra) ;										// 所有scope。
				BoundaryScope	scope( fixture) ;										// 架空署名応答を同期借用する。
				MaintenanceDriverPackageInspection normal ;								// 通常全field。
				MaintenanceDriverPackageInspection observed ;							// 新mode同field。
				ReachedReferenceCollector collector( ReachedReferenceMode::RESIDUAL) ;	// 新modeだけ。
				DriverArchiveInput		  input = fixture.input ;						// 不正byteだけで期待hashを変える。
				// 元byte拒否で部分観測を確定しない。
				if( group == 5U && variant == 3U) {
					input.sha256 = std::wstring( 64U, L'b') ;
				}

				std::size_t					checks{} ;	// 元取消しの有限呼出し数。
				const std::function<bool()> cancel = [&checks, group, variant]() {
					return group == 5U && variant == 4U && ++checks == 3U ;
				} ; // 各入口で同じ取消し順序を使う。
				const auto normalError = inspectMaintenanceDriverPackage(
					input, OfficialDriverArchiveFormat::ZIP, normal, cancel) ;	// 元入口。
				checks			 = 0U ;
				const auto error = inspectReachedMaintenanceDriverPackage(
					input, OfficialDriverArchiveFormat::ZIP, observed, collector,
					cancel) ;	// 同closure一回借用。
				DRIVERCRATE_EXPECT( context, error == normalError) ;
				expectObservationUnchanged( context, normal, observed) ;
				const auto value =
					// 元全byteへ結ぶ。
					collector.serialize( "fixture", observed, STDOUT) ;
				// 元拒否なら観測全体も空にする。
				if( error != 0) {
					DRIVERCRATE_EXPECT( context, collector.rootCount() == 0U && !value) ;
				} else {
					DRIVERCRATE_EXPECT( context,
									   value && value->find( "FictionalOnly") == std::string::npos &&
										   value->find( "FictionalOtherOS") == std::string::npos &&
										   value->find( "sample.dll") == std::string::npos) ;
				}
			}

			continue ;
		}

		// 共同4096／訪問1024／opaque4096と＋1、全serialization拒否を検査する。
		if( group == 6U) {
			addUse( L"FictionalFallback") ;
			reference.inventory.coverageGaps.resize(
				4095U, {L"Gap", {}, OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED}) ;
			reference.inventory.visitedSections.resize( 1024U, L"Visited") ;
			ReachedReferenceCollector exact( ReachedReferenceMode::RESIDUAL) ;	// 共同上限。
			exact.append( closure, inspection.infs.front(), 0U) ;
			exact.finish( inspection) ;
			DRIVERCRATE_EXPECT( context, exact.error() == 0 &&
											exact.serialize( "fixture", inspection, STDOUT)) ;
			reference.inventory.coverageGaps.push_back( reference.inventory.coverageGaps.front()) ;
			ReachedReferenceCollector excess( ReachedReferenceMode::RESIDUAL) ;	// 共同＋1。
			excess.append( closure, inspection.infs.front(), 0U) ;
			DRIVERCRATE_EXPECT( context, excess.error() != 0 && excess.rootCount() == 0U) ;
			reference.inventory.coverageGaps.clear() ;
			reference.inventory.visitedSections.push_back( L"Extra") ;
			ReachedReferenceCollector visited( ReachedReferenceMode::RESIDUAL) ;	// 訪問＋1。
			visited.append( closure, inspection.infs.front(), 0U) ;
			DRIVERCRATE_EXPECT( context, visited.error() != 0 && visited.rootCount() == 0U) ;
			reference.inventory.visitedSections.clear() ;
			reference.files.clear() ;
			// gap4095＋seed1のopaque上限を1MiB内の全serializedで確認する。
			for( std::size_t index = 0U; index < 4095U; ++index) {
				reference.inventory.coverageGaps.push_back(
					{L"Opaque" + std::to_wstring( index),
					 {},
					 OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED}) ;
			}

			ReachedReferenceCollector opaque( ReachedReferenceMode::RESIDUAL) ;	// 共同opaque上限。
			opaque.append( closure, inspection.infs.front(), 0U) ;
			opaque.finish( inspection) ;
			const auto opaqueValue =
				// 全serialized内の4096節正例。
				opaque.serialize( "fixture", inspection, STDOUT) ;
			DRIVERCRATE_EXPECT( context,
							   opaque.error() == 0 && opaqueValue &&
								   opaqueValue->find( "\"sectionId\":4096") != std::string::npos) ;
			reference.inventory.coverageGaps.push_back(
				{L"ExtraOpaque", {}, OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED}) ;
			ReachedReferenceCollector opaqueOver(
				ReachedReferenceMode::RESIDUAL) ;	// 用途とgap共同opaque＋1。
			opaqueOver.append( closure, inspection.infs.front(), 0U) ;
			DRIVERCRATE_EXPECT( context, opaqueOver.error() != 0 && opaqueOver.rootCount() == 0U) ;
			reference.inventory.coverageGaps.clear() ;
			addUse( L"FictionalFallback") ;
			reference.files.resize( 1600U, reference.files.front()) ;
			ReachedReferenceCollector serialized(
				ReachedReferenceMode::RESIDUAL) ;	// 全package serialization上限。
			serialized.append( closure, inspection.infs.front(), 0U) ;
			DRIVERCRATE_EXPECT( context, serialized.error() == 0 && serialized.rootCount() == 1U) ;
			serialized.append( closure, inspection.infs.front(), 1U) ;
			DRIVERCRATE_EXPECT( context, serialized.error() != 0 && serialized.rootCount() == 0U) ;
			continue ;
		}

		// 新modeにも元診断を残し、全固定語以外のprivacy値を保存しない。
		if( group == 7U) {
			addUse( L"FictionalFallback") ;
			reference.files.front().target = L"https://fictional.invalid/private-name.sys" ;
		}

		ReachedReferenceCollector collector( ReachedReferenceMode::RESIDUAL) ;	// 新schemaだけ。
		collector.append( closure, inspection.infs.front(), 0U) ;
		collector.finish( inspection) ;
		const auto value =
			// 実byteのhashを含む。
			collector.serialize( "fixture", inspection, STDOUT) ;
		DRIVERCRATE_EXPECT( context, value.has_value()) ;
		// optional不成立では本文を参照せず元失敗を残す。
		if( !value) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   value->find( "dc-maintenance-residual-reference-observation-v1") !=
								   std::string::npos &&
							   value->find( std::to_string( UNSUPPORTED_ERROR)) != std::string::npos) ;
		// 同節二markerを独立分類し、対応範囲は節だけにする。
		if( group == 0U) {
			DRIVERCRATE_EXPECT(
				context,
				value->find( "REGISTRY_SCOPE_MARKER_UNASSESSED") != std::string::npos &&
					value->find( "REGISTRY_DATA_FILE_CANDIDATE_UNASSESSED") != std::string::npos &&
					value->find( "SAME_SECTION_ONLY") != std::string::npos) ;
			reference.sourceSectionPresent = true ;
			ReachedReferenceCollector source(
				ReachedReferenceMode::RESIDUAL) ;	// source有無で分類を変えない。
			source.append( closure, inspection.infs.front(), 0U) ;
			source.finish( inspection) ;
			const auto withSource =
				// 分類は維持する。
				source.serialize( "fixture", inspection, STDOUT) ;
			DRIVERCRATE_EXPECT( context,
							   withSource && withSource->find( "REGISTRY_SCOPE_MARKER_UNASSESSED") !=
												 std::string::npos) ;
		}

		// 既知不足と依存の固定分類は根拠ありでだけ成立する。
		if( group == 1U) {
			constexpr std::array<std::string_view, 5U> EXPECTED{
				"UNFOLLOWED_SECTION_REFERENCES", "UNFOLLOWED_SERVICE_EVENTLOG",
				"SOFTWARE_INSTALLATION_UNASSESSED", "COPYINF_PACKAGE_DEPENDENCY",
				"COMPONENT_DEPENDENCY_UNASSESSED"} ;	// 限定分類。
			// 各種類の存在を検査し、種類数を用途数と混同しない。
			for( const auto expected : EXPECTED) {
				DRIVERCRATE_EXPECT( context, value->find( expected) != std::string::npos) ;
			}

			reference.inventory = {} ;
			ReachedReferenceCollector absent(
				ReachedReferenceMode::RESIDUAL) ;	// 根拠なしはfallback。
			absent.append( closure, inspection.infs.front(), 0U) ;
			absent.finish( inspection) ;
			const auto withoutEvidence =
				// 再解釈しない。
				absent.serialize( "fixture", inspection, STDOUT) ;
			DRIVERCRATE_EXPECT(
				context,
				withoutEvidence &&
					withoutEvidence->find( "COPYINF_PACKAGE_DEPENDENCY") == std::string::npos &&
					withoutEvidence->find( "COMPONENT_DEPENDENCY_UNASSESSED") == std::string::npos) ;
		}

		// named・data・未知・fallbackを全て保持する。
		if( group == 2U) {
			constexpr std::array<std::string_view, 5U> EXPECTED{
				"OPAQUE_DATA_ROW_UNASSESSED", "NAMED_SERVICE_STRUCTURE_UNASSESSED",
				"NAMED_SERVICE_ASSOCIATION_UNASSESSED", "UNKNOWN_DIRECTIVE_OR_FILE_SEMANTICS",
				"OTHER_UNSUPPORTED_USE"} ;	// 固定五種類。
			// 各元markerが独立して残ることを検査する。
			for( const auto expected : EXPECTED) {
				DRIVERCRATE_EXPECT( context, value->find( expected) != std::string::npos) ;
			}
		}

		// 複数gapは全一致ordinalだけで、gap-only節IDは用途の後へ追加する。
		if( group == 3U) {
			DRIVERCRATE_EXPECT(
				context,
				value->find( "\"coverageGapOrdinals\":[0,1]") != std::string::npos &&
					value->find(
						"\"gapOrdinal\":3,\"kind\":\"UNFOLLOWED_SECTION_REFERENCES\",\"sectionId\":4") !=
						std::string::npos &&
					value->find( "\"coverageGapBinding\":\"NOT_OBSERVED\"") != std::string::npos) ;
		}

		// CRLF実hash、null分母と新modeの未知値拒否を検査する。
		if( group == 7U) {
			std::wstring hash ;												// 実送信全byteを独立CNGで比較する。
			const auto	 hashError = computeBytesSha256( STDOUT, hash) ;	// 元hash APIの診断。
			std::string	 hashBytes ;										// SHA-256のASCII文字だけを明示変換する。
			// CNG hashの各桁を値を変えずに変換し、暗黙narrowingを避ける。
			for( const wchar_t digit : hash) {
				hashBytes.push_back( static_cast<char>( digit)) ;
			}

			DRIVERCRATE_EXPECT( context, hashError == 0 &&
											value->find( hashBytes) != std::string::npos &&
											value->find( "fictional.invalid") == std::string::npos &&
											value->find( "private-name") == std::string::npos &&
											!collector.serialize( "fixture", inspection, "{}\n")) ;
			// 元UNSUPPORTED以外の四状態を細分類の分母へ入れない。
			for( const auto location :
				{MaintenanceInfFileLocation::LOCATED, MaintenanceInfFileLocation::MISSING,
				 MaintenanceInfFileLocation::NOT_CHECKED}) {
				reference.files.front().location = location ;
				ReachedReferenceCollector other( ReachedReferenceMode::RESIDUAL) ;	// null分類だけ。
				other.append( closure, inspection.infs.front(), 0U) ;
				other.finish( inspection) ;
				const auto normal =
					// 元位置を保持する。
					other.serialize( "fixture", inspection, STDOUT) ;
				DRIVERCRATE_EXPECT( context, normal && normal->find( "\"classification\":null") !=
														  std::string::npos) ;
			}

			ReachedReferenceCollector invalid( static_cast<ReachedReferenceMode>( 99U)) ;	// 未知mode。
			DRIVERCRATE_EXPECT( context, invalid.error() != 0 && invalid.rootCount() == 0U) ;
		}
	}

	std::wstring parent = DRIVERCRATE_RESIDUAL_WORKSPACE ;	// 新54固定writer fixture親だけ。
	std::ranges::replace( parent, L'/', L'\\') ;
	const std::wstring path =
		parent +
		L"\\20261008-maintenance-residual-reference-54-fixture-sidecar.json" ;	// 正確な固定stem。
	BoundaryFixture	   fixture( MatrixCase{}, 5599U) ;							// 自分のreparse先だけを所有する。
	const std::wstring target = fixture.input.inspectionPath.substr(
		0U, fixture.input.inspectionPath.find_last_of( L'\\')) ;	// 架空ZIP親。
	const BOOL linked = CreateSymbolicLinkW(
		parent.c_str(), target.c_str(),
		SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) ;	// 親拒否。
	DRIVERCRATE_EXPECT( context, linked != FALSE) ;
	// 自分のlinkだけを解除し、targetの内容を削除しない。
	if( linked != FALSE) {
		DRIVERCRATE_EXPECT( context,
						   writeReachedReferenceSidecar( path, "fixture", "{}",
														ReachedReferenceMode::RESIDUAL) != 0) ;
		DRIVERCRATE_EXPECT( context, RemoveDirectoryW( parent.c_str()) != FALSE) ;
	}

	DRIVERCRATE_EXPECT( context, CreateDirectoryW( parent.c_str(), nullptr) != FALSE) ;
	DRIVERCRATE_EXPECT(
		context, writeReachedReferenceSidecar( path, "fixture", "{}") != 0 &&
					 writeReachedReferenceSidecar( path + L"extra", "fixture", "{}",
												  ReachedReferenceMode::RESIDUAL) != 0 &&
					 writeReachedReferenceSidecar( path, "fixture", "{}",
												  static_cast<ReachedReferenceMode>( 99U)) != 0) ;
	const std::string exact( 1024U * 1024U, 'x') ;	// writer全byte上限の架空値。
	DRIVERCRATE_EXPECT( context,
					   writeReachedReferenceSidecar( path, "fixture", exact + "x",
													ReachedReferenceMode::RESIDUAL) != 0 &&
						   writeReachedReferenceSidecar( path, "fixture", exact,
														ReachedReferenceMode::RESIDUAL) == 0) ;
	DRIVERCRATE_EXPECT(
		context,
		writeReachedReferenceSidecar( path, "fixture", "{}", ReachedReferenceMode::RESIDUAL) ==
			static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_EXISTS))) ;
	// 成功fixtureだけを片付け、実研究sidecarと部分失敗は保持する。
	DRIVERCRATE_EXPECT( context, DeleteFileW( path.c_str()) != FALSE) ;
	DRIVERCRATE_EXPECT( context, RemoveDirectoryW( parent.c_str()) != FALSE) ;
}
} // namespace
} // namespace drivercrate::test

namespace drivercrate {
/** @brief 専用targetだけでroot／全参照の署名応答を模擬する。
 * @param[in] workspace 元byteが固定された架空抽出領域。
 * @param[in] package 呼出し本体が生成したINF／CAT／全local member。
 * @return 設定済み架空署名診断。未知入力・未設定はE_UNEXPECTED。
 * @note 実CAT暗号署名を検証しない。製品sourceへこのsymbolを定義しない。
 */
NativeError verifyMaintenanceInfIntegrityForTest( const OfficialDownloadWorkspace &workspace,
												 const OfficialInfPackage		 &package)
{
	using namespace test ;
	// 未設定scopeと未知rootを成功へfallbackしない。
	if( activeFixture == nullptr ||
	   (package.infRelativePath != L"sample.inf" && package.infRelativePath != L"peer.inf")) {
		return E_UNEXPECTED ;
	}

	const bool	root = package.infRelativePath == L"sample.inf" ;	// 元ROOTの役割を原名へ結ぶ。
	const auto &sources =
		root ? activeFixture->rootSources : activeFixture->peerSources ;	// 全集合。
	// CATと全source集合が期待と完全一致しない要求も拒否する。
	if( package.catalogRelativePath != (root ? L"sample.cat" : L"peer.cat") ||
	   package.sourceFiles != sources) {
		return E_UNEXPECTED ;
	}

	activeFixture->signatureCalls.push_back(
		{package.infRelativePath, package.catalogRelativePath, package.sourceFiles}) ;
	const std::array required{package.infRelativePath,
							  package.catalogRelativePath} ;	// INF自身も必須。
	// INF／CATを必ず確認し、nullの空sourceも空member成功にしない。
	for( const auto &name : required) {
		const NativeError error = checkFixtureMember( workspace, name) ;	// 同じ原byte再照合。
		// 先行byte失敗を架空署名成功で隠さない。
		if( error != 0) {
			return error ;
		}
	}

	// 全local payloadを同じ原member集合へ結ぶ。
	for( const auto &name : sources) {
		const NativeError error = checkFixtureMember( workspace, name) ;	// 個別の元byte。
		// 一fileの失敗でも全署名成功値を返さない。
		if( error != 0) {
			return error ;
		}
	}

	return root ? activeFixture->rootError : activeFixture->peerError ;
}

/** @brief 専用targetだけで有限核へ架空native証拠を供給する。
 * @param[in] workspace 実hash固定済みの架空抽出領域。
 * @param[in] members 呼出し本体が準備した閉じたINF集合。
 * @param[in] rootIndex 元rootの位置。今回0だけを扱う。
 * @param[in] seeds 実SetupAPI readerが選んだroot seed群。
 * @param[in] observationId 非零の同run観測世代。
 * @param[out] result 核成功時だけの架空native結果。拒否時は空。
 * @return 架空観測0、不正入力／未知member／核拒否のHRESULT。
 * @note SYSTEMの証拠は架空。実OS・trust・Driver Store・PnPを呼ばない。
 */
NativeError inspectMaintenanceInfDependenciesForTest(
	const OfficialDownloadWorkspace					 &workspace,
	const std::span<const InfDependencyPackageMember> members, const std::size_t rootIndex,
	const std::span<const std::wstring> seeds, const std::uint64_t observationId,
	InfDependencyNativeResult &result)
{
	using namespace test ;
	result = {} ;
	// 未設定、未知root、容量外、seedなしを成功の空graphへ変換しない。
	if( activeFixture == nullptr || rootIndex != 0U || members.empty() || members.size() > 2U ||
	   members.front().relativePath != L"sample.inf" || observationId == 0U || seeds.empty()) {
		return E_UNEXPECTED ;
	}

	const bool packagePeer = activeFixture->nativeMode == NativeMode::PACKAGE ||
							 // 原ZIPに参照INFを持つ構成だけ。
							 activeFixture->nativeMode == NativeMode::PACKAGE_FAILED ;
	// member全集合・順序と原seedを完全比較し、未知候補を成功へfallbackしない。
	if( members.size() != (packagePeer ? 2U : 1U) ||
	   (packagePeer && members[1U].relativePath != L"peer.inf") ||
	   !std::ranges::equal( seeds, activeFixture->rootSeeds)) {
		return E_UNEXPECTED ;
	}

	++activeFixture->nativeCalls ;

	const InfDependencyContext context{10U, 0U, 26100U, 0x8664U, false, observationId} ;	// 架空OS。
	std::vector<InfDependencyDocument> documents ;											// 同じ原memberの有限証拠集合。
	// 閉じた元INFの実hashとsizeを照合し、由来は裸PACKAGEのまま保持する。
	for( const auto &member : members) {
		const auto original = activeFixture->find( member.relativePath) ;	// 一元の原member。
		// 未知名・表示hash差・実byte差を証拠不足へ弱めない。
		if( original == nullptr || member.sha256 != original->hash ||
		   member.byteCount != original->bytes.size() ||
		   checkFixtureMember( workspace, member.relativePath) != 0) {
			return E_UNEXPECTED ;
		}

		documents.push_back( {documents.size() + 1U, member.sha256, member.byteCount,
							 InfDependencyOrigin::PACKAGE, InfDependencyEvidence::VERIFIED,
							 InfDependencyEvidence::NOT_CHECKED,
							 member.relativePath == L"peer.inf" &&
									 activeFixture->nativeMode == NativeMode::PACKAGE_FAILED
								 ? InfDependencyEvidence::FAILED
								 : InfDependencyEvidence::VERIFIED,
							 context}) ;
	}

	const NativeMode mode = activeFixture->nativeMode ;	// scope中だけの架空分類。
	// SYSTEM応答はINF自身だけの三軸で、実payload位置を作らない。
	if( mode == NativeMode::SYSTEM || mode == NativeMode::SYSTEM_FAILED) {
		documents.push_back( {2U, std::wstring( 64U, L'a'), 123U, InfDependencyOrigin::SYSTEM,
							 InfDependencyEvidence::VERIFIED, InfDependencyEvidence::VERIFIED,
							 mode == NativeMode::SYSTEM_FAILED ? InfDependencyEvidence::FAILED
															   : InfDependencyEvidence::VERIFIED,
							 context}) ;
	}

	// 同期核だけがこのscopeのtableを借用し、明示辺とseedの解決を実処理する。
	const InfDependencyOperations operations{
		[&documents, mode]( const auto &source, const std::wstring_view name,
						   InfDependencyLookup &out) {
			out = {} ;
			// 未知の照会を通常の未発見へfallbackしない。
			if( source.identity != 1U || name != L"peer.inf" || mode == NativeMode::NONE) {
				return NativeError{E_UNEXPECTED} ;
			}

			out.checked = true ;
			// 照会済み未発見はこの一matrixだけで明示する。
			if( mode != NativeMode::MISSING && documents.size() == 2U) {
				out.documents.push_back( documents.back()) ;
			}

			return NativeError{} ;
		},
		[mode]( const auto &source, const std::wstring_view name, InfDependencySection &out) {
			out = {} ;
			// 実readerが渡したroot節と原Needs対象だけへ応答する。
			if( source.identity == 1U && (name == L"Install.NT" || name == L"Install.NT.Services" ||
										 name == L"Install.NT.CoInstallers" ||
										 (name == L"Install.NT.Software" &&
										  std::ranges::find( activeFixture->rootSeeds, name) !=
											  activeFixture->rootSeeds.end()))) {
				out.state = InfDependencyReadState::PRESENT ;
				// base節だけのInclude／NeedsをServicesへ流用しない。
				if( name == L"Install.NT" && mode != NativeMode::NONE) {
					out.references = {{InfDependencyDirective::INCLUDE, L"peer.inf"}} ;
					// 原fixtureが持たないNeedsをfakeで追加しない。
					if( !activeFixture->includeOnly) {
						out.references.push_back( {InfDependencyDirective::NEEDS, L"Shared"}) ;
					}

					// 新fixtureの原追加seedだけを同じ核へ引き継ぐ。
					if( activeFixture->sharedNeed) {
						out.references.push_back( {InfDependencyDirective::NEEDS, L"Additional"}) ;
					}
				}
			}
			// 参照INFの明示Shared節だけを存在観測へ回答する。
			else if( source.identity == 2U &&
					(name == L"Shared" || (activeFixture->sharedNeed && name == L"Additional"))) {
				// 参照INFの存在だけを回答し、CopyFiles全payload成功を追加しない。
				out.state = InfDependencyReadState::PRESENT ;
			}
			// root自身のShared不在と外部候補の存在を区別する。
			else if( source.identity == 1U &&
					(name == L"Shared" || (activeFixture->sharedNeed && name == L"Additional"))) {
				// 同INFで調べる原Needs名の不存在だけを明示する。
				out.state = InfDependencyReadState::MISSING ;
			} else {
				// 未知identity／節名を通常の未発見へfallbackしない。
				return NativeError{E_UNEXPECTED} ;
			}

			return NativeError{} ;
		},
		[&documents]( const auto &snapshot) {
			const auto original = std::ranges::find_if( documents, [&snapshot]( const auto &item) {
				return item.identity == snapshot.identity && item.sha256 == snapshot.sha256 &&
					   item.byteCount == snapshot.byteCount ;
			}) ; // 同期核の原tableだけを借用する架空再確認。
			return original == documents.end() ? NativeError{E_UNEXPECTED} : NativeError{} ;
		}} ; // 実nativeのhandle／OS再確認とは別の架空境界。
	const NativeError error = resolveInfDependencies( documents.front(), seeds, operations,
													 result.dependency) ;	// 有限核本体。
	// 核の拒否でも部分graphを公開しない。
	if( error != 0) {
		result = {} ;
		return error ;
	}

	// 各署名findingの元HRESULTを独立したgraph identityへ結ぶ。
	for( const auto &document : result.dependency.documents) {
		result.findings.push_back(
			{document.identity,
			 document.signature == InfDependencyEvidence::FAILED ? SIGNATURE_FAILURE : 0, 0}) ;
	}

	// 架空境界で実hash照合したINFの個数だけ。
	result.fixedFileCount = members.size() ;
	// 共同byte予算も実memberの有限量だけを渡し、systemの実確認と呼ばない。
	for( const auto &member : members) {
		result.fixedByteCount += member.byteCount ;
	}

	return 0 ;
}
} // namespace drivercrate

namespace drivercrate::test {
namespace {
/** @brief 元閉包と共通DTOの全独立軸・診断を比較する。
 * @param[in,out] context 有限assertion集計。
 * @param[in] closure 同じ元rootの実閉包。
 * @param[in] row 同じ元hashに結合した保守DTO。
 */
void expectProjection( TestContext &context, const MaintenanceDriverClosure &closure,
					  const MaintenanceInfInspection &row)
{
	DRIVERCRATE_EXPECT( context, row.parser.state == closure.structure.parser.state &&
									row.parser.error == closure.structure.parser.error) ;
	DRIVERCRATE_EXPECT( context, row.contentKind == closure.structure.contentKind &&
									row.referenceCoverage == closure.structure.referenceCoverage) ;
	DRIVERCRATE_EXPECT( context,
					   row.rootIntegrity.state == closure.structure.rootIntegrity.state &&
						   row.rootIntegrity.error == closure.structure.rootIntegrity.error) ;
	DRIVERCRATE_EXPECT( context, row.integrity.state == closure.integrity.state &&
									row.integrity.error == closure.integrity.error) ;
	DRIVERCRATE_EXPECT( context, row.dependency.state == closure.structure.dependency.state &&
									row.dependency.reason == closure.structure.dependency.reason &&
									row.dependency.error == closure.structure.dependency.error) ;
	DRIVERCRATE_EXPECT( context, row.dependency.observedReferenceCount ==
										closure.structure.dependency.observedReferenceCount &&
									row.dependency.resolvedInfCount ==
										closure.structure.dependency.resolvedInfCount) ;
	DRIVERCRATE_EXPECT( context,
					   row.applicability.state == MaintenanceInspectionState::NOT_CHECKED &&
						   row.applicability.error == 0) ;
	DRIVERCRATE_EXPECT(
		context, row.dependenciesChecked ==
						 (row.dependency.state != MaintenanceInfDependencyState::NOT_CHECKED) &&
					 row.hasExternalDependencies ==
						 (row.dependenciesChecked && row.dependency.observedReferenceCount != 0U)) ;
	DRIVERCRATE_EXPECT( context, row.inspectedBytes == closure.content.expandedBytes &&
									row.infSha256 == closure.structure.infSha256) ;
}

/** @brief root成功・部分閉包・既知FAILEDの不足構成を作る。
 * @param[in] index 0～11の固定matrix位置。
 * @return 一構成の元入力と独立期待。
 */
MatrixCase matrixCase( const std::size_t index)
{
	MatrixCase spec ;	// 通常Portsの全local参照署名が架空成功する基準。
	// 不足の状態組合せだけを一条件ずつ変更する。
	switch( index) {
		// sourceなし無参照nullもINF自身／CATが必要。
		case 0U:
			spec.rootSource	 = false ;
			spec.nullService = true ;
			break ;

		// 宣言済みroot SYS欠落をnullの無参照へ補完しない。
		case 1U:
			spec.rootFile	 = false ;
			spec.nullService = true ;
			spec.coverage	 = MaintenanceInfReferenceCoverage::INCOMPLETE ;
			spec.whole		 = MaintenanceInspectionState::NOT_CHECKED ;
			break ;

		// 未解釈用途はroot成功だけで全署名成功にしない。
		case 2U:
			spec.install  = "UnknownFileUse=mystery.dll\r\n" ;
			spec.coverage = MaintenanceInfReferenceCoverage::INCOMPLETE ;
			spec.whole	  = MaintenanceInspectionState::NOT_CHECKED ;
			break ;

		// 全local位置・全署名は裸PACKAGE由来未検査と独立。
		case 3U:
			spec.nativeMode = NativeMode::PACKAGE ;
			spec.dependency = MaintenanceInfDependencyState::OBSERVED ;
			break ;

		// 依存INF自身の成功を必要SYS全byteの成功へ使わない。
		case 4U:
			spec.nativeMode = NativeMode::PACKAGE ;
			spec.peerFile	= false ;
			spec.dependency = MaintenanceInfDependencyState::OBSERVED ;
			spec.coverage	= MaintenanceInfReferenceCoverage::INCOMPLETE ;
			spec.whole		= MaintenanceInspectionState::NOT_CHECKED ;
			break ;

		// 照会済み未発見も独立した未解決状態で残す。
		case 5U:
			spec.nativeMode = NativeMode::MISSING ;
			spec.dependency = MaintenanceInfDependencyState::UNRESOLVED ;
			spec.coverage	= MaintenanceInfReferenceCoverage::INCOMPLETE ;
			spec.whole		= MaintenanceInspectionState::NOT_CHECKED ;
			break ;

		// SYSTEM INF三証拠が揃っても全payload位置は不明。
		case 6U:
			spec.rootSource = false ;
			spec.nativeMode = NativeMode::SYSTEM ;
			spec.dependency = MaintenanceInfDependencyState::RESOLVED_CURRENT_OS ;
			spec.coverage	= MaintenanceInfReferenceCoverage::INCOMPLETE ;
			spec.whole		= MaintenanceInspectionState::NOT_CHECKED ;
			break ;

		// SYSTEMの既知署名FAILEDを全payload不明で消さない。
		case 7U:
			spec.rootSource = false ;
			spec.nativeMode = NativeMode::SYSTEM_FAILED ;
			spec.dependency = MaintenanceInfDependencyState::OBSERVED ;
			spec.coverage	= MaintenanceInfReferenceCoverage::INCOMPLETE ;
			spec.whole		= MaintenanceInspectionState::FAILED ;
			spec.wholeError = SIGNATURE_FAILURE ;
			break ;

		// root署名FAILEDも未知用途によるNOT_CHECKEDへ落とさない。
		case 8U:
			spec.install	= "UnknownFileUse=mystery.dll\r\n" ;
			spec.rootError	= static_cast<NativeError>( TRUST_E_NOSIGNATURE) ;
			spec.coverage	= MaintenanceInfReferenceCoverage::INCOMPLETE ;
			spec.whole		= MaintenanceInspectionState::FAILED ;
			spec.wholeError = spec.rootError ;
			break ;

		// 依存INF署名FAILEDと原HRESULTをroot成功で消さない。
		case 9U:
			spec.nativeMode = NativeMode::PACKAGE_FAILED ;
			spec.dependency = MaintenanceInfDependencyState::OBSERVED ;
			spec.whole		= MaintenanceInspectionState::FAILED ;
			spec.wholeError = SIGNATURE_FAILURE ;
			break ;

		// 依存INF自身の成功の後に全payload CAT memberが失敗する。
		case 10U:
			spec.nativeMode = NativeMode::PACKAGE ;
			spec.peerError	= SIGNATURE_FAILURE ;
			spec.dependency = MaintenanceInfDependencyState::OBSERVED ;
			spec.whole		= MaintenanceInspectionState::FAILED ;
			spec.wholeError = SIGNATURE_FAILURE ;
			break ;

		// 未解決依存とroot既知失敗を同時に保持する。
		case 11U:
			spec.nativeMode = NativeMode::MISSING ;
			spec.rootError	= static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
			spec.dependency = MaintenanceInfDependencyState::UNRESOLVED ;
			spec.coverage	= MaintenanceInfReferenceCoverage::INCOMPLETE ;
			spec.whole		= MaintenanceInspectionState::FAILED ;
			spec.wholeError = spec.rootError ;
			break ;

		// 未登録matrixを正常fixtureとして増やさない。
		default:
			throw std::runtime_error( "unknown matrix") ;
	}

	return spec ;
}

/** @brief 十二の不足署名・全参照組合せを実閉包とDTOへ接続する。
 * @param[in,out] context 有限assertion集計。
 */
void testIntegrityMatrix( TestContext &context)
{
	// 各rootを同じ一runへ固定し、未知と失敗を分母へ残す。
	for( std::size_t index = 0U; index < 12U; ++index) {
		const MatrixCase spec = matrixCase( index) ;						// 原構成と期待を一度だけ所有する。
		BoundaryFixture	 fixture( spec, 900U + index) ;						// 実driverを含まない一元ZIP。
		BoundaryScope	 scope( fixture) ;									// 呼出し終了までの専用応答借用。
		const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 原root一件。
		OfficialDownloadWorkspace				workspace ;					// 閉包の単独所有。
		MaintenanceDriverClosure				closure ;					// 内容専用の独立結果。
		const NativeError						error = extractMaintenanceDriverClosure(
			  {&fixture.input,
								   OfficialDriverArchiveFormat::ZIP,
								   {},
								   selected,
								   L"maint-integrity-out"},
			  CONTENT_POLICY, workspace, closure) ;	// 製品と同じ閉包集約本体。
		DRIVERCRATE_EXPECT( context, error == 0) ;
		// 失敗fixtureの部分結果を参照してprocessを破壊しない。
		if( error != 0) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, closure.structure.referenceCoverage == spec.coverage) ;
		DRIVERCRATE_EXPECT( context,
						   closure.structure.rootIntegrity.state ==
								   (spec.rootError == 0 ? MaintenanceInspectionState::PASSED
														: MaintenanceInspectionState::FAILED) &&
							   closure.structure.rootIntegrity.error == spec.rootError) ;
		DRIVERCRATE_EXPECT( context, closure.integrity.state == spec.whole &&
										closure.integrity.error == spec.wholeError) ;
		DRIVERCRATE_EXPECT( context, closure.structure.dependency.state == spec.dependency) ;
		DRIVERCRATE_EXPECT( context, fixture.nativeCalls == 1U) ;
		const std::size_t expectedCalls =
			// rootと必要全payload。
			index == 3U || index == 10U ? 2U : 1U ;
		DRIVERCRATE_EXPECT( context, fixture.signatureCalls.size() == expectedCalls) ;
		// 呼出し欠落の回帰を不一致として保持し、空vectorの参照でprocessを壊さない。
		if( !fixture.signatureCalls.empty()) {
			DRIVERCRATE_EXPECT( context,
							   fixture.signatureCalls.front().inf == L"sample.inf" &&
								   fixture.signatureCalls.front().catalog == L"sample.cat" &&
								   fixture.signatureCalls.front().sources == fixture.rootSources) ;
		}

		// 全位置完了の参照packageだけを自身のCATへ検査する。
		if( expectedCalls == 2U && fixture.signatureCalls.size() == 2U) {
			DRIVERCRATE_EXPECT( context, fixture.signatureCalls.back().inf == L"peer.inf" &&
											fixture.signatureCalls.back().catalog == L"peer.cat" &&
											fixture.signatureCalls.back().sources ==
												std::vector<std::wstring>{L"peer.sys"}) ;
		}

		DRIVERCRATE_EXPECT( context, !closure.dependency.dependency.plan.rootEvidenceVerified &&
										closure.dependency.dependency.plan.actionCoverage ==
											InfDependencyEvidence::NOT_CHECKED &&
										closure.dependency.dependency.plan.deviceApplicability ==
											InfDependencyEvidence::NOT_CHECKED &&
										closure.dependency.dependency.plan.installRoute ==
											InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT(
			context,
			std::ranges::all_of( closure.dependency.dependency.documents, []( const auto &document) {
				return document.origin != InfDependencyOrigin::PACKAGE ||
					   document.provenance == InfDependencyEvidence::NOT_CHECKED ;
			})) ; // 裸由来を昇格しない。
		// 元署名診断がsummaryとfindingから失われないことも比較する。
		if( index == 7U || index == 9U) {
			DRIVERCRATE_EXPECT( context, closure.structure.dependency.error == SIGNATURE_FAILURE &&
											std::ranges::any_of( closure.dependency.findings,
																[]( const auto &finding) {
																	return finding.signatureError ==
																		   SIGNATURE_FAILURE ;
																})) ;
		}

		fixture.signatureCalls.clear() ;
		fixture.nativeCalls = 0U ;
		MaintenanceDriverPackageInspection result ;	// 同じrootを独立した共通DTOへ射影する。
		DRIVERCRATE_EXPECT( context,
						   inspectMaintenanceDriverPackage(
							   fixture.input, OfficialDriverArchiveFormat::ZIP, result) == 0) ;
		const auto row = std::ranges::find_if( result.infs, [&closure]( const auto &item) {
			return item.infSha256 == closure.structure.infSha256 ;
		}) ; // 同じ元hashへ結び、peer行を先頭として代用しない。
		DRIVERCRATE_EXPECT( context, row != result.infs.end()) ;
		// 同じrootを観測できた場合だけ全軸を比較する。
		if( row != result.infs.end()) {
			expectProjection( context, closure, *row) ;
			const bool legacyRoutePassed =
				// 未知宣言は従来静的routeの対象外。
				index == 2U || index == 8U ;
			DRIVERCRATE_EXPECT( context, row->installRoute.state ==
												(legacyRoutePassed
													 ? MaintenanceInspectionState::PASSED
													 : MaintenanceInspectionState::UNSUPPORTED) &&
											(legacyRoutePassed ? row->installRoute.error == 0
															   : row->installRoute.error != 0)) ;
		}

		DRIVERCRATE_EXPECT( context, fixture.nativeCalls == 1U &&
										fixture.signatureCalls.size() == expectedCalls) ;
	}
}

/** @brief 一つのnamed構造不足を実参照readerと専用架空署名へ結ぶ構成。 */
struct NamedServiceBoundaryCase {
	/// 架空Servicesの宣言本文。identityを外部へ出力しない。
	std::string_view		   declarations ;
	/// 参照先節の四項目または具体的欠落構造。
	std::string_view		   sections ;
	/// 宣言SYSだけを元ZIPから欠落させる場合true。
	bool					   missingSys{} ;
	/// 未知actionをDDInstallへ併記する場合true。
	bool					   unknownAction{} ;
	/// 非実行parserの独立期待。
	MaintenanceInspectionState parser{MaintenanceInspectionState::PASSED} ;
} ;

/**
 * @brief Namedの構造成功・不足とroot／全署名の独立を閉包と共通DTOで回帰する。
 * @param[in,out] context 有限assertion集計。
 * @note 実INF／source位置／byteを使用するが、署名・由来はこのtargetだけのfakeである。
 */
void testNamedServiceIntegrity( TestContext &context)
{
	constexpr std::string_view VALID_SERVICE =
		"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\sample.sys\r\n" ;	// 架空SYSを参照する必須四項目。
	constexpr std::array<NamedServiceBoundaryCase, 13U> CASES{{
		{"AddService=FictionalService,2,ServiceInstall\r\n", VALID_SERVICE},
		{"AddService=FictionalAuxiliary,0,ServiceInstall\r\n", VALID_SERVICE},
		{"AddService=FictionalAuxiliary,,ServiceInstall\r\n", VALID_SERVICE},
		{"AddService=FictionalService,8,ServiceInstall\r\n", VALID_SERVICE, false, false,
		 MaintenanceInspectionState::UNSUPPORTED},
		{"AddService=FictionalService,2,ServiceInstall\r\n",
		 "[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n", false, false,
		 MaintenanceInspectionState::FAILED},
		{"AddService=FictionalService,2,ServiceInstall\r\n", VALID_SERVICE, true},
		{"AddService=FictionalService,2,ServiceInstall\r\n", VALID_SERVICE, false, true,
		 MaintenanceInspectionState::UNSUPPORTED},
		{"AddService=FictionalService,2,MissingServiceInstall\r\n", VALID_SERVICE, false, false,
		 MaintenanceInspectionState::FAILED},
		{"AddService=FictionalService,2,ServiceInstall,MissingEvents\r\n", VALID_SERVICE, false,
		 false, MaintenanceInspectionState::FAILED},
		{"AddService=FictionalService,2,ServiceInstall\r\n",
		 "[ServiceInstall]\r\nServiceType=1\r\nStartType=broken\r\nErrorControl=1\r\nServiceBinary=%12%\\sample.sys\r\n",
		 false, false, MaintenanceInspectionState::FAILED},
		{"AddService=FictionalService,2,serviceinstall\r\nAddService=FictionalAuxiliary,,SERVICEINSTALL\r\n",
		 VALID_SERVICE},
		{"AddService=,2\r\nAddService=FictionalAuxiliary,0,ServiceInstall\r\n", VALID_SERVICE},
		{"AddService=FictionalService,2,ServiceInstall\r\nAddService=FictionalSecond,2,ServiceInstall\r\n",
		 VALID_SERVICE, false, false, MaintenanceInspectionState::UNSUPPORTED},
	}} ; // 構造認識と全file位置・全署名を独立に指定する閉じた分母。
	// 十三構成をroot架空成功／既知FAILEDの両条件へ結び、不足でFAILEDを消さない。
	for( std::size_t index = 0U; index < CASES.size(); ++index) {
		const auto &testCase = CASES[index] ;	// 静的な一つの原構成だけを借用する。
		// 元署名診断だけを切り替え、byteと構造の期待は維持する。
		for( const bool signatureFailed : {false, true}) {
			MatrixCase spec ;	// 従来source／CopyFilesと通常Portsを持つ基準。
			spec.rootFile  = !testCase.missingSys ;
			spec.rootError = signatureFailed ? SIGNATURE_FAILURE : 0 ;
			spec.install   = testCase.unknownAction ? "UnknownNamedAction=fixture.dll\r\n" : "" ;
			const std::string extra =
				"[DestinationDirs]\r\nDefaultDestDir=12\r\n[Install.NT.Services]\r\n" +
				std::string( testCase.declarations) +
				// 架空serviceだけ。
				std::string( testCase.sections) ;
			// 同じ原構成だけの実ZIPと架空応答を一runへ固定する。
			BoundaryFixture fixture( spec, 1050U + index * 2U + (signatureFailed ? 1U : 0U), "Ports",
									extra) ;
			BoundaryScope	scope( fixture) ;									// 同期fakeの借用を一回へ限定する。
			const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 原一root。
			OfficialDownloadWorkspace				workspace ;					// 破棄時に今回の閉包だけを解除する。
			MaintenanceDriverClosure				closure ;					// 導入型へ変換しない結果。
			const NativeError						error = extractMaintenanceDriverClosure(
				  {&fixture.input,
									   OfficialDriverArchiveFormat::ZIP,
									   {},
									   selected,
									   L"named-integrity-out"},
				  CONTENT_POLICY, workspace, closure) ;	// 製品と同じ読取・有限閉包本体。
			DRIVERCRATE_EXPECT( context, error == 0) ;
			// 全体失敗は不一致へ残し、空の構造を参照しない。
			if( error != 0) {
				continue ;
			}

			const MaintenanceInspectionState whole =
				signatureFailed
					? MaintenanceInspectionState::FAILED
					: MaintenanceInspectionState::
						  NOT_CHECKED ;	// 親default文脈がない合法展開形は未対応を維持する。
			DRIVERCRATE_EXPECT( context, closure.structure.parser.state == testCase.parser) ;
			DRIVERCRATE_EXPECT( context, closure.structure.referenceCoverage ==
											MaintenanceInfReferenceCoverage::INCOMPLETE) ;
			DRIVERCRATE_EXPECT( context, !closure.references.empty()) ;
			// 実在service節のbinary宣言は絶対pathへのWindows展開と元位置不足を区別する。
			if( index != 4U && index != 7U && !closure.references.empty()) {
				const auto &files =
					// 元rootの参照結果だけを借用する。
					closure.references.front().files ;
				DRIVERCRATE_EXPECT( context, std::ranges::any_of( files, []( const auto &file) {
									   return file.directive == L"ServiceBinary" ;
								   })) ; // 観測欠落を未対応の正常値として扱わない。
				// Shared節も含む全binary用途を検査し、basename fallbackの成功を認めない。
				for( const auto &file : files) {
					// 今回到達した具体的binary用途だけを原Windows展開形へ照合する。
					if( file.directive == L"ServiceBinary") {
						DRIVERCRATE_EXPECT( context,
										   file.target.size() >= 3U && file.target[1] == L':' &&
											   file.target[2] == L'\\' &&
											   file.target.find( L'%') == std::wstring::npos) ;
						DRIVERCRATE_EXPECT(
							context, file.location == MaintenanceInfFileLocation::UNSUPPORTED &&
										 file.error == HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
					}
				}
			}

			DRIVERCRATE_EXPECT( context, closure.structure.rootIntegrity.state ==
											(signatureFailed ? MaintenanceInspectionState::FAILED
															 : MaintenanceInspectionState::PASSED)) ;
			DRIVERCRATE_EXPECT( context, closure.structure.rootIntegrity.error == spec.rootError) ;
			DRIVERCRATE_EXPECT( context, closure.integrity.state == whole &&
											closure.integrity.error == spec.rootError) ;
			DRIVERCRATE_EXPECT( context,
							   closure.structure.contentKind ==
								   (index == 11U ? MaintenanceInfContentKind::MIXED
												 : MaintenanceInfContentKind::PACKAGE_FILES)) ;
			DRIVERCRATE_EXPECT( context,
							   closure.structure.dependency.state ==
									   MaintenanceInfDependencyState::NONE &&
								   closure.structure.dependency.observedReferenceCount == 0U) ;
			DRIVERCRATE_EXPECT( context,
							   !closure.dependency.dependency.plan.rootEvidenceVerified &&
								   closure.dependency.dependency.plan.deviceApplicability ==
									   InfDependencyEvidence::NOT_CHECKED &&
								   closure.dependency.dependency.plan.installRoute ==
									   InfDependencyEvidence::NOT_CHECKED) ;

			MaintenanceDriverPackageInspection result ;	// 同じ元ZIPの共通保守DTOへ独立射影する。
			DRIVERCRATE_EXPECT( context,
							   inspectMaintenanceDriverPackage(
								   fixture.input, OfficialDriverArchiveFormat::ZIP, result) == 0) ;
			DRIVERCRATE_EXPECT( context, result.infs.size() == 1U) ;
			// 原一INFを観測した場合だけ全軸を比較する。
			if( result.infs.size() == 1U) {
				expectProjection( context, closure, result.infs.front()) ;
				// 従来named正例の静的routeを内容のnull認定へ変更しない。
				if( index == 0U) {
					DRIVERCRATE_EXPECT( context, result.infs.front().installRoute.state ==
													MaintenanceInspectionState::PASSED) ;
				}
			}
		}
	}

	MatrixCase failedPeer ;	// 未評価namedと依存INFの既知FAILEDを同時に持つ構成。
	failedPeer.nativeMode = NativeMode::PACKAGE_FAILED ;
	// 原rootと依存INFのbyte・架空署名失敗を同じ閉じたZIPへ結ぶ。
	BoundaryFixture fixture(
		failedPeer, 1099U, "Ports",
		"[Install.NT.Services]\r\nAddService=FictionalService,8,ServiceInstall\r\n" +
			std::string( VALID_SERVICE)) ;
	BoundaryScope scope( fixture) ;										// 架空依存失敗は元署名HRESULTだけを供給する。
	const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 依存INFを第二rootへしない。
	OfficialDownloadWorkspace				workspace ;					// この一runだけの所有閉包。
	MaintenanceDriverClosure				closure ;					// 全payload未確認と既知失敗を同時に保持する。
	DRIVERCRATE_EXPECT(
		context,
		extractMaintenanceDriverClosure(
			{&fixture.input, OfficialDriverArchiveFormat::ZIP, {}, selected, L"named-peer-out"},
			CONTENT_POLICY, workspace, closure) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   closure.structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT( context, closure.structure.referenceCoverage ==
									MaintenanceInfReferenceCoverage::INCOMPLETE) ;
	DRIVERCRATE_EXPECT( context,
					   closure.structure.rootIntegrity.state == MaintenanceInspectionState::PASSED) ;
	DRIVERCRATE_EXPECT( context, closure.integrity.state == MaintenanceInspectionState::FAILED &&
									closure.integrity.error == SIGNATURE_FAILURE &&
									closure.structure.dependency.error == SIGNATURE_FAILURE) ;
}

/**
 * @brief 一つのeventlog親markerと独立子Uの閉じた回帰構成を保持します。
 * @note 本文は架空INFだけで、registry作用や未知値を解釈するvalidatorではありません。
 */
struct EventLogBoundaryCase {
	/// 同行AddServiceの元本文。
	std::string_view declarations ;
	/// 第4fieldのDIRECTIVESとその子registryの元本文。
	std::string_view events ;
	/// 通常source節の有無。子Uの代用根拠にはしない。
	bool			 source{true} ;
	/// 分離後に残す親AddService marker数。
	std::size_t		 markers{} ;
	/// 元eventlog gap数。親分離後も全件保持する。
	std::size_t		 gaps{1U} ;
	/// 元readerの全体拒否を要求する場合true。
	bool			 rejected{} ;
	/// 第3fieldの必須構造不足を作る場合true。
	bool			 brokenService{} ;
	/// 同期署名fakeの既知FAILEDを維持する場合true。
	bool			 rootFailed{} ;
	/// 同じreference以外のSYSTEM不足を併記する場合true。
	NativeMode		 nativeMode{NativeMode::NONE} ;
} ;

/**
 * @brief 同行第4fieldの子Uだけで親一件を分離し、元構造・gap・全軸を保持します。
 * @param[in,out] context 元assertion集計。九つの有限条件群を追加します。
 * @note 実byte、元reader、CAT呼出集合を使い、署名結果だけを隔離targetのfakeで供給します。
 */
void testEventLogMarkerSeparation( TestContext &context)
{
	constexpr std::string_view SERVICE =
		"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\sample.sys\r\n" ;	// 第3fieldだけの必須構造。
	constexpr std::string_view GOOD =
		"[Events]\r\nAddReg=EventRegistry\r\n[EventRegistry]\r\n"
		"HKR,,EventMessageFile,0x00020000,.\\messages.dll\r\n" ;	// 元readerが保持する具体的子U。
	constexpr std::string_view DECL =
		"AddService=FictionalEventService,2,ServiceInstall,Events\r\n" ;	// 厳密四field。
	constexpr std::array<EventLogBoundaryCase, 36U> CASES{{
		{DECL, GOOD},
		{DECL, GOOD, false},
		{"AddService=FictionalEventService,0,ServiceInstall,Events\r\n", GOOD},
		{"AddService=FictionalEventService,,ServiceInstall,Events\r\n", GOOD},
		{DECL,
		 "[Events]\r\nDelReg=EventRegistry\r\n[EventRegistry]\r\nHKR,,UnknownValue,0,opaque\r\n",
		 false},
		{DECL,
		 "[Events]\r\nAddReg=EventRegistry\r\n[EventRegistry]\r\nHKR,,UnknownValue,0,opaque\r\n",
		 true, 1U},
		{"AddService=FictionalEventService,2,ServiceInstall\r\n", GOOD, true, 0U, 0U},
		{"AddService=FictionalEventService,2,ServiceInstall,\r\n", GOOD, true, 0U, 0U},
		{DECL, "[Events]\r\n", false, 1U},
		{DECL, "[Events]\r\nAddReg=EventRegistry\r\n[EventRegistry]\r\n", false, 1U},
		{DECL, "", true, 2U},
		{DECL, "[Events]\r\nAddReg=MissingRegistry\r\n", true, 1U},
		{DECL, "[Events]\r\nAddReg=EventRegistry\r\n[EventRegistry]\r\nHKR\r\n", true, 1U, 1U,
		 true},
		{DECL, "[Events]\r\nAddReg=\r\n", true, 1U, 1U, true},
		{DECL,
		 "[Events]\r\nBitReg=EventRegistry\r\n[EventRegistry]\r\nHKR,,EventMessageFile,0,.\\messages.dll\r\n",
		 false, 1U},
		{DECL,
		 "[Events]\r\nUnknownEvent=EventRegistry\r\n[EventRegistry]\r\nHKR,,EventMessageFile,0,.\\messages.dll\r\n",
		 false, 1U},
		{DECL, "[Events]\r\nEventMessageFile=%SystemRoot%\\one.dll;two.dll\r\n", false, 1U},
		{"AddService=FictionalEventService,2,Events,ServiceInstall\r\n", GOOD, true, 1U},
		{"AddService=FictionalEventService,2,ServiceInstall,Events,System,FictionalName\r\n", GOOD,
		 true, 1U},
		{"AddService=FictionalEventService,2,serviceinstall,eVeNtS\r\n", GOOD},
		{"AddService=FictionalEventService,0,ServiceInstall,Events\r\nAddService=FictionalOther,0,ServiceInstall,Events\r\n",
		 GOOD, true, 2U, 2U},
		{DECL,
		 "[Events]\r\nAddReg=EventRegistry\r\nNeeds=Events\r\n[EventRegistry]\r\nHKR,,EventMessageFile,0,.\\messages.dll\r\n",
		 true, 1U},
		{DECL, "[Events]\r\nAddReg=Events\r\n", true, 1U, 1U, true},
		{"AddService=FictionalEventService,8,ServiceInstall,Events\r\n", GOOD, true, 1U},
		{DECL, GOOD, true, 1U, 1U, false, true},
		{DECL, GOOD, true, 0U, 1U, false, false, true},
		{DECL, GOOD, true, 0U, 1U, false, false, false, NativeMode::PACKAGE_FAILED},
		{DECL,
		 "[Events]\r\n[Other]\r\nAddReg=OtherRegistry\r\n[OtherRegistry]\r\nHKR,,EventMessageFile,0,.\\other.dll\r\n",
		 false, 1U, 1U, false, false, false, NativeMode::SYSTEM},
		{"AddService=FictionalSame,0,ServiceInstall,Events\r\nAddService=FictionalSame,0,ServiceInstall,EmptyEvents\r\n",
		 "[Events]\r\nAddReg=EventRegistry\r\n[EventRegistry]\r\nHKR,,EventMessageFile,0,.\\messages.dll\r\n[EmptyEvents]\r\n",
		 true, 1U, 2U},
		{DECL,
		 "[Events]\r\nAddReg=EventRegistry\r\nDelReg=SecondRegistry\r\n[EventRegistry]\r\nHKR,,UnknownValue,0,opaque\r\n[SecondRegistry]\r\nHKR,,EventMessageFile,0,.\\messages.dll\r\n"},
		{"AddService=,2,ServiceInstall,Events\r\n", GOOD, true, 1U},
		{"AddService=%UnresolvedService%,2,ServiceInstall,Events\r\n", GOOD, true, 1U},
		{"AddService=FictionalEventService,2,Events,Events\r\n", GOOD, true, 1U},
		{DECL, GOOD, true, 1U},
		{DECL,
		 "[Events]\r\nAddReg=EventRegistry,EVENTREGISTRY\r\n[EventRegistry]\r\nHKR,,EventMessageFile,0,.\\messages.dll\r\n",
		 true, 1U},
		{DECL,
		 "[Events]\r\nAddReg=EventRegistry,MissingRegistry\r\n[EventRegistry]\r\nHKR,,EventMessageFile,0,.\\messages.dll\r\n",
		 true, 1U},
	}} ; // 九群の正負条件を有限三十六構成へ固定する。
	// 各閉じた構成を一度ずつ実readerと同closureへ結び、追加native再試行をしない。
	for( std::size_t index = 0U; index < CASES.size(); ++index) {
		const auto &testCase = CASES[index] ;	// 架空の一構成だけを同期借用する。
		MatrixCase	spec ;						// 従来のbyte/CAT境界と独立署名応答。
		spec.rootSource = testCase.source ;
		spec.rootError	= testCase.rootFailed ? SIGNATURE_FAILURE : 0 ;
		spec.nativeMode = testCase.nativeMode ;
		// 別節のUしかない形では元eventlogの不足を補完しない。
		if( index == 27U) {
			spec.install = "Needs=Other\r\n" ;
		}

		// DDInstallとeventlogが共有する子registryは混在callerとして親を保留する。
		if( index == 33U) {
			spec.install = "AddReg=EventRegistry\r\n" ;
		}

		const std::string extra =
			"[Install.NT.Services]\r\n" + std::string( testCase.declarations) +
			(testCase.brokenService
				 ? "[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nServiceBinary=%12%\\sample.sys\r\n"
				 : std::string( SERVICE)) +
			// 同行第三・第四fieldを別節へ固定。
			std::string( testCase.events) ;
		BoundaryFixture				  fixture( spec, 5700U + index, "Ports",
											  extra) ;	// 原INFとCATの実byteを所有する。
		BoundaryScope				  scope( fixture) ;	// この一runだけの架空署名応答。
		std::vector<OfficialZipEntry> entries ;			// 元memberのsize/hashだけを実readerへ渡す。
		// 全原memberを有限に列挙し、本文改変と位置の別入力を混在させない。
		for( const auto &member : fixture.files) {
			entries.push_back( {wideName( member.name), member.bytes.size(), member.hash}) ;
		}

		MaintenanceInfReferences references ;	// 最終用途だけを分離する対象。
		const NativeError		 error = inspectMaintenanceInfReferences(
			   fixture.source, entries, L"sample.inf", fixture.rootSeeds, CONTENT_POLICY.infPolicy,
			   references) ;	// 元APIは変更しない。
		DRIVERCRATE_EXPECT( context, (error != 0) == testCase.rejected) ;
		// 架空case番号と診断値だけを失敗時に通知し、本文やpathを出力しない。
		if( (error != 0) != testCase.rejected) {
			std::cerr << "Eventlog fixture case " << index << ", reader error " << error << '\n' ;
		}

		// 元全体失敗の部分結果を成功用途として扱わない。
		if( error != 0) {
			DRIVERCRATE_EXPECT( context, references.files.empty() &&
											references.inventory.visitedSections.empty()) ;
			continue ;
		}

		const auto markerCount = std::ranges::count_if( references.files, []( const auto &file) {
			return file.directive == L"AddService" ;
		}) ; // 同名二行も一件ずつ照合する元用途数。
		DRIVERCRATE_EXPECT( context, markerCount == static_cast<std::ptrdiff_t>( testCase.markers)) ;
		// 不一致時はcase番号だけを通知し、用途本文を外へ出さない。
		if( markerCount != static_cast<std::ptrdiff_t>( testCase.markers)) {
			std::cerr << "Eventlog marker fixture mismatch, case " << index << '\n' ;
		}

		DRIVERCRATE_EXPECT(
			context, std::ranges::count_if( references.inventory.coverageGaps, []( const auto &gap) {
						 return gap.kind ==
								OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG ;
					 }) == static_cast<std::ptrdiff_t>( testCase.gaps)) ; // 親分離でgapを除去しない。
		DRIVERCRATE_EXPECT( context, references.referenceCoverage ==
										MaintenanceInfReferenceCoverage::INCOMPLETE) ;
		// 分離正例の同referenceには必ず元HRESULTの独立registry子Uが残る。
		if( testCase.markers < testCase.gaps) {
			DRIVERCRATE_EXPECT( context, std::ranges::any_of( references.files, []( const auto &file) {
								   return (file.directive == L"RegistryFileUseNotAssessed" ||
										   file.directive == L"RegistryFileUsesNotAssessed") &&
										  file.location ==
											  MaintenanceInfFileLocation::UNSUPPORTED &&
										  file.error == UNSUPPORTED_ERROR ;
							   })) ;
		}

		const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 同じ閉じたrootだけ。
		OfficialDownloadWorkspace				workspace ;					// 同scopeで今回の抽出だけを所有する。
		MaintenanceDriverClosure				closure ;					// parser/content/署名/依存の元独立軸。
		DRIVERCRATE_EXPECT(
			context, extractMaintenanceDriverClosure( {&fixture.input,
													  OfficialDriverArchiveFormat::ZIP,
													  {},
													  selected,
													  L"eventlog-boundary-out"},
													 CONTENT_POLICY, workspace, closure) == 0) ;
		DRIVERCRATE_EXPECT( context, closure.structure.referenceCoverage ==
										MaintenanceInfReferenceCoverage::INCOMPLETE) ;
		DRIVERCRATE_EXPECT( context,
						   closure.structure.rootIntegrity.state ==
								   (testCase.rootFailed ? MaintenanceInspectionState::FAILED
														: MaintenanceInspectionState::PASSED) &&
							   closure.structure.rootIntegrity.error == spec.rootError) ;
		const bool failed = testCase.rootFailed ||
							// 既知FAILEDを優先する。
							testCase.nativeMode == NativeMode::PACKAGE_FAILED ;
		DRIVERCRATE_EXPECT( context,
						   closure.integrity.state ==
								   (failed ? MaintenanceInspectionState::FAILED
										   : MaintenanceInspectionState::NOT_CHECKED) &&
							   closure.integrity.error == (failed ? SIGNATURE_FAILURE : 0)) ;
		DRIVERCRATE_EXPECT( context, closure.structure.contentKind ==
										(index == 30U ? MaintenanceInfContentKind::MIXED
													  : MaintenanceInfContentKind::PACKAGE_FILES)) ;
		DRIVERCRATE_EXPECT(
			context,
			std::ranges::count_if( closure.structure.installs.front().fileUses, []( const auto &use) {
				return use.directive == L"AddService" ;
			}) == static_cast<std::ptrdiff_t>( testCase.gaps)) ; // 元install.fileUsesは削除しない。
		DRIVERCRATE_EXPECT( context, fixture.nativeCalls == 1U && !fixture.signatureCalls.empty()) ;
	}

	// 私有保持量超過はreader全体を拒否せず、同じ元markerを保持して閉じる。
	MatrixCase capacity ;	// 行・項目の元上限内で私有proofだけを保留する架空構成。
	// 三千五百の未知行は元作用・用途として残し、予算を親ごとにresetしない。
	for( std::size_t row = 0U; row < 3500U; ++row) {
		capacity.install += "UnknownFixture=opaque\r\n" ;
	}

	BoundaryFixture				  fixture( capacity, 5799U, "Ports",
										  "[Install.NT.Services]\r\n" + std::string( DECL) + std::string( SERVICE) +
											  // 既存readerの共同4096行内。
											  std::string( GOOD)) ;
	std::vector<OfficialZipEntry> entries ;	// 実固定memberだけ。
	// 元byte拘束のまま全memberを実readerへ渡す。
	for( const auto &member : fixture.files) {
		entries.push_back( {wideName( member.name), member.bytes.size(), member.hash}) ;
	}

	MaintenanceInfReferences references ;	// 私有限界でも元用途を保持する。
	DRIVERCRATE_EXPECT( context, inspectMaintenanceInfReferences(
									fixture.source, entries, L"sample.inf", fixture.rootSeeds,
									CONTENT_POLICY.infPolicy, references) == 0) ;

	DRIVERCRATE_EXPECT( context, std::ranges::count_if( references.files, []( const auto &file) {
									return file.directive == L"AddService" ;
								}) == 1) ;
	DRIVERCRATE_EXPECT( context, std::ranges::count_if( references.files, []( const auto &file) {
									return file.directive == L"UnknownFixture" ;
								}) == 3500) ;

	// 元field上限と必要長失敗は私有proof保留ではなく元全体拒否へ残す。
	for( const bool excessiveFields : {false, true}) {
		std::string event = "[Events]\r\nAddReg=" ;	// 同じ第4fieldの元本文だけ。
		// 六十五fieldは先頭の合法節名だけで部分followしない。
		if( excessiveFields) {
			// 原一行の全fieldを既存64上限へ拘束する。
			for( std::size_t field = 0U; field < 65U; ++field) {
				event += (field == 0U ? "EventRegistry" : ",EventRegistry") ;
			}
		} else {
			event += std::string( 4096U, 'x') ;
		}

		event += "\r\n[EventRegistry]\r\nHKR,,EventMessageFile,0,.\\messages.dll\r\n" ;
		BoundaryFixture invalid( MatrixCase{}, excessiveFields ? 5801U : 5800U, "Ports",
								"[Install.NT.Services]\r\n" + std::string( DECL) +
									// 元byte固定。
									std::string( SERVICE) + event) ;
		std::vector<OfficialZipEntry> members ;	// 原hashを含む一意memberだけ。
		// 拒否前後の部分観測を別のmember集合へ補完しない。
		for( const auto &member : invalid.files) {
			members.push_back( {wideName( member.name), member.bytes.size(), member.hash}) ;
		}

		MaintenanceInfReferences result ;	// 読取不能では公開参照を空に保つ。
		DRIVERCRATE_EXPECT( context, inspectMaintenanceInfReferences(
										invalid.source, members, L"sample.inf", invalid.rootSeeds,
										CONTENT_POLICY.infPolicy,
										result) == HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
		DRIVERCRATE_EXPECT( context,
						   result.files.empty() && result.inventory.visitedSections.empty()) ;
	}

	// 元readerの共同行上限は私有proof保留と区別し、正確な上限と＋1を確認する。
	for( const std::size_t rows : {4081U, 4082U}) {
		MatrixCase limit ;	// Version六行・source一行と全到達行を共同で消費する。
		// 上限内の未知行を全件保持し、＋1を切り捨てない。
		for( std::size_t row = 0U; row < rows; ++row) {
			limit.install += "UnknownFixture=opaque\r\n" ;
		}

		BoundaryFixture				  bounded( limit, 5800U + rows, "Ports",
											  "[Install.NT.Services]\r\n" + std::string( DECL) +
												  // 同じ全read経路。
												  std::string( SERVICE) + std::string( GOOD)) ;
		std::vector<OfficialZipEntry> members ;	// 元memberのhashだけを同期借用する。
		// 元INF・CAT・SYSを同じ閉じた位置へ結ぶ。
		for( const auto &member : bounded.files) {
			members.push_back( {wideName( member.name), member.bytes.size(), member.hash}) ;
		}

		MaintenanceInfReferences result ;	// 失敗時は空のまま。
		const NativeError		 error = inspectMaintenanceInfReferences(
			   bounded.source, members, L"sample.inf", bounded.rootSeeds, CONTENT_POLICY.infPolicy,
			   result) ;	// 元全体境界。
		DRIVERCRATE_EXPECT( context, (error == 0) == (rows == 4081U)) ;
		// 上限内は全行と元markerを保持し、全file充足にはしない。
		if( error == 0) {
			DRIVERCRATE_EXPECT( context, result.inventory.scannedLines == 4096U &&
											result.referenceCoverage ==
												MaintenanceInfReferenceCoverage::INCOMPLETE) ;
		} else {
			DRIVERCRATE_EXPECT( context, error == HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) &&
											result.files.empty() &&
											result.inventory.visitedSections.empty()) ;
		}
	}
}

/** @brief 明示named位置の一条件と元byte／全署名の独立期待。 */
struct ExpandedBinaryBoundaryCase {
	/// 到達list固有の導入先。defaultや未到達keyは成功根拠にしない。
	std::string_view		   destinations{"FixtureCopy=12\r\n"} ;
	/// 到達named copy行のdestinationと元source。
	std::string_view		   copyRows{"sample.sys\r\n"} ;
	/// 元service binary。Windows展開後も元参照へ保持する。
	std::string_view		   binary{"%12%\\sample.sys"} ;
	/// 追加の到達copy宣言。別listの重複・未知衝突を観測する。
	std::string_view		   extraCopy ;
	/// 追加のcopy list定義。未到達listの存在だけで照合しない。
	std::string_view		   extraLists ;
	/// named基準を@直接copyへ戻す場合だけfalse。
	bool					   namedCopy{true} ;
	/// 実元SYSを保護packageから欠落させる場合だけtrue。
	bool					   missingSys{} ;
	/// 元ServiceBinary用途の位置期待。
	MaintenanceInfFileLocation location{MaintenanceInfFileLocation::LOCATED} ;
	/// 元ServiceBinary用途の診断期待。
	NativeError				   locationError{} ;
} ;

/**
 * @brief 明示named導入先を元sourceへ戻し、coverageと架空署名を独立に回帰する。
 * @param[in,out] context 有限assertion集計。
 * @note 製品の実byte・INF本体と専用fake署名を使い、system導入先を開かない。
 */
void testExpandedBinaryIntegrity( TestContext &context)
{
	constexpr NativeError UNSUPPORTED = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;	// 合法未対応。
	constexpr NativeError DUPLICATE =
		// 一宣言へ絞れない元状態。
		HRESULT_FROM_WIN32( ERROR_DUP_NAME) ;
	constexpr std::array CASES{
		ExpandedBinaryBoundaryCase{},
		ExpandedBinaryBoundaryCase{.destinations = "FixtureCopy=11\r\n",
								   .binary		 = "%11%\\sample.sys"},
		ExpandedBinaryBoundaryCase{.destinations = "FixtureCopy=12,payload\r\n",
								   .copyRows	 = "renamed.sys,sample.sys\r\n",
								   .binary		 = "%12%\\payload\\renamed.sys"},
		ExpandedBinaryBoundaryCase{.destinations = "fixturecopy=12\r\n",
								   .copyRows	 = "renamed.sys,sample.sys\r\n",
								   .binary		 = "%12%\\renamed.sys"},
		// 同HINF全target・同名・source一行・空subdir一致だけを元source成功へ変更する。
		ExpandedBinaryBoundaryCase{.destinations = "FixtureCopy=13\r\n",
								   .binary		 = "%13%\\sample.sys"},
		ExpandedBinaryBoundaryCase{.destinations  = "DefaultDestDir=12\r\n",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = UNSUPPORTED},
		ExpandedBinaryBoundaryCase{.destinations  = "DefaultDestDir=12\r\n",
								   .namedCopy	  = false,
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = UNSUPPORTED},
		ExpandedBinaryBoundaryCase{.destinations  = "OtherCopy=12\r\n",
								   .extraLists	  = "[OtherCopy]\r\nsample.sys\r\n",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = UNSUPPORTED},
		ExpandedBinaryBoundaryCase{.destinations  = "FixtureCopy=10\r\n",
								   .binary		  = "%10%\\sample.sys",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = UNSUPPORTED},
		ExpandedBinaryBoundaryCase{.destinations  = "FixtureCopy=12\r\nFixtureCopy=12\r\n",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = DUPLICATE},
		ExpandedBinaryBoundaryCase{.destinations  = "FixtureCopy=12\r\nSecondCopy=12\r\n",
								   .extraCopy	  = "CopyFiles=SecondCopy\r\n",
								   .extraLists	  = "[SecondCopy]\r\nsample.sys\r\n",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = DUPLICATE},
		ExpandedBinaryBoundaryCase{.missingSys	  = true,
								   .location	  = MaintenanceInfFileLocation::MISSING,
								   .locationError = HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)},
		ExpandedBinaryBoundaryCase{.destinations  = "FixtureCopy=13,payload\r\n",
								   .binary		  = "%13%\\payload\\sample.sys",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = UNSUPPORTED},
		ExpandedBinaryBoundaryCase{.binary		  = "%12%\\different\\sample.sys",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = UNSUPPORTED},
		ExpandedBinaryBoundaryCase{.destinations  = "FixtureCopy=12\r\nSecondCopy=10\r\n",
								   .extraCopy	  = "CopyFiles=SecondCopy\r\n",
								   .extraLists	  = "[SecondCopy]\r\nsample.sys\r\n",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = UNSUPPORTED},
		ExpandedBinaryBoundaryCase{.destinations  = "FixtureCopy=12\r\nSecondCopy=12\r\n",
								   .extraCopy	  = "CopyFiles=SecondCopy\r\n",
								   .extraLists	  = "[SecondCopy]\r\nsample.sys,other.sys\r\n",
								   .location	  = MaintenanceInfFileLocation::UNSUPPORTED,
								   .locationError = DUPLICATE},
	} ; // 正例・合法未対応・missingの十六構成を同じ元署名二条件へ固定する。
	// 元位置と架空root署名を別条件で比較し、未知が既知FAILEDを消さないことを確認する。
	for( std::size_t index = 0U; index < CASES.size(); ++index) {
		const auto &testCase = CASES[index] ;	// 閉じた一構成を同期呼出しだけが借用する。
		// 署名だけを切り替え、元source・導入先・不足の条件を同一に保つ。
		for( const bool signatureFailed : {false, true}) {
			MatrixCase spec ;	// 元sourceは常にsample.sysであり、導入先別名をmemberにしない。
			spec.rootCopyList = testCase.namedCopy ;
			spec.rootFile	  = !testCase.missingSys ;
			spec.rootError	  = signatureFailed ? SIGNATURE_FAILURE : 0 ;
			spec.install	  = testCase.extraCopy ;
			const std::string extra =
				"[DestinationDirs]\r\n" + std::string( testCase.destinations) + "[FixtureCopy]\r\n" +
				std::string( testCase.copyRows) + std::string( testCase.extraLists) +
				"[Install.NT.Services]\r\nAddService=FictionalService,2,ServiceInstall\r\n"
				"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=" +
				// 具体的参照を必ず持つ架空INF。
				std::string( testCase.binary) + "\r\n" ;
			BoundaryFixture fixture( spec, 1500U + index * 2U + (signatureFailed ? 1U : 0U), "Ports",
									extra) ;									// 同じ元ZIPと保護memberを所有する。
			BoundaryScope	scope( fixture) ;									// 専用fakeはこの同期scopeだけで借用する。
			const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 元一root。
			OfficialDownloadWorkspace workspace ;								// 今回の有限workspaceだけを所有する。
			MaintenanceDriverClosure  closure ;									// 未導入の独立内容結果。
			const NativeError		  error = extractMaintenanceDriverClosure(
				{&fixture.input,
						 OfficialDriverArchiveFormat::ZIP,
						 {},
						 selected,
						 L"binary-integrity-out"},
				CONTENT_POLICY, workspace, closure) ;	// 製品と同じ閉包本体。
			DRIVERCRATE_EXPECT( context, error == 0) ;
			// fixtureの全体失敗を不一致に残し、空結果を参照しない。
			if( error != 0) {
				continue ;
			}

			const bool complete =
				// 全file位置の期待。
				testCase.location == MaintenanceInfFileLocation::LOCATED ;
			const MaintenanceInspectionState whole =
				signatureFailed
					? MaintenanceInspectionState::FAILED
					: (complete
						   ? MaintenanceInspectionState::PASSED
						   : MaintenanceInspectionState::NOT_CHECKED) ;	// 既知FAILEDを優先する。
			DRIVERCRATE_EXPECT( context, closure.structure.parser.state ==
											MaintenanceInspectionState::PASSED) ;
			DRIVERCRATE_EXPECT( context,
							   closure.structure.referenceCoverage ==
								   (complete ? MaintenanceInfReferenceCoverage::COMPLETE
											 : MaintenanceInfReferenceCoverage::INCOMPLETE)) ;
			DRIVERCRATE_EXPECT( context, closure.structure.rootIntegrity.state ==
											(signatureFailed ? MaintenanceInspectionState::FAILED
															 : MaintenanceInspectionState::PASSED)) ;
			DRIVERCRATE_EXPECT( context, closure.structure.rootIntegrity.error == spec.rootError) ;
			DRIVERCRATE_EXPECT( context, closure.integrity.state == whole &&
											closure.integrity.error == spec.rootError) ;
			DRIVERCRATE_EXPECT( context, closure.structure.dependency.state ==
											MaintenanceInfDependencyState::NONE) ;
			DRIVERCRATE_EXPECT( context, closure.structure.contentKind ==
											MaintenanceInfContentKind::PACKAGE_FILES) ;
			DRIVERCRATE_EXPECT( context, !closure.references.empty()) ;
			// 原rootの具体的binary参照が観測された場合だけその位置と元sourceを比較する。
			if( !closure.references.empty()) {
				const auto &files =
					// この閉包の元参照を借用する。
					closure.references.front().files ;
				const auto binary = std::ranges::find_if( files, []( const auto &file) {
					return file.directive == L"ServiceBinary" ;
				}) ; // 同名のcopy用途でbinaryの欠落を補完しない。
				DRIVERCRATE_EXPECT( context, binary != files.end()) ;
				// 観測欠落は既に不一致へ残し、存在する元binaryだけを参照する。
				if( binary != files.end()) {
					DRIVERCRATE_EXPECT( context, !binary->target.empty() &&
													binary->location == testCase.location &&
													binary->error == testCase.locationError) ;
					// 成功したsourceだけを自身の保護memberへ結び、destination別名を署名へ渡さない。
					if( complete) {
						DRIVERCRATE_EXPECT( context, binary->relativePath == L"sample.sys") ;
					}

					// 新named13も元全targetを保持し、元source成功を実Store位置へ読み替えない。
					if( index == 4U) {
						DRIVERCRATE_EXPECT( context, binary->target == L".\\sample.sys" &&
														binary->section == L"ServiceInstall" &&
														binary->directive == L"ServiceBinary") ;
					}
				}
			}

			DRIVERCRATE_EXPECT( context,
							   fixture.signatureCalls.size() == 1U && fixture.nativeCalls == 1U) ;
			// root署名は既存元source集合を保持し、新system位置の存在を証拠にしない。
			if( !fixture.signatureCalls.empty()) {
				DRIVERCRATE_EXPECT( context, fixture.signatureCalls.front().inf == L"sample.inf" &&
												fixture.signatureCalls.front().sources ==
													fixture.rootSources) ;
			}

			MaintenanceDriverPackageInspection result ;	// 同じ元ZIPを共通保守DTOへ独立射影する。
			DRIVERCRATE_EXPECT( context,
							   inspectMaintenanceDriverPackage(
								   fixture.input, OfficialDriverArchiveFormat::ZIP, result) == 0) ;
			DRIVERCRATE_EXPECT( context, result.infs.size() == 1U) ;
			// 元一INFが観測された場合だけ元閉包と全独立軸を比較する。
			if( result.infs.size() == 1U) {
				expectProjection( context, closure, result.infs.front()) ;
			}
		}
	}

	// 位置成功／不足の両方で依存INFの既知FAILEDと原HRESULTを維持する。
	for( const bool unresolvedPosition : {false, true}) {
		MatrixCase spec ;	// root sourceとpeer署名失敗は二条件で同一にする。
		spec.rootCopyList = true ;
		spec.nativeMode	  = NativeMode::PACKAGE_FAILED ;
		const std::string extra =
			"[DestinationDirs]\r\n" +
			std::string( unresolvedPosition ? "DefaultDestDir=12\r\n" : "FixtureCopy=13\r\n") +
			"[FixtureCopy]\r\nsample.sys\r\n[Install.NT.Services]\r\n"
			"AddService=FictionalService,2,ServiceInstall\r\n[ServiceInstall]\r\nServiceType=1\r\n"
			"StartType=3\r\nErrorControl=1\r\nServiceBinary=" +
			std::string( unresolvedPosition
							? "%12%\\sample.sys\r\n"
							: "%13%\\sample.sys\r\n") ;	// 元位置成功だけを相対13へ結ぶ。
		BoundaryFixture fixture( spec, unresolvedPosition ? 1599U : 1598U, "Ports",
								extra) ;									// 同じ架空署名条件。
		BoundaryScope	scope( fixture) ;									// 元peer HRESULTを返す同期借用。
		const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 元rootは一件。
		OfficialDownloadWorkspace				workspace ;					// このrunの所有境界。
		MaintenanceDriverClosure				closure ;					// 位置と既知署名失敗を別に保持する。
		DRIVERCRATE_EXPECT(
			context, extractMaintenanceDriverClosure( {&fixture.input,
													  OfficialDriverArchiveFormat::ZIP,
													  {},
													  selected,
													  L"binary-peer-out"},
													 CONTENT_POLICY, workspace, closure) == 0) ;
		DRIVERCRATE_EXPECT( context,
						   closure.structure.parser.state == MaintenanceInspectionState::PASSED) ;
		DRIVERCRATE_EXPECT( context,
						   closure.structure.referenceCoverage ==
							   (unresolvedPosition ? MaintenanceInfReferenceCoverage::INCOMPLETE
												   : MaintenanceInfReferenceCoverage::COMPLETE)) ;
		DRIVERCRATE_EXPECT( context, closure.structure.rootIntegrity.state ==
										MaintenanceInspectionState::PASSED) ;
		DRIVERCRATE_EXPECT( context, closure.integrity.state == MaintenanceInspectionState::FAILED &&
										closure.integrity.error == SIGNATURE_FAILURE &&
										closure.structure.dependency.error == SIGNATURE_FAILURE) ;
	}
}

/** @brief 作用・未解釈宣言の内容と従来routeの検出限界を独立に確認する。
 * @param[in,out] context 有限assertion集計。
 * @note keyなしRun登録と明示AddSoftwareも静的拒否する。不完全softwareと架空未知宣言を実作用再現にしない。
 */
void testDangerousActions( TestContext &context)
{
	const std::array<std::pair<std::string_view, std::string_view>, 7U> cases{
		{{"RunPreSetupCommands=Commands\r\n", "[Commands]\r\n\"fixture.exe\"\r\n"},
		 {"RegisterDlls=Registration\r\n", "[Registration]\r\n11,,fixture.dll,1\r\n"},
		 {"",
		  "[Install.NT.CoInstallers]\r\nAddReg=CoReg\r\n[CoReg]\r\nHKR,,CoInstallers32,0x10000,\"fixture.dll\"\r\n"},
		 {"AddReg=Autorun\r\n",
		  "[Autorun]\r\nHKLM,\"Software\\Microsoft\\Windows\\CurrentVersion\\Run\",Fixture,0,\"fixture.exe\"\r\n"},
		 {"AddSoftware=Fixture,0,SoftwareSection\r\n", "[SoftwareSection]\r\nSoftwareType=1\r\n"},
		 {"FirmwareFile=fixture.bin\r\n", ""},
		 {"UnknownFileUse=mystery.dll\r\n", ""}}} ;	// 全本文は架空で実行しない。
	// 七構成の原挙動を一つずつ比較し、静的routeの到達を導入安全性へ変換しない。
	for( std::size_t index = 0U; index < cases.size(); ++index) {
		MatrixCase spec ;	// 通常sourceは各caseで保持する。
		spec.install = cases[index].first ;
		BoundaryFixture fixture( spec, 930U + index, "Ports", cases[index].second) ;	// 一作用だけ。
		BoundaryScope	scope( fixture) ;												// 同期検査中だけの架空署名。
		MaintenanceDriverPackageInspection result ;										// 内容とrouteを分けた出力。
		DRIVERCRATE_EXPECT( context,
						   inspectMaintenanceDriverPackage(
							   fixture.input, OfficialDriverArchiveFormat::ZIP, result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.infs.size() == 1U) ;
		// 不完全出力を先頭成功の証拠にしない。
		if( result.infs.size() != 1U) {
			continue ;
		}

		const auto		 &row = result.infs.front() ;	// 同じ一INFの全独立軸。
		const std::string diagnostic =
			"Action " + std::to_string( index) + " parser " +
			std::to_string( static_cast<int>( row.parser.state)) + " root " +
			std::to_string( static_cast<int>( row.rootIntegrity.state)) + " coverage " +
			std::to_string( static_cast<int>( row.referenceCoverage)) + " whole " +
			std::to_string( static_cast<int>( row.integrity.state)) + " route " +
			// 固定enumだけの失敗説明。
			std::to_string( static_cast<int>( row.installRoute.state)) ;
		DRIVERCRATE_EXPECT( context, row.rootIntegrity.state == MaintenanceInspectionState::PASSED) ;
		const bool legacyRejected =
			index < 5U ;	// 既知実行・Run登録と明示software予約は静的に拒否する。
		context.expect(
			row.installRoute.state == (legacyRejected ? MaintenanceInspectionState::UNSUPPORTED
													  : MaintenanceInspectionState::PASSED) &&
				(legacyRejected ? row.installRoute.error != 0 : row.installRoute.error == 0),
			diagnostic + " expected legacy route", __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context,
						   row.applicability.state == MaintenanceInspectionState::NOT_CHECKED) ;
		const bool fileCoverageComplete =
			index < 2U ;	// command／DLLの作用完全性とは別の全local位置。
		context.expect( row.referenceCoverage ==
							   (fileCoverageComplete
									? MaintenanceInfReferenceCoverage::COMPLETE
									: MaintenanceInfReferenceCoverage::INCOMPLETE) &&
						   row.integrity.state == (fileCoverageComplete
													   ? MaintenanceInspectionState::PASSED
													   : MaintenanceInspectionState::NOT_CHECKED),
					   diagnostic + " expected independent file coverage", __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context,
						   fixture.signatureCalls.size() == 1U && fixture.nativeCalls == 1U) ;
		CommonDriverPackageInspection normal ;	// 静的policyの拒否と架空未知宣言の到達を分ける入口。
		fixture.signatureCalls.clear() ;
		DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( fixture.input,
															   OfficialDriverArchiveFormat::ZIP,
															   normal) == 0) ;
		DRIVERCRATE_EXPECT( context,
						   normal.infs.size() == 1U &&
							   normal.infs.front().state ==
								   (legacyRejected ? CommonInfInspectionState::CLOSURE_REJECTED
												   : CommonInfInspectionState::VERIFIED) &&
							   (legacyRejected ? normal.infs.front().error != 0
											   : normal.infs.front().error == 0) &&
							   fixture.signatureCalls.size() == (legacyRejected ? 0U : 1U)) ;
	}
}

/** @brief keyなし正常行・禁止登録行と正規Software Type 2を通常policyで比較する。
 * @param[in,out] context 有限assertion集計。
 * @note 実source／readerを使うが署名は専用fakeで、software／registry作用を実行しない。
 */
void testActionPolicyRows( TestContext &context)
{
	const std::array<std::pair<std::string_view, std::string_view>, 9U> cases{
		{{"", ""},
		 {"", "[FixtureCopy]\r\nsample.sys,,,2\r\n"},
		 {"AddReg=FixtureReg\r\n", "[FixtureReg]\r\nHKR,,FictionalSetting,0x10001,7\r\n"},
		 {"AddReg=FixtureReg\r\n", "[FixtureReg]\r\nHKR,,FictionalSetting,0,%ScalarValue%\r\n"
								   "[Strings]\r\nScalarValue=\"Fictional Plain Value\"\r\n"},
		 {"AddReg=FixtureReg\r\n",
		  "[FixtureReg]\r\nHKLM,\"Software\\Microsoft\\Windows\\CurrentVersion\\Run\",Fixture,0,\"fixture.exe\"\r\n"},
		 {"AddReg=FixtureReg\r\n",
		  "[FixtureReg]\r\nHKCU,\"sOfTwArE\\mIcRoSoFt\\wInDoWs\\cUrReNtVeRsIoN\\rUnOnCe\",Fixture,0,\"fixture.exe\"\r\n"},
		 {"AddReg=FixtureReg\r\n",
		  "[FixtureReg]\r\nHKLM,%RunKey%,Fixture,0,\"fixture.exe\"\r\n"
		  "[Strings]\r\nRunKey=\"Software\\Microsoft\\Windows\\CurrentVersion\\Run\"\r\n"},
		 {"AddReg=FixtureReg\r\n",
		  "[FixtureReg]\r\nHKR,,cOiNsTaLlErS32,0x10000,\"fixture.dll\"\r\n"},
		 {"",
		  "[Install.NT.Software]\r\nAddSoftware=FictionalDeviceCompanion,,FixtureSoftware\r\n"
		  "[FixtureSoftware]\r\nSoftwareType=2\r\n"
		  "SoftwareID=pfn://Fictional.DriverCrateCompanion_abcdefghjkmnp\r\n"}}} ;	// 形式準拠の架空入力だけ。
	// 九構成を同じ閉包・fake署名条件で比較し、導入作用を実行しない。
	for( std::size_t index = 0U; index < cases.size(); ++index) {
		MatrixCase spec ;	// 基準のINF／CAT／SYSを保つ一構成。
		spec.install	  = cases[index].first ;
		spec.rootCopyList = index == 1U ;
		BoundaryFixture				  fixture( spec, 1010U + index, "Ports",
											  cases[index].second) ;	// 単独所有入力。
		BoundaryScope				  scope( fixture) ;					// 通常検査へ署名応答だけを借用する。
		CommonDriverPackageInspection result ;							// candidate／planを持たない通常検査結果。
		DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( fixture.input,
															   OfficialDriverArchiveFormat::ZIP,
															   result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.infs.size() == 1U) ;
		// 原root一行のないfixtureを部分成功へ変換しない。
		if( result.infs.size() != 1U) {
			continue ;
		}

		const bool rejected =
			index >= 4U ;						// 正常四形を保持し、Run／CoInstaller登録とsoftware予約を拒否する。
		const auto &row = result.infs.front() ;	// 同じ原rootへ結ぶ一結果。
		DRIVERCRATE_EXPECT(
			context, row.state == (rejected ? CommonInfInspectionState::CLOSURE_REJECTED
											: CommonInfInspectionState::VERIFIED) &&
						 row.error == (rejected ? HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) : 0)) ;
		DRIVERCRATE_EXPECT( context, fixture.signatureCalls.size() == (rejected ? 0U : 1U) &&
										fixture.nativeCalls == 0U) ;
		// 署名到達した正例は同じINF／CATと一source集合だけを要求する。
		if( !fixture.signatureCalls.empty()) {
			DRIVERCRATE_EXPECT( context,
							   fixture.signatureCalls.front().inf == L"sample.inf" &&
								   fixture.signatureCalls.front().catalog == L"sample.cat" &&
								   fixture.signatureCalls.front().sources ==
									   std::vector<std::wstring>{L"sample.sys"}) ;
		}

		fixture.signatureCalls.clear() ;
		fixture.nativeCalls = 0U ;
		MaintenanceDriverPackageInspection
			maintenance ;	// 通常拒否とは独立した内容署名・位置の射影。
		DRIVERCRATE_EXPECT( context,
						   inspectMaintenanceDriverPackage(
							   fixture.input, OfficialDriverArchiveFormat::ZIP, maintenance) == 0) ;
		DRIVERCRATE_EXPECT( context, maintenance.infs.size() == 1U) ;
		// 元rootに結ばない部分観測を次の軸比較へ使わない。
		if( maintenance.infs.size() != 1U) {
			continue ;
		}

		const auto &content = maintenance.infs.front() ;	// 同じ原INFの保守専用結果。
		const bool	fileCoverageComplete =
			index < 4U ;	// scalar dataと明示file listは具体的未知file用途なし。
		DRIVERCRATE_EXPECT( context,
						   content.rootIntegrity.state == MaintenanceInspectionState::PASSED &&
							   content.rootIntegrity.error == 0) ;
		DRIVERCRATE_EXPECT(
			context, content.referenceCoverage ==
							 (fileCoverageComplete ? MaintenanceInfReferenceCoverage::COMPLETE
												   : MaintenanceInfReferenceCoverage::INCOMPLETE) &&
						 content.integrity.state ==
							 (fileCoverageComplete ? MaintenanceInspectionState::PASSED
												   : MaintenanceInspectionState::NOT_CHECKED) &&
						 content.integrity.error == 0) ;
		DRIVERCRATE_EXPECT( context,
						   content.installRoute.state ==
								   (rejected ? MaintenanceInspectionState::UNSUPPORTED
											 : MaintenanceInspectionState::PASSED) &&
							   content.installRoute.error ==
								   (rejected ? HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) : 0)) ;
		DRIVERCRATE_EXPECT( context,
						   content.applicability.state == MaintenanceInspectionState::NOT_CHECKED &&
							   content.dependency.state == MaintenanceInfDependencyState::NONE) ;
		DRIVERCRATE_EXPECT( context,
						   fixture.signatureCalls.size() == 1U && fixture.nativeCalls == 1U) ;
	}
}

/** @brief fake合格の後もINF／CAT／SYS全byteの欠落・改変を再検証が拒否する。
 * @param[in,out] context 有限assertion集計。
 */
void testReverificationBytes( TestContext &context)
{
	constexpr std::array<std::wstring_view, 3U> names{L"sample.inf", L"sample.cat",
													  L"sample.sys"} ;	// 全member。
	// 三memberを欠落／同size改変の二形で検証し、署名再呼出しより前で拒否する。
	for( std::size_t index = 0U; index < 6U; ++index) {
		BoundaryFixture fixture( MatrixCase{}, 950U + index) ;	// 架空sourceの全member成功条件。
		BoundaryScope	scope( fixture) ;						// 内容成功はこのEXEだけのfake。
		CommonDriverPackageInspection result ;					// 実閉包と実hashを所有する通常DTO。
		DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( fixture.input,
															   OfficialDriverArchiveFormat::ZIP,
															   result) == 0) ;
		DRIVERCRATE_EXPECT( context,
						   result.infs.size() == 1U &&
							   result.infs.front().state == CommonInfInspectionState::VERIFIED) ;
		// 合格閉包を持たないfixtureを変更してはいけない。
		if( result.infs.size() != 1U || !result.infs.front().workspace) {
			continue ;
		}

		auto	  &inf	= result.infs.front() ;	// 所有するfixtureの閉包だけを変更する。
		const auto name = names[index / 2U] ;	// 三memberの順序。
		DRIVERCRATE_EXPECT( context, reverifyCommonDriverInf( inf) == 0) ;
		fixture.signatureCalls.clear() ;
		DRIVERCRATE_EXPECT( context, inf.workspace->discardFile( name) == 0) ;
		// 改変形だけは同sizeの別実byteを同じ所有pathへ作る。
		if( index % 2U != 0U) {
			std::string changed = fixture.find( name)->bytes ;	// 元hashは更新しない。
			changed.front()		= changed.front() == 'X' ? 'Y' : 'X' ;
			DRIVERCRATE_EXPECT( context, writeFixture( *inf.workspace, name, changed)) ;
		}

		const NativeError error = reverifyCommonDriverInf( inf) ;	// 実hash／sizeの拒否。
		DRIVERCRATE_EXPECT( context,
						   error == (index % 2U == 0U ? HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)
													  : SIGNATURE_FAILURE)) ;
		DRIVERCRATE_EXPECT( context, fixture.signatureCalls.empty()) ;
	}
}

/** @brief 通常19 Classの名前policyと追加二Classの隔離をfake署名条件で比較する。
 * @param[in,out] context 有限assertion集計。
 * @note ClassGuid固定の名前policy試験。全Windows Class妥当性や端末適用性ではない。
 */
void testNormalClassPolicy( TestContext &context)
{
	constexpr std::array<std::string_view, 21U> classes{
		"Biometric", "Bluetooth", "Camera",			"Display", "HIDClass",		  "Image",
		"Keyboard",	 "MEDIA",	  "Modem",			"Monitor", "Mouse",			  "Multifunction",
		"Net",		 "Ports",	  "Printer",		"Sensor",  "SmartCardReader", "USB",
		"USBDevice", "System",	  "MultiPortSerial"} ;	// 従来19と内容専用二。
	// 全名称を同じ実source／CAT／SYS条件で比較する。
	for( std::size_t index = 0U; index < classes.size(); ++index) {
		BoundaryFixture fixture( MatrixCase{}, 970U + index, classes[index]) ;	// 同一の静的条件。
		BoundaryScope	scope( fixture) ;										// 正当な通常policy通過だけを架空署名へ渡す。
		CommonDriverPackageInspection result ;									// 導入能力は発行しない通常検査DTO。
		DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( fixture.input,
															   OfficialDriverArchiveFormat::ZIP,
															   result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.infs.size() == 1U) ;
		// 一行だけの結果がない場合は範囲外参照を行わない。
		if( result.infs.size() != 1U) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, result.infs.front().state ==
										(index < 19U ? CommonInfInspectionState::VERIFIED
													 : CommonInfInspectionState::CLOSURE_REJECTED)) ;
		DRIVERCRATE_EXPECT( context, fixture.signatureCalls.size() == (index < 19U ? 1U : 0U)) ;
		DRIVERCRATE_EXPECT( context, fixture.nativeCalls == 0U) ;
	}
}

/** @brief 未設定／未知入力／再入をfake成功へfallbackしない。
 * @param[in,out] context 有限assertion集計。
 */
void testBoundaryRejections( TestContext &context)
{
	OfficialDownloadWorkspace empty ;	// 未設定境界では参照しない空領域。
	OfficialInfPackage		  package ;	// 未知入力も署名成功にしない。
	InfDependencyNativeResult result ;	// 未設定nativeは必ず空へ戻す。
	DRIVERCRATE_EXPECT( context,
					   verifyMaintenanceInfIntegrityForTest( empty, package) == E_UNEXPECTED) ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceInfDependenciesForTest( empty, {}, 0U, {}, 1U,
																		 result) == E_UNEXPECTED &&
									result.dependency.documents.empty()) ;
	BoundaryFixture fixture( MatrixCase{}, 999U) ;	// 同じthreadだけの所有者。
	{
		BoundaryScope scope( fixture) ;	// scope終了後にslotを残さない。
		package.infRelativePath = L"unknown.inf" ;
		DRIVERCRATE_EXPECT( context, verifyMaintenanceInfIntegrityForTest( fixture.source, package) ==
										E_UNEXPECTED) ;
		package.infRelativePath		= L"sample.inf" ;
		package.catalogRelativePath = L"sample.cat" ;
		package.sourceFiles			= {L"unknown.sys"} ;
		DRIVERCRATE_EXPECT( context, verifyMaintenanceInfIntegrityForTest( fixture.source, package) ==
											E_UNEXPECTED &&
										fixture.signatureCalls.empty()) ;
		const std::array<InfDependencyPackageMember, 1U> members{
			{{L"sample.inf", fixture.files.front().hash,
			  // 元root。
			  fixture.files.front().bytes.size()}}} ;
		const std::array<std::wstring, 1U> badSeeds{L"UnknownSection"} ;	// 元構成にないseed。
		DRIVERCRATE_EXPECT(
			context, inspectMaintenanceInfDependenciesForTest( fixture.source, members, 0U, badSeeds,
															  1U, result) == E_UNEXPECTED &&
						 result.dependency.documents.empty() && fixture.nativeCalls == 0U) ;
		bool rejected{} ;	// 再入の例外が発生したことだけを観測する。
		try {
			BoundaryScope nested( fixture) ;	// 外側のscopeを上書きしない。
		} catch( const std::runtime_error &) {
			rejected = true ;
		}

		DRIVERCRATE_EXPECT( context, rejected && activeFixture == &fixture) ;
	}

	DRIVERCRATE_EXPECT( context, activeFixture == nullptr && verifyMaintenanceInfIntegrityForTest(
																empty, package) == E_UNEXPECTED) ;
}
/** @brief 通常package全fieldを観測の有無で比較する。
 * @param[in,out] context 有限assertion集計。
 * @param[in] left 元通常結果。
 * @param[in] right 研究入口の通常結果。
 */
void expectObservationUnchanged( TestContext								 &context,
								const MaintenanceDriverPackageInspection &left,
								const MaintenanceDriverPackageInspection &right)
{
	DRIVERCRATE_EXPECT(
		context,
		left.error == right.error && left.scanSessionId == right.scanSessionId &&
			left.archiveSha256 == right.archiveSha256 && left.archiveBytes == right.archiveBytes &&
			left.inventoryFileCount == right.inventoryFileCount &&
			left.inspectedBytes == right.inspectedBytes &&
			left.parser.state == right.parser.state && left.parser.error == right.parser.error &&
			left.infs.size() == right.infs.size()) ;
	// 全rowを同順・同hashで比較し、個別FAILEDも除外しない。
	for( std::size_t index = 0U; index < (std::min)( left.infs.size(), right.infs.size()); ++index) {
		const auto &a = left.infs[index] ;	// 元row全field。
		const auto &b = right.infs[index] ;	// 同じ原ZIPの研究row。
		DRIVERCRATE_EXPECT(
			context,
			a.infSha256 == b.infSha256 && a.archiveDepth == b.archiveDepth &&
				a.inspectedBytes == b.inspectedBytes && a.parser.state == b.parser.state &&
				a.parser.error == b.parser.error && a.contentKind == b.contentKind &&
				a.referenceCoverage == b.referenceCoverage &&
				a.rootIntegrity.state == b.rootIntegrity.state &&
				a.rootIntegrity.error == b.rootIntegrity.error &&
				a.integrity.state == b.integrity.state && a.integrity.error == b.integrity.error &&
				a.applicability.state == b.applicability.state &&
				a.applicability.error == b.applicability.error &&
				a.installRoute.state == b.installRoute.state &&
				a.installRoute.error == b.installRoute.error &&
				a.dependency.state == b.dependency.state &&
				a.dependency.reason == b.dependency.reason &&
				a.dependency.error == b.dependency.error &&
				a.dependency.observedReferenceCount == b.dependency.observedReferenceCount &&
				a.dependency.resolvedInfCount == b.dependency.resolvedInfCount &&
				a.dependenciesChecked == b.dependenciesChecked &&
				a.hasExternalDependencies == b.hasExternalDependencies) ;
	}
}

/** @brief 有限16条件群で同run最終参照と元判定・privacy・拒否境界を比較する。
 * @param[in,out] context 有限assertion集計。
 * @note 実readerと同fixtureの架空署名を使う。実署名・実device成功を意味しない。
 */
void testReachedReferenceObservation( TestContext &context)
{
	constexpr std::string_view STDOUT =
		"{\"schema\":\"fixture-v2\"}\r\n" ;	// 改行を含む実hash契約fixture。
	// 到達5・位置4・残り7の承認済み16群を一度ずつ実行する。
	for( std::size_t group = 0U; group < 16U; ++group) {
		MatrixCase spec ;	// 旧構成の既定を保持する。
		spec.rootCopyList = true ;
		std::string extra =
			"[DestinationDirs]\r\nFixtureCopy=13\r\n[FixtureCopy]\r\nsample.sys\r\n"
			"[Install.NT.Services]\r\nAddService=FictionalService,2,ServiceInstall\r\n"
			// named13成功の元byte。
			"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%13%\\sample.sys\r\n" ;
		// 元未到達節のbinaryを現在OSの到達へ加えない。
		if( group == 1U) {
			extra += "[UnreachedFixture]\r\nServiceBinary=unreached.sys\r\n" ;
		}

		// 別OSの付随節を現在OSの到達へ加えない。
		if( group == 2U) {
			extra += "[Install.NTx86.Services]\r\nServiceBinary=other-os.sys\r\n" ;
		}

		// Include資料と最終共有seedを原byteとfake核応答へ一対一で結ぶ。
		if( group == 3U || group == 4U || group == 11U) {
			spec.nativeMode	 = group == 11U ? NativeMode::PACKAGE_FAILED : NativeMode::PACKAGE ;
			spec.includeOnly = group == 3U ;
			spec.sharedNeed	 = group == 4U ;
		}

		// 親defaultだけの展開は元UNSUPPORTEDのまま残す。
		if( group == 6U) {
			extra.replace( extra.find( "FixtureCopy=13"), 14U, "DefaultDestDir=12") ;
			extra.replace( extra.find( "%13%"), 4U, "%12%") ;
		}

		// sourceと使用先の欠落を宣言消去で補完しない。
		if( group == 7U) {
			spec.rootFile = false ;
		}

		// 同source複数named候補の原曖昧HRESULTを保持する。
		if( group == 8U) {
			spec.install = "CopyFiles=SecondCopy\r\n" ;
			extra.replace( extra.find( "FixtureCopy=13"), 14U, "FixtureCopy=12\r\nSecondCopy=12") ;
			extra.replace( extra.find( "%13%"), 4U, "%12%") ;
			extra += "[SecondCopy]\r\nsample.sys\r\n" ;
		}

		// 位置成功や不足がrootの既知FAILEDを消さない。
		if( group == 10U) {
			spec.rootError = SIGNATURE_FAILURE ;
		}

		BoundaryFixture fixture( spec, 5300U + group, "Ports", extra) ;	// 同一原ZIPの一元所有者。
		BoundaryScope	scope( fixture) ;								// 元byteとfake署名をこの同期scopeだけで借用する。
		MaintenanceDriverPackageInspection normal ;						// 観測なし通常結果。
		MaintenanceDriverPackageInspection observed ;					// 観測ありの同じ全field。
		ReachedReferenceCollector		   collector ;					// 同run stack所有の具体型。
		DriverArchiveInput input = fixture.input ;						// 拒否試験だけで元期待hashを変える。
		// 元byte mismatchを部分成功へ縮小しない。
		if( group == 12U) {
			input.sha256 = std::wstring( 64U, L'a') ;
		}

		std::size_t normalChecks{} ;	// 元取消し呼出しの順序。
		std::size_t observedChecks{} ;	// 観測が取消し回数を増やさないことを確認する。
		const std::function<bool()> normalCancel = [&normalChecks, group]() {
			return group == 13U && ++normalChecks == 3U ;
		} ; // 最終取消しだけ。
		const std::function<bool()> observedCancel = [&observedChecks, group]() {
			return group == 13U && ++observedChecks == 3U ;
		} ; // 同じ順序を借用する。
		const auto normalError = inspectMaintenanceDriverPackage(
			input, OfficialDriverArchiveFormat::ZIP, normal, normalCancel) ;	// 元入口。
		const auto observedError = inspectReachedMaintenanceDriverPackage(
			input, OfficialDriverArchiveFormat::ZIP, observed, collector,
			observedCancel) ;	// 各INF extract一回だけ。
		DRIVERCRATE_EXPECT( context, normalError == observedError) ;
		expectObservationUnchanged( context, normal, observed) ;
		// 元全体拒否では研究の仮結果も残さない。
		if( group == 12U || group == 13U) {
			DRIVERCRATE_EXPECT( context, observedError != 0 && collector.rootCount() == 0U &&
											!collector.serialize( "fixture", observed, STDOUT)) ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context, observedError == 0 && collector.error() == 0 &&
										collector.rootCount() == observed.infs.size()) ;
		const auto serialized =
			// 各原結果を全byteへ結ぶ。
			collector.serialize( "fixture", observed, STDOUT) ;
		DRIVERCRATE_EXPECT( context, serialized.has_value()) ;
		// 原失敗を残した上で、未確定optionalを参照しない。
		if( !serialized || observed.infs.empty()) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, serialized->find( "SOURCE_DECLARATION") != std::string::npos &&
										serialized->find( "SERVICE_BINARY") != std::string::npos &&
										serialized->find( "NOT_OBSERVED") != std::string::npos &&
										serialized->find( "FictionalService") == std::string::npos &&
										serialized->find( "sample.sys") == std::string::npos &&
										serialized->find( "ServiceInstall") == std::string::npos &&
										serialized->find( "ROOT\\") == std::string::npos) ;
		// 未到達／別OSの値を研究本文へ保存しない。
		if( group == 1U || group == 2U) {
			DRIVERCRATE_EXPECT( context, serialized->find( "unreached") == std::string::npos &&
											serialized->find( "other-os") == std::string::npos) ;
		}

		// Include資料の空seedと共有seed追加後の最終参照を区別する。
		if( group == 3U) {
			DRIVERCRATE_EXPECT( context,
							   serialized->find( "\"firstPresentSeedId\":0") != std::string::npos) ;
		}

		// 最終package候補を途中履歴やnative採用と呼ばない。
		if( group == 4U) {
			DRIVERCRATE_EXPECT(
				context, serialized->find( "PACKAGE_CANDIDATE") != std::string::npos &&
							 serialized->find( "FIRST_PRESENT_SEED_ONLY") != std::string::npos) ;
		}

		// 元各位置の診断を特定helper原因へ再分類しない。
		if( group >= 5U && group <= 8U) {
			const std::string expected =
				group == 6U
					? "UNSUPPORTED"
					: (group == 7U ? "MISSING"
								   : (group == 8U ? "UNSUPPORTED" : "LOCATED")) ;	// 元位置期待。
			DRIVERCRATE_EXPECT( context, serialized->find( "\"location\":\"" + expected + "\"") !=
											std::string::npos) ;
		}

		// 元既知FAILEDと原HRESULTを不足や位置成功で消さない。
		if( group == 10U || group == 11U) {
			DRIVERCRATE_EXPECT( context, observed.infs.front().integrity.state ==
												MaintenanceInspectionState::FAILED &&
											serialized->find( std::to_string( SIGNATURE_FAILURE)) !=
												std::string::npos) ;
		}

		// 以下は同じ実closureを借用して計測だけの境界を確認する。
		if( group == 9U || group == 14U || group == 15U) {
			const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 同じ原root。
			OfficialDownloadWorkspace				workspace ;					// 架空extractの所有者。
			MaintenanceDriverClosure				closure ;					// 実readerの最終結果。
			DRIVERCRATE_EXPECT(
				context, extractMaintenanceDriverClosure( {&fixture.input,
														  OfficialDriverArchiveFormat::ZIP,
														  {},
														  selected,
														  L"reached-boundary"},
														 CONTENT_POLICY, workspace, closure) == 0) ;
			// 同hash別位置の参照を先頭へ併合しない。
			if( group == 9U && !closure.references.empty()) {
				closure.references.push_back( closure.references.front()) ;
				closure.references.back().infRelativePath = L"other/sample.inf" ;
				ReachedReferenceCollector duplicate ;	// 原hashを共有しても各ordinalを残す。
				duplicate.append( closure, observed.infs.front(), 0U) ;
				duplicate.finish( observed) ;
				const auto value =
					// 同じ元rowへ結ぶ。
					duplicate.serialize( "fixture", observed, STDOUT) ;
				DRIVERCRATE_EXPECT( context,
								   value && value->find( "\"infOrdinal\":1") != std::string::npos &&
									   value->find( "\"graphIdentity\":0") != std::string::npos) ;
			}

			// 未知enum・opaque不整合・run ID injectionと改行差を拒否する。
			if( group == 14U && !closure.references.empty()) {
				closure.references.front().files.front().location =
					static_cast<MaintenanceInfFileLocation>( 99U) ;
				ReachedReferenceCollector invalid ;	// 元結果は変更せず計測だけを拒否する。
				invalid.append( closure, observed.infs.front(), 0U) ;
				DRIVERCRATE_EXPECT( context,
								   invalid.error() != 0 && invalid.rootCount() == 0U &&
									   !collector.serialize( "bad\"key", observed, STDOUT) &&
									   !collector.serialize( "fixture", observed, "{}\n")) ;
				closure.references.front().files.front().location =
					MaintenanceInfFileLocation::LOCATED ;
				closure.dependency.dependency.edges.push_back( {999U}) ;
				ReachedReferenceCollector opaque ;	// 元graphの未知identityを拒否する。
				opaque.append( closure, observed.infs.front(), 0U) ;
				DRIVERCRATE_EXPECT( context, opaque.error() != 0 && opaque.rootCount() == 0U) ;
			}

			// 原参照64と＋1・各用途4096と＋1・stdout256KiBと＋1を別計測で検査する。
			if( group == 15U && !closure.references.empty()) {
				closure.references.resize( 64U, closure.references.front()) ;
				ReachedReferenceCollector limit ;	// 上限を受理する有限射影。
				limit.append( closure, observed.infs.front(), 0U) ;
				DRIVERCRATE_EXPECT( context, limit.error() == 0) ;
				closure.references.push_back( closure.references.front()) ;
				ReachedReferenceCollector over ;	// ＋1を切捨てず拒否する。
				over.append( closure, observed.infs.front(), 0U) ;
				DRIVERCRATE_EXPECT( context, over.error() != 0 && over.rootCount() == 0U) ;
				closure.references.resize( 1U) ;
				closure.references.front().files.resize( 4096U,
														closure.references.front().files.front()) ;
				ReachedReferenceCollector uses ;	// 元各用途上限。
				uses.append( closure, observed.infs.front(), 0U) ;
				DRIVERCRATE_EXPECT( context, uses.error() == 0) ;
				closure.references.front().files.push_back(
					closure.references.front().files.front()) ;
				ReachedReferenceCollector excess ;	// 元＋1は全拒否。
				excess.append( closure, observed.infs.front(), 0U) ;
				DRIVERCRATE_EXPECT( context, excess.error() != 0 && excess.rootCount() == 0U) ;
				std::string exact( 256U * 1024U - 2U, 'x') ;	// stdout全byte上限のfixture。
				exact += "\r\n" ;
				DRIVERCRATE_EXPECT( context,
								   collector.serialize( "fixture", observed, exact).has_value()) ;
				exact.insert( exact.begin(), 'x') ;
				DRIVERCRATE_EXPECT( context, !collector.serialize( "fixture", observed, exact)) ;
			}
		}
	}

	std::wstring parent = DRIVERCRATE_REACHED_WORKSPACE ;	// 新53のこの構成だけのwriter fixture親。
	std::ranges::replace( parent, L'/', L'\\') ;
	const std::wstring path =
		parent +
		L"\\20261008-maintenance-reached-reference-53-fixture-sidecar.json" ;	// 正確な許可stem。
	BoundaryFixture	   fixture( MatrixCase{}, 5399U) ;							// reparse先もこのfixtureの所有領域だけ。
	const std::wstring target = fixture.input.inspectionPath.substr(
		0U, fixture.input.inspectionPath.find_last_of( L'\\')) ;	// 架空ZIP親。
	const BOOL linked = CreateSymbolicLinkW(
		parent.c_str(), target.c_str(),
		SYMBOLIC_LINK_FLAG_DIRECTORY |
			SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) ;	// 元親のreparse拒否fixture。
	DRIVERCRATE_EXPECT( context, linked != FALSE) ;
	// 作成した自分のlinkだけを解除し、target内のfileを削除しない。
	if( linked != FALSE) {
		DRIVERCRATE_EXPECT( context, writeReachedReferenceSidecar( path, "fixture", "{}") != 0) ;
		DRIVERCRATE_EXPECT( context, RemoveDirectoryW( parent.c_str()) != FALSE) ;
	}

	DRIVERCRATE_EXPECT( context, CreateDirectoryW( parent.c_str(), nullptr) != FALSE) ;
	DRIVERCRATE_EXPECT( context,
					   writeReachedReferenceSidecar( L"relative.json", "fixture", "{}") != 0 &&
						   writeReachedReferenceSidecar( path + L"extra", "fixture", "{}") != 0) ;
	DRIVERCRATE_EXPECT( context, writeReachedReferenceSidecar( path, "fixture", "{}") == 0) ;
	DRIVERCRATE_EXPECT( context,
					   writeReachedReferenceSidecar( path, "fixture", "{}") ==
						   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_EXISTS))) ;
	// 成功した架空fixtureだけを解除し、実研究sidecarと部分失敗fileは触らない。
	DRIVERCRATE_EXPECT( context, DeleteFileW( path.c_str()) != FALSE) ;
	DRIVERCRATE_EXPECT( context, RemoveDirectoryW( parent.c_str()) != FALSE) ;
}
} // namespace
} // namespace drivercrate::test

/** @brief 専用非通信・非導入回帰と合成API境界を実行し件数・numeric・hashを表示する。
 * @return 全assertion成功0、不一致またはfixture例外1。
 */
int main()
{
	drivercrate::test::TestContext context ;	// このprocessだけの有限assertion集計。
	try {
		drivercrate::test::testBoundaryRejections( context) ;
		drivercrate::test::testIntegrityMatrix( context) ;
		drivercrate::test::testNamedServiceIntegrity( context) ;
		drivercrate::test::testEventLogMarkerSeparation( context) ;
		drivercrate::test::testExpandedBinaryIntegrity( context) ;
		drivercrate::test::testDangerousActions( context) ;
		drivercrate::test::testActionPolicyRows( context) ;
		drivercrate::test::testReverificationBytes( context) ;
		drivercrate::test::testNormalClassPolicy( context) ;
		drivercrate::test::testReachedReferenceObservation( context) ;
		drivercrate::test::testResidualReferenceObservation( context) ;
		std::cout << "Original regression assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		DRIVERCRATE_EXPECT( context,
						   context.assertionCount() == 2605 && context.failureCount() == 0) ;
		drivercrate::test::testFieldCompletenessBoundary( context) ;
		DRIVERCRATE_EXPECT( context,
						   context.assertionCount() == 3119 && context.failureCount() == 0) ;
		drivercrate::test::testCompleteValueProof( context) ;
	} catch( ...) {
		// payload・path・commandを出力せず、予期しないfixture失敗を拒否終了へ残す。
		std::cerr << "Maintenance integrity fixture exception.\n" ;
		return 1 ;
	}

	std::cout
		<< "Integrity matrix: 12, named configurations: 27, expanded binary configurations: 34, actions: 7, policy rows: 9, member changes: 6, Class policies: 21, Assertions: "
		<< context.assertionCount() << ", failures: " << context.failureCount() << '\n'
		<< "Reached reference condition groups: 16\nResidual reference condition groups: 8\nEventlog marker condition groups: 9, configurations: 36, private capacity: 3500, reader lines: 4096 plus 1\n" ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
