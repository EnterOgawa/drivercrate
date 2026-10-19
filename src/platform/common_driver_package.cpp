//------------------------------------------------------------------------------
/**
 * @file common_driver_package.cpp
 * @brief 由来と独立したdriver packageの保護取込みと個別検査。
 * @version 01.14.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  内容署名と未解決依存の表示を分離。
 * Ver.01.02.00 Shunji Ogawa  2026/10/05  非実行の保守内容検証と導入経路を独立評価。
 * Ver.01.03.00 Shunji Ogawa  2026/10/05  保守内容検査だけで非圧縮EXE参照を検証。
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  標準二構文識別子を通常検査・再検査へ接続。
 * Ver.01.05.00 Shunji Ogawa  2026/10/07  通常19 Classを保持して内容専用21 Classへ分離。
 * Ver.01.06.00 Shunji Ogawa  2026/10/07  部分保守閉包の旧全integrity誤昇格を抑止。
 * Ver.01.07.00 Shunji Ogawa  2026/10/07  保守閉包の独立状態を射影し従来routeと分離。
 * Ver.01.08.00 Shunji Ogawa  2026/10/08  研究compile限定で同scope最終参照をstack collectorへ借用。
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  全CAT閉包から一基本INFの必要構成計画を構築。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  全import graphと選択機能graphの独立境界を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/13  選択節のInclude/Needsを元byteと独立効果の検査へ結合。
 * Ver.01.12.00 Shunji Ogawa  2026/10/14  監視側の明示一INFへ通常policyの同じ実検査を接続。
 * Ver.01.13.00 Shunji Ogawa  2026/10/15  同元内容の必要関係から数値拒否段階を伝播。
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  実選択graphの充足Needsを追加INFと別に保持。
 * </pre>
 *
 * @note 入力と閉包をworker内だけで保持し、取得元証明や導入許可を発行しません。
 * @see docs/adr/0151-common-package-content-and-origin-separation.md
 * @see docs/adr/0263-common-inf-syntax-and-action-boundaries.md
 */
//------------------------------------------------------------------------------

#include "platform/common_driver_package.h"
#include "platform/inf_dependency_native.h"

#include "core/candidate_assessment.h"
#include "core/device_observation.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"

// 研究EXE内だけに最終closureの同期借用を接続し、通常compileへ状態を残さない。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
#include "maintenance_reached_reference_observation.h"
#endif

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内容検査の有限policy。
//------------------------------------------------------------------------------

constexpr std::uint64_t		INPUT_BYTES		 = 128ULL * 1024ULL * 1024ULL ;	// 外側入力上限。
constexpr std::uint64_t		EXPANDED_BYTES	 = 512ULL * 1024ULL * 1024ULL ;	// 展開／保持上限。
constexpr std::size_t		INF_COUNT		 = 128U ;						// 全archive合計のINF数上限。
constexpr std::size_t		NESTED_COUNT	 = 16U ;						// 一段nested archive数上限。
constexpr DWORD				COPY_CHUNK_BYTES = 1024U * 1024U ;				// 同期copyのbyte上限。
constexpr std::wstring_view COPY_NAME		 = L"input.archive" ;			// 保護copyの固定内部名。
constexpr std::array		CLASSES{
	   std::wstring_view( L"Biometric"), std::wstring_view( L"Bluetooth"), std::wstring_view( L"Camera"),
	   std::wstring_view( L"Display"), std::wstring_view( L"HIDClass"), std::wstring_view( L"Image"),
	   std::wstring_view( L"Keyboard"), std::wstring_view( L"MEDIA"), std::wstring_view( L"Modem"),
	   std::wstring_view( L"Monitor"), std::wstring_view( L"Mouse"), std::wstring_view( L"Multifunction"),
	   std::wstring_view( L"Net"), std::wstring_view( L"Ports"), std::wstring_view( L"Printer"),
	   std::wstring_view( L"Sensor"), std::wstring_view( L"SmartCardReader"), std::wstring_view( L"USB"),
	   // 基本driverの静的検査対象。未知classは未対応へ残す。
	   std::wstring_view( L"USBDevice")} ;
// 内容解析だけが扱う追加Class。通常policyと導入許可の集合へ流用しない。
constexpr std::array CONTENT_CLASSES{CLASSES[0],
									 CLASSES[1],
									 CLASSES[2],
									 CLASSES[3],
									 CLASSES[4],
									 CLASSES[5],
									 CLASSES[6],
									 CLASSES[7],
									 CLASSES[8],
									 CLASSES[9],
									 CLASSES[10],
									 CLASSES[11],
									 CLASSES[12],
									 CLASSES[13],
									 CLASSES[14],
									 CLASSES[15],
									 CLASSES[16],
									 CLASSES[17],
									 CLASSES[18],
									 std::wstring_view( L"System"),
									 std::wstring_view( L"MultiPortSerial")} ;
static_assert( CLASSES.size() == 19U && CONTENT_CLASSES.size() == 21U) ;
// 必要役割はClass同一の基本driver候補へ変換せず、関係検査の別役割へ渡します。
constexpr std::array				  REQUIRED_CLASSES{CLASSES[0],
									   CLASSES[1],
									   CLASSES[2],
									   CLASSES[3],
									   CLASSES[4],
									   CLASSES[5],
									   CLASSES[6],
									   CLASSES[7],
									   CLASSES[8],
									   CLASSES[9],
									   CLASSES[10],
									   CLASSES[11],
									   CLASSES[12],
									   CLASSES[13],
									   CLASSES[14],
									   CLASSES[15],
									   CLASSES[16],
									   CLASSES[17],
									   CLASSES[18],
									   std::wstring_view( L"Extension"),
									   std::wstring_view( L"SoftwareComponent")} ;
constexpr std::array				  SIGNATURES{std::wstring_view( L"$Windows NT$"),
								 // 標準INF構文。CAT暗号署名とは独立。
								 std::wstring_view( L"$Chicago$")} ;
constexpr OfficialInfInspectionPolicy INF_POLICY{
	.maximumHardwareIds			   = 4096U,
	.maximumSourceFiles			   = 8192U,
	.acceptedClasses			   = REQUIRED_CLASSES,
	.acceptedProviders			   = {},
	.acceptedSignatures			   = SIGNATURES,
	.acceptAnyProvider			   = true,
	.requireDriverBinary		   = false,
	.rejectUnreferencedPrograms	   = false,
	.rejectInstallActions		   = true,
	.rejectExternalDependencies	   = false,
	.allowRequiredDriverComponents = true,
} ; // 製品名、現在版、INF名を適合証拠にしない。
constexpr OfficialDriverClosurePolicy POLICY{
	.zipPolicy				   = {INPUT_BYTES, INPUT_BYTES, EXPANDED_BYTES, 4096U},
	.cabPolicy				   = {INPUT_BYTES, INPUT_BYTES, EXPANDED_BYTES, 4096U},
	.infPolicy				   = INF_POLICY,
	.maximumInfCount		   = 1U,
	.maximumClosureFiles	   = 8194U,
	.maximumClosureBytes	   = 256ULL * 1024ULL * 1024ULL,
	.maximumExpansionRatio	   = 200U,
	.maximumNestedArchiveDepth = 1U,
} ; // 各INFを独立した非実行閉包として扱う。

constexpr OfficialInfInspectionPolicy CONTENT_INF_POLICY{
	.maximumHardwareIds					  = 4096U,
	.maximumSourceFiles					  = 8192U,
	.acceptedClasses					  = CONTENT_CLASSES,
	.acceptedProviders					  = {},
	.acceptedSignatures					  = SIGNATURES,
	.acceptAnyProvider					  = true,
	.requireDriverBinary				  = false,
	.rejectUnreferencedPrograms			  = false,
	.rejectInstallActions				  = false,
	.rejectExternalDependencies			  = false,
	.allowReferencedExecutablesForContent = true,
} ; // 作用は実行せず、別の静的導入経路findingへ保持する。
constexpr OfficialDriverClosurePolicy CONTENT_POLICY{
	.zipPolicy				   = POLICY.zipPolicy,
	.cabPolicy				   = POLICY.cabPolicy,
	.infPolicy				   = CONTENT_INF_POLICY,
	.maximumInfCount		   = POLICY.maximumInfCount,
	.maximumClosureFiles	   = POLICY.maximumClosureFiles,
	.maximumClosureBytes	   = POLICY.maximumClosureBytes,
	.maximumExpansionRatio	   = POLICY.maximumExpansionRatio,
	.maximumNestedArchiveDepth = POLICY.maximumNestedArchiveDepth,
} ; // 元入力・参照・展開量・nested境界は従来と同一。

/** @brief Copy中のfile handleを単独所有する。 */
class ArchiveFile final {
public:
	/**
	 * @brief 所有するhandleを設定する。
	 * @param[in] handle CloseHandle対象またはINVALID_HANDLE_VALUE。
	 */
	explicit ArchiveFile( const HANDLE handle) noexcept : handle_( handle)
	{
	}
	/** @brief 有効な所有handleだけを閉じる。 */
	~ArchiveFile()
	{
		// 失敗したopenのsentinelをCloseHandleへ渡さない。
		if( handle_ != INVALID_HANDLE_VALUE) {
			CloseHandle( handle_) ;
		}
	}
	/**
	 * @brief copy中の所有file handleの複製構築をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	ArchiveFile( const ArchiveFile &other) = delete ;
	/**
	 * @brief copy中の所有file handleの複製代入をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @return 宣言された自己参照型です。削除宣言なので戻り値を生成しません。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	ArchiveFile			&operator=( const ArchiveFile &other) = delete ;
	/** @brief 呼出し中だけ有効な非所有handleを返す。 @return 所有handleまたはsentinel。 */
	[[nodiscard]] HANDLE get() const noexcept
	{
		return handle_ ;
	}

private:
	/// Scope終了で閉じる所有handle。
	HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

/**
 * @brief Win32診断値をHRESULTへ変換する。
 * @param[in] error Windows APIまたは検査の診断値。
 * @return 元のcodeを保持するHRESULT。
 */
[[nodiscard]] NativeError fromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

/**
 * @brief 最終path要素の拡張子をASCII小文字で得る。
 * @param[in] path 呼出し中有効なpath。
 * @return 拡張子または空。
 */
[[nodiscard]] std::wstring extensionOf( const std::wstring_view path)
{
	const std::size_t separator = path.find_last_of( L"/\\") ;	// 最終directory境界。
	const std::size_t dot		= path.find_last_of( L'.') ;	// 拡張子の開始候補。
	// Directory内のdotを拡張子として解釈しない。
	if( dot == std::wstring_view::npos ||
	   (separator != std::wstring_view::npos && dot < separator)) {
		return {} ;
	}

	std::wstring extension( path.substr( dot)) ;	// 小文字化する最終拡張子。
	std::ranges::transform( extension, extension.begin(), []( const wchar_t c) noexcept {
		return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c - L'A' + L'a') : c ;
	}) ;
	return extension ;
}

/**
 * @brief 一つのlocal通常fileを共有なしで有限copyする。
 * @param[in] path 検証済み絶対local path。
 * @param[in,out] workspace 初期化済みのcopy所有領域。
 * @param[out] byteCount 成功時だけcopy byte数。
 * @return 完全copy時0、それ以外はHRESULT。
 */
[[nodiscard]] NativeError copyArchiveBytes( const std::wstring		 &path,
										   OfficialDownloadWorkspace &workspace,
										   std::uint64_t			 &byteCount)
{
	byteCount = 0 ;
	ArchiveFile input( CreateFileW( path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
								  FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
								  nullptr)) ;	// 共有なし入力。
	// 開けないfileの内容を推測せず中止する。
	if( input.get() == INVALID_HANDLE_VALUE) {
		return fromWin32( GetLastError()) ;
	}

	BY_HANDLE_FILE_INFORMATION attributes{} ;	// Handle自身の通常file属性。
	// 属性取得に失敗した入力をcopyしない。
	if( GetFileInformationByHandle( input.get(), &attributes) == FALSE) {
		return fromWin32( GetLastError()) ;
	}

	// Pipe、directory、reparse pointを通常archiveとして扱わない。
	if( GetFileType( input.get()) != FILE_TYPE_DISK ||
	   (attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
		   0) {
		return fromWin32( ERROR_ACCESS_DENIED) ;
	}

	LARGE_INTEGER size{} ;	// Copyする実file byte数。
	// Sizeを読めない入力を無制限streamとして扱わない。
	if( GetFileSizeEx( input.get(), &size) == FALSE) {
		return fromWin32( GetLastError()) ;
	}

	// 空または有限上限を超えた入力を確保前に拒否する。
	if( size.QuadPart <= 0 || static_cast<std::uint64_t>( size.QuadPart) > INPUT_BYTES) {
		return fromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	std::uint64_t freeBytes{} ;											// Workspace volumeの実空き容量。
	NativeError	  error = workspace.queryAvailableBytes( freeBytes) ;	// 容量観測の診断値。
	// 容量不足または観測失敗時はcopyを開始しない。
	if( error != 0 || freeBytes < static_cast<std::uint64_t>( size.QuadPart)) {
		return error != 0 ? error : fromWin32( ERROR_DISK_FULL) ;
	}

	HANDLE outputHandle{INVALID_HANDLE_VALUE} ;	// 所有wrapperへ直ちに移す作成handle。
	error = workspace.createFile( COPY_NAME, outputHandle) ;
	// 作成できなければ入力だけを閉じて終了する。
	if( error != 0) {
		return error ;
	}

	ArchiveFile			   output( outputHandle) ;									// 全終了経路で閉じるcopy先。
	std::vector<std::byte> buffer( COPY_CHUNK_BYTES) ;								// 固定1 MiBのcopy用heap領域。
	std::uint64_t		   remaining = static_cast<std::uint64_t>( size.QuadPart) ;	// 残りbyte数。
	// 固定sizeを上限に1 MiBずつcopyし、短い読取りと部分書込みを拒否する。
	while( remaining != 0) {
		const DWORD requested = static_cast<DWORD>(
			std::min<std::uint64_t>( remaining, buffer.size())) ;	// 今回の有限要求量。
		DWORD read{} ;												// 実際に読んだbyte数。
		// API失敗時は直後の診断値を保持する。
		if( ReadFile( input.get(), buffer.data(), requested, &read, nullptr) == FALSE) {
			return fromWin32( GetLastError()) ;
		}

		// 宣言sizeまで読めないfileを合格させない。
		if( read != requested) {
			return fromWin32( ERROR_HANDLE_EOF) ;
		}

		DWORD written{} ;	// 実際に書いたbyte数。
		// API失敗時は直後の診断値を保持する。
		if( WriteFile( output.get(), buffer.data(), requested, &written, nullptr) == FALSE) {
			return fromWin32( GetLastError()) ;
		}

		// 部分書込みにstaleなGetLastErrorを割り当てない。
		if( written != requested) {
			return fromWin32( ERROR_WRITE_FAULT) ;
		}

		remaining -= requested ;
	}

	byteCount = static_cast<std::uint64_t>( size.QuadPart) ;
	return 0 ;
}

/**
 * @brief 全体失敗で部分閉包を破棄し、診断値だけを残す。
 * @param[in,out] inspection 今回所有する結果。
 * @param[in] error 0ではない失敗HRESULT。
 * @return 指定された診断値。
 */
NativeError failInspection( CommonDriverPackageInspection &inspection, const NativeError error)
{
	inspection		 = {} ;
	inspection.error = error ;
	return error ;
}

/**
 * @brief 個別INFを非実行閉包とWindows署名まで検査する。
 * @param[in] input 固定した内容入力。
 * @param[in] format 外側形式。
 * @param[in] nested 空または一段nested path。
 * @param[in] path Inventoryが保持するINF相対path。
 * @param[in] infIndex 検査内で一意な0起点INF連番。保護領域名へ用いる。
 * @param[out] inspected 個別結果と成功閉包。
 */
void inspectOneInf( const DriverArchiveInput &input, const OfficialDriverArchiveFormat format,
				   const std::wstring &nested, const std::wstring &path, const std::size_t infIndex,
				   CommonInfInspection &inspected)
{
	inspected.scanSessionId		= input.scanSessionId ;
	inspected.infRelativePath	= path ;
	inspected.nestedArchivePath = nested ;
	auto workspace = std::make_unique<OfficialDownloadWorkspace>() ;	// このINFだけの所有領域。
	OfficialDriverClosure closure ;										// 全署名成功まではlocalに保持する閉包。
	const std::array	  selected{std::wstring_view( path)} ;			// 一件のINFを固定する選択。
	const std::wstring	  workspaceTag =
		L"common-inf-" + std::to_wstring( infIndex) ;	// 同時保持するINF間で衝突しないtag。
	inspected.error = extractDriverClosure( {&input, format, nested, selected, workspaceTag}, POLICY,
										   *workspace, closure) ;
	// 構造を検査できないINFへ署名合格を付与しない。
	if( inspected.error != 0) {
		return ;
	}

	// 単一INF要求に対する内部整合性を要求する。
	if( closure.packages.empty() || closure.packages.size() > 8U) {
		inspected.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return ;
	}

	inspected.state = CommonInfInspectionState::SIGNATURE_REJECTED ;
	// 元CopyINFから到達した全INFの独立CAT/publisher/memberを確認します。
	for( const auto &package : closure.packages) {
		inspected.error = verifyWindowsInfPackageIntegrity( *workspace, package) ;
		// 追加役割の署名失敗をbase成功の裏へ隠しません。
		if( inspected.error != 0) {
			return ;
		}
	}

	// 署名失敗の閉包は所有を残さず、個別診断だけを保持する。
	if( inspected.error != 0) {
		return ;
	}

	inspected.state = CommonInfInspectionState::VERIFIED ;
	// 基本候補の従来単一package形を維持し、必要役割は同じ実閉包の別集合へ移します。
	for( std::size_t ordinal = 1U; ordinal < closure.packages.size(); ++ordinal) {
		inspected.requiredInfPackages.push_back( std::move( closure.packages[ordinal])) ;
	}

	closure.packages.resize( 1U) ;
	inspected.workspace = std::move( workspace) ;
	inspected.closure	= std::move( closure) ;
}

/**
 * @brief 保守用一INFの内容と導入経路を非実行で独立評価する。
 * @param[in] input 元archiveの固定内容identity。
 * @param[in] format 外側のZIPまたはCAB。
 * @param[in] nested 空または一段nested path。
 * @param[in] path Inventoryが保持するINF相対path。
 * @param[in] index 保護領域用の0起点連番。
 * @param[out] result PathとIDを持たない個別観測。
 * @param[in,out] collector 研究compileだけの同期stack所有者。Nullなら観測しない。
 * @note 閉包は関数終了で破棄する。端末適合を照合せず、導入用結果を返さない。
 */
void inspectMaintenanceInf( const DriverArchiveInput			&input,
						   const OfficialDriverArchiveFormat format, const std::wstring &nested,
						   const std::wstring &path, const std::size_t index,
						   MaintenanceInfInspection &result
// 通常compileの引数・observer状態を変更しない。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
						   ,
						   ReachedReferenceCollector *collector
#endif
)
{
	result.archiveDepth = nested.empty() ? 0U : 1U ;
	OfficialDownloadWorkspace workspace ;												// この非実行検査だけの保護領域。
	MaintenanceDriverClosure  closure ;													// 導入用型とは互換でない内容閉包。
	const std::array		  selected{std::wstring_view( path)} ;						// 一つの元INFを固定する。
	const std::wstring		  tag	= L"maintenance-inf-" + std::to_wstring( index) ;	// 有限連番。
	const NativeError		  error = extractMaintenanceDriverClosure(
		{&input, format, nested, selected, tag}, CONTENT_POLICY, workspace, closure) ;	// 内容抽出。
	// 未解析なら署名と導入経路を未検査へ残し、driver不正を断定しない。
	if( error != 0) {
		result.parser = {error == fromWin32( ERROR_NOT_SUPPORTED)
							 ? MaintenanceInspectionState::UNSUPPORTED
							 : MaintenanceInspectionState::FAILED,
						 error} ;
// 元未解析rowも同runの未観測として保持し、部分closureを公開しない。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
		// 研究観測の独立失敗を元parser診断へ返さない。
		if( collector != nullptr) {
			collector->append( closure, result, index) ;
		}
#endif
		return ;
	}

	// 内容入口の単一INF契約違反を隠さない。
	if( closure.content.packages.size() != 1U) {
		result.parser = {MaintenanceInspectionState::FAILED,
						 static_cast<NativeError>( E_UNEXPECTED)} ;
// 同じ元FAILEDを研究観測へ残す。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
		// 通常射影を完了していないclosureは未観測として扱う。
		if( collector != nullptr) {
			collector->append( MaintenanceDriverClosure{}, result, index) ;
		}
#endif
		return ;
	}

	// 同一閉包の各軸をそのまま結び、root-onlyの再計算で全署名結果を上書きしない。
	result.parser			 = closure.structure.parser ;
	result.contentKind		 = closure.structure.contentKind ;
	result.referenceCoverage = closure.structure.referenceCoverage ;
	result.rootIntegrity	 = closure.structure.rootIntegrity ;
	result.dependency		 = closure.structure.dependency ;
	result.integrity		 = closure.integrity ;
	result.applicability	 = {MaintenanceInspectionState::NOT_CHECKED, 0} ;
	result.infSha256		 = closure.structure.infSha256 ;
	result.inspectedBytes	 = closure.content.expandedBytes ;
	result.dependenciesChecked =
		result.dependency.state != MaintenanceInfDependencyState::NOT_CHECKED ;
	result.hasExternalDependencies =
		result.dependenciesChecked && result.dependency.observedReferenceCount != 0U ;

	OfficialInfReferenceInventory references ;	// 従来route用の全section参照。新summaryを更新しない。
	const NativeError			  referencesError = inspectOfficialInfReferences(
		workspace, closure.content.entries, path, references) ;	// 未解決の参照を補完しない。
	OfficialInfPackage routePackage ;							// 従来導入構造の静的評価だけを受ける。
	const NativeError  routeError =
		inspectOfficialInfPackage( workspace, closure.content.entries, path, INF_POLICY,
								  routePackage) ;	// 従来policyを変更しない。
	const NativeError routeFinding =
		routeError != 0 ? routeError
						: (referencesError != 0 ? referencesError
												: (references.hasExternalDependencies
													   ? fromWin32( ERROR_NOT_SUPPORTED)
													   : 0)) ;	// 依存未解決も保留。
	result.installRoute = {routeFinding == 0 ? MaintenanceInspectionState::PASSED
											 : MaintenanceInspectionState::UNSUPPORTED,
						   routeFinding} ;
// 従来route射影後、同一extractのclosureが生存するscopeだけでconst借用する。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
	// 研究計測の容量・例外失敗でも元rowとHRESULTを保持する。
	if( collector != nullptr) {
		collector->append( closure, result, index) ;
	}
#endif
}

/**
 * @brief 保守検査の全体失敗で部分結果を破棄する。
 * @param[in,out] result 破棄する保守観測。
 * @param[in] error 0ではないHRESULT。
 * @return 同じ診断値。
 */
NativeError failMaintenance( MaintenanceDriverPackageInspection &result, const NativeError error)
{
	result		 = {} ;
	result.error = error ;
	return error ;
}

} // namespace

/**
 * @see src/platform/common_driver_package.h 宣言側の契約を正本とする。
 */
NativeError copyLocalDriverArchive( const std::wstring_view	  selectedPath,
								   const ScanSessionId		  scanSessionId,
								   OfficialDownloadWorkspace &workspace, DriverArchiveInput &input,
								   OfficialDriverArchiveFormat &format)
{
	input = {} ;
	// Network path、device path、ADS、埋込NUL、相対pathをlocal入力へ混入させない。
	if( scanSessionId == 0 || selectedPath.size() < 4U || selectedPath.size() > 32767U ||
	   selectedPath[1] != L':' || selectedPath[2] != L'\\' ||
	   !((selectedPath[0] >= L'A' && selectedPath[0] <= L'Z') ||
		 (selectedPath[0] >= L'a' && selectedPath[0] <= L'z')) ||
	   selectedPath.find( L':', 2U) != std::wstring_view::npos ||
	   selectedPath.find( L'\0') != std::wstring_view::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const std::wstring extension = extensionOf( selectedPath) ;	// 実行しない形式の選択。
		// 明示対応していない形式を起動や外部展開へfallbackしない。
		if( extension != L".zip" && extension != L".cab") {
			return fromWin32( ERROR_NOT_SUPPORTED) ;
		}

		NativeError error =
			// 保護領域作成。
			workspace.initialize( L"local-driver-input", scanSessionId) ;
		// 初期化失敗なら元fileを読み取らない。
		if( error != 0) {
			return error ;
		}

		DriverArchiveInput copied ;	// 全copyとhash成功後だけ公開する内容identity。
		error = copyArchiveBytes( std::wstring( selectedPath), workspace, copied.byteCount) ;
		// Copy失敗をhash処理で上書きしない。
		if( error != 0) {
			return error ;
		}

		copied.scanSessionId  = scanSessionId ;
		copied.inspectionPath = workspace.path( COPY_NAME) ;
		error				  = computeFileSha256( copied.inspectionPath, copied.sha256) ;
		// Hashが固定できない入力を後段へ渡さない。
		if( error != 0) {
			return error ;
		}

		format = extension == L".zip" ? OfficialDriverArchiveFormat::ZIP
									  : OfficialDriverArchiveFormat::CABINET ;
		input  = std::move( copied) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

/**
 * @see src/platform/common_driver_package.h 宣言側の契約を正本とする。
 */
NativeError inspectSelectedCommonDriverPackage( const DriverArchiveInput			&input,
											   const OfficialDriverArchiveFormat format,
											   const std::wstring_view			 selectedInf,
											   CommonDriverPackageInspection	&inspection,
											   const std::function<bool()>		&cancellation)
{
	inspection = {} ;
	// 監視側の有限な一INFだけを受理し、形式や原byte上限を緩めません。
	if( input.scanSessionId == 0U || input.byteCount == 0U || input.byteCount > INPUT_BYTES ||
	   selectedInf.empty() || selectedInf.size() > 260U ||
	   (format != OfficialDriverArchiveFormat::ZIP &&
		format != OfficialDriverArchiveFormat::CABINET)) {
		return failInspection( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	}

	try {
		// 開始前の取消しを部分内容の合格へ変えません。
		if( cancellation && cancellation()) {
			return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
		}

		OfficialDriverArchiveInventory inventory ;	// 全外側entryと元archivehashです。
		auto error = inspectDriverArchiveInventory( {&input, format, {}}, POLICY,
												   inventory) ;	// 元inventory/hashの実結果です。
		// 一INF選択を理由に全archive破損やentry上限を無視しません。
		if( error != 0 || inventory.entries.size() > 4096U) {
			return failInspection( inspection,
								  error != 0 ? error : fromWin32( ERROR_BUFFER_OVERFLOW)) ;
		}

		const auto selected = std::ranges::find_if( inventory.entries, [&]( const auto &entry) {
			return entry.relativePath == selectedInf ;
		}) ; // 元inventoryの完全一致だけです。
		// 任意pathや別形式を選択INFへ補完しません。
		if( selected == inventory.entries.end() || extensionOf( selected->relativePath) != L".inf") {
			return failInspection( inspection, fromWin32( ERROR_NOT_FOUND)) ;
		}

		CommonInfInspection inspected ;	// 旧全INF入口と同じ個別型です。
		inspectOneInf( input, format, {}, selected->relativePath, 0U,
					  inspected) ;	// 同通常policy/全CAT/memberです。
		// 確保失敗や保持量超過を通常の内容拒否へ丸めません。
		if( inspected.error == static_cast<NativeError>( E_OUTOFMEMORY) ||
		   inspected.closure.expandedBytes > EXPANDED_BYTES) {
			return failInspection( inspection, inspected.error != 0
												  ? inspected.error
												  : fromWin32( ERROR_FILE_TOO_LARGE)) ;
		}

		// 同期検査後の取消しでは所有閉包を破棄します。
		if( cancellation && cancellation()) {
			return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
		}

		error = verifyOfficialFileMetadata(
			input.inspectionPath, {input.byteCount, input.sha256}) ;	// 元archiveを再確認します。
		// 途中byte差替えから一INFの正常結果を発行しません。
		if( error != 0) {
			return failInspection( inspection, error) ;
		}

		inspection.scanSessionId	  = input.scanSessionId ;
		inspection.archiveSha256	  = input.sha256 ;
		inspection.archiveBytes		  = input.byteCount ;
		inspection.inventoryFileCount = inventory.entries.size() ;
		inspection.retainedBytes	  = inspected.closure.expandedBytes ;
		inspection.infs.push_back( std::move( inspected)) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return failInspection( inspection, static_cast<NativeError>( E_OUTOFMEMORY)) ;
	}
}

/** @see common_driver_package.h */
NativeError inspectCommonDriverPackage( const DriverArchiveInput			&input,
									   const OfficialDriverArchiveFormat format,
									   CommonDriverPackageInspection	&inspection,
									   const std::function<bool()>		&cancellation)
{
	inspection = {} ;
	// 共通入口の固定上限と形式を個別parserへ渡す前に確認する。
	if( input.scanSessionId == 0 || input.byteCount == 0 || input.byteCount > INPUT_BYTES ||
	   (format != OfficialDriverArchiveFormat::ZIP &&
		format != OfficialDriverArchiveFormat::CABINET)) {
		return failInspection( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	}

	try {
		inspection.scanSessionId = input.scanSessionId ;
		inspection.archiveSha256 = input.sha256 ;
		inspection.archiveBytes	 = input.byteCount ;
		std::vector<std::wstring> jobs( 1U) ;	// 最初は直下、その後は最大16の一段nested。
		// 外側を先に確認し、一段内側の各archiveまでを有限回検査する。
		for( std::size_t jobIndex = 0; jobIndex < jobs.size(); ++jobIndex) {
			// 取消しでは既に合格した閉包も破棄する。
			if( cancellation && cancellation()) {
				return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
			}

			const std::wstring nested = jobs[jobIndex] ;	// Job追加によるvector再配置と独立したpath。
			OfficialDriverArchiveInventory inventory ;		// 今回の有限inventory。
			const NativeError			   error = inspectDriverArchiveInventory(
				 {&input, format, nested}, POLICY, inventory) ;	// 全entryと元入力hashの検査。
			// Archive全体の破損を個別INF拒否へ縮小しない。
			if( error != 0) {
				return failInspection( inspection, error) ;
			}

			// 入れ子を含めたinventory総数も有限に保つ。
			if( inventory.entries.size() > 4096U - inspection.inventoryFileCount) {
				return failInspection( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
			}

			inspection.inventoryFileCount += inventory.entries.size() ;
			// Inventory順を維持し、未参照の別用途fileは閉包へ含めない。
			for( const OfficialZipEntry &entry : inventory.entries) {
				const std::wstring extension = extensionOf( entry.relativePath) ;	// 静的形式の選択。
				// 外側で確認したZIP／CABだけを一段nested処理へ登録する。
				if( jobIndex == 0 && (extension == L".zip" || extension == L".cab")) {
					// 未検査archiveを黙って飛ばさず、全体上限として拒否する。
					if( jobs.size() >= NESTED_COUNT + 1U) {
						return failInspection( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
					}

					jobs.push_back( entry.relativePath) ;
				}

				// INF以外のentryをdriver候補として解釈しない。
				if( extension != L".inf") {
					continue ;
				}

				// 一部のINFだけを検査して全体完了としない。
				if( inspection.infs.size() >= INF_COUNT) {
					return failInspection( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
				}

				// 各INF間でも取消しを確認する。
				if( cancellation && cancellation()) {
					return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
				}

				CommonInfInspection inspected ;	// 現在INFの個別結果。
				inspectOneInf( input, format, nested, entry.relativePath, inspection.infs.size(),
							  inspected) ;
				// 全体resource失敗を個別の内容不適合とみなさない。
				if( inspected.error == static_cast<NativeError>( E_OUTOFMEMORY)) {
					return failInspection( inspection, inspected.error) ;
				}

				// 成功閉包の累積保持量を上限以内に保つ。
				if( inspected.closure.expandedBytes > EXPANDED_BYTES - inspection.retainedBytes) {
					return failInspection( inspection, fromWin32( ERROR_FILE_TOO_LARGE)) ;
				}

				inspection.retainedBytes += inspected.closure.expandedBytes ;
				inspection.infs.push_back( std::move( inspected)) ;
			}
		}

		// 最後の同期API実行中に届いた取消しを反映する。
		if( cancellation && cancellation()) {
			return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
		}

		const NativeError finalIdentityError = verifyOfficialFileMetadata(
			input.inspectionPath, {input.byteCount, input.sha256}) ;	// 公開直前の外側入力再照合。
		// 最後の署名検証中に入力が変わった場合も部分合格を破棄する。
		if( finalIdentityError != 0) {
			return failInspection( inspection, finalIdentityError) ;
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		return failInspection( inspection, static_cast<NativeError>( E_OUTOFMEMORY)) ;
	} catch( const std::length_error &) {
		return failInspection( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	} catch( ...) {
		// 外部取消しcallback等の例外をworker境界から漏らさない。
		return failInspection( inspection, static_cast<NativeError>( E_UNEXPECTED)) ;
	}
}

namespace {
/** @brief 通常と研究入口が共有する元有限loopを実行する。
 * @param[in] input 元固定archive。
 * @param[in] format 既存非実行形式。
 * @param[out] inspection 元判定と通常row。
 * @param[in] cancellation 元取消し契約。
 * @param[in,out] collector 研究compileだけのstack借用。Nullなら観測しない。
 * @return 元有限判定のHRESULT。計測失敗は元判定へ反映しない。
 */
NativeError inspectMaintenanceDriverPackageImpl( const DriverArchiveInput		   &input,
												const OfficialDriverArchiveFormat	format,
												MaintenanceDriverPackageInspection &inspection,
												const std::function<bool()>		   &cancellation
// 通常compileへobserver引数・callback・storeを導入しない。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
												,
												ReachedReferenceCollector *collector
#endif
)
{
	inspection = {} ;
	// 個別parserの前に従来と同じ全体予算と非実行形式を要求する。
	if( input.scanSessionId == 0 || input.byteCount == 0 || input.byteCount > INPUT_BYTES ||
	   (format != OfficialDriverArchiveFormat::ZIP &&
		format != OfficialDriverArchiveFormat::CABINET)) {
		return failMaintenance( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	}

	try {
		inspection.scanSessionId = input.scanSessionId ;
		inspection.archiveSha256 = input.sha256 ;
		inspection.archiveBytes	 = input.byteCount ;
		std::vector<std::wstring> jobs( 1U) ;	// 直下と最大16件の一段nested。
		// 全inventoryを有限列挙し、未検査部分を成功として隠さない。
		for( std::size_t index = 0; index < jobs.size(); ++index) {
			// 取消し時は部分合格も破棄する。
			if( cancellation && cancellation()) {
				return failMaintenance( inspection, fromWin32( ERROR_CANCELLED)) ;
			}

			const std::wstring			   nested = jobs[index] ;	// Vector追加と独立した借用元。
			OfficialDriverArchiveInventory inventory ;				// 今回の全通常file。
			NativeError					   error =
				inspectDriverArchiveInventory( {&input, format, nested}, CONTENT_POLICY,
											  inventory) ;	// 元hash・path・展開量を検証する。
			// 全体破損や総file上限を個別driverの不適合にしない。
			if( error != 0 || inventory.entries.size() > 4096U - inspection.inventoryFileCount) {
				return failMaintenance( inspection,
									   error != 0 ? error : fromWin32( ERROR_BUFFER_OVERFLOW)) ;
			}

			inspection.inventoryFileCount += inventory.entries.size() ;
			// 一段nestedと全INFをarchive順で検査する。
			for( const OfficialZipEntry &entry : inventory.entries) {
				const std::wstring extension =
					// 非実行の形式選択。
					extensionOf( entry.relativePath) ;
				// 外側で確認した非実行archiveだけを一段処理へ登録する。
				if( index == 0 && (extension == L".zip" || extension == L".cab")) {
					// 上限を超えた場合に残りを黙って無視しない。
					if( jobs.size() >= NESTED_COUNT + 1U) {
						return failMaintenance( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
					}

					jobs.push_back( entry.relativePath) ;
				}

				// 実行形式やその他fileをINFとして解釈しない。
				if( extension != L".inf") {
					continue ;
				}

				// 全INF上限では部分結果を破棄する。
				if( inspection.infs.size() >= INF_COUNT) {
					return failMaintenance( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
				}

				// 各署名APIの間でも取消しを反映する。
				if( cancellation && cancellation()) {
					return failMaintenance( inspection, fromWin32( ERROR_CANCELLED)) ;
				}

				MaintenanceInfInspection result ;	// 個別失敗も保持する四軸観測。
				inspectMaintenanceInf( input, format, nested, entry.relativePath,
									  inspection.infs.size(), result
// 研究compileだけで同scopeの具体的collectorを明示的に渡す。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
									  ,
									  collector
#endif
				) ;
				// Resource失敗や全閉包の累積展開上限を内容不正に縮小しない。
				if( result.parser.error == static_cast<NativeError>( E_OUTOFMEMORY) ||
				   result.inspectedBytes > EXPANDED_BYTES - inspection.inspectedBytes) {
					return failMaintenance( inspection, result.parser.error != 0
														   ? result.parser.error
														   : fromWin32( ERROR_FILE_TOO_LARGE)) ;
				}

				inspection.inspectedBytes += result.inspectedBytes ;
				inspection.infs.push_back( std::move( result)) ;
			}
		}

		// 最後のAPI呼出し中の取消しも部分合格を残さない。
		if( cancellation && cancellation()) {
			return failMaintenance( inspection, fromWin32( ERROR_CANCELLED)) ;
		}

		const NativeError identityError = verifyOfficialFileMetadata(
			input.inspectionPath, {input.byteCount, input.sha256}) ;	// 公開直前の外側実byte照合。
		// 元archive変化を旧内容合格で隠さない。
		if( identityError != 0) {
			return failMaintenance( inspection, identityError) ;
		}

		inspection.parser = {inspection.infs.empty() ? MaintenanceInspectionState::UNSUPPORTED
													 : MaintenanceInspectionState::PASSED,
							 inspection.infs.empty() ? fromWin32( ERROR_NOT_SUPPORTED) : 0} ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return failMaintenance( inspection, static_cast<NativeError>( E_OUTOFMEMORY)) ;
	} catch( const std::length_error &) {
		return failMaintenance( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	} catch( ...) {
		// Callback等の例外をworker境界へ漏らさず、診断値を残す。
		return failMaintenance( inspection, static_cast<NativeError>( E_UNEXPECTED)) ;
	}
}
} // namespace

/** @see src/platform/common_driver_package.h 宣言側の契約を正本とする。 */
NativeError inspectMaintenanceDriverPackage( const DriverArchiveInput		   &input,
											const OfficialDriverArchiveFormat	format,
											MaintenanceDriverPackageInspection &inspection,
											const std::function<bool()>		   &cancellation)
{
	return inspectMaintenanceDriverPackageImpl( input, format, inspection, cancellation
// 研究target内の従来呼出しでも観測の有無を明示し、通常引数は保持する。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
											   ,
											   nullptr
#endif
	) ;
}

// 通常platformの公開API・DTOを変更せず、研究EXE内だけの入口を定義する。
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
/** @see tests/live/maintenance_reached_reference_observation.h 宣言側の契約を正本とする。 */
NativeError inspectReachedMaintenanceDriverPackage( const DriverArchiveInput			  &input,
												   const OfficialDriverArchiveFormat   format,
												   MaintenanceDriverPackageInspection &inspection,
												   ReachedReferenceCollector		  &collector,
												   const std::function<bool()>		  &cancellation)
{
	const NativeError error = inspectMaintenanceDriverPackageImpl(
		input, format, inspection, cancellation, &collector) ;	// 元loopを一回だけ実行する。
	collector.finish( inspection) ;
	return error ;
}
#endif

/** @see src/platform/common_driver_package.h 宣言側の契約を正本とする。 */
NativeError reverifyCommonDriverInf( const CommonInfInspection &inspected)
{
	// 合格閉包を所有していない値を再検証へ渡さない。
	if( inspected.scanSessionId == 0 || inspected.state != CommonInfInspectionState::VERIFIED ||
	   inspected.error != 0 || !inspected.workspace || inspected.closure.packages.size() != 1U ||
	   inspected.closure.entries.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 取得時の全fileをsizeとhashへ照合し、差替えを最初に検出する。
	for( const OfficialZipEntry &entry : inspected.closure.entries) {
		const NativeError error = verifyOfficialFileMetadata(
			inspected.workspace->path( entry.relativePath),
			{entry.uncompressedSize, entry.sha256}) ;	// 個別fileの不変性検査。
		// 一つでも変更があれば署名や導入へ進めない。
		if( error != 0) {
			return error ;
		}
	}

	// 同同期呼出しだけ元所有者を借り、baseと全必要役割を同じpolicyで再解析します。
	const auto verifyPackage = [&]( const OfficialInfPackage &expected) {
		OfficialInfPackage actual ;	// 現在byteから再解析した元metadataです。
		// 元役割packageの再解析診断です。
		const NativeError  error =
			inspectOfficialInfPackage( *inspected.workspace, inspected.closure.entries,
									  expected.infRelativePath, INF_POLICY, actual) ;
		// 再解析失敗を同じ内容へ補正しません。
		if( error != 0) {
			return error ;
		}

		// 版/ID/fileだけでなく元必要関係と役割identityも不変であることを要求します。
		if( actual.infRelativePath != expected.infRelativePath ||
		   actual.catalogRelativePath != expected.catalogRelativePath ||
		   actual.className != expected.className || actual.providerName != expected.providerName ||
		   actual.driverDate != expected.driverDate ||
		   actual.driverVersion != expected.driverVersion ||
		   actual.hardwareIds != expected.hardwareIds ||
		   actual.sourceFiles != expected.sourceFiles ||
		   actual.hasExternalDependencies != expected.hasExternalDependencies ||
		   actual.role != expected.role || actual.classGuid != expected.classGuid ||
		   actual.extensionId != expected.extensionId ||
		   actual.selectedInstallSection != expected.selectedInstallSection ||
		   actual.selectedBasicSection != expected.selectedBasicSection ||
		   actual.selectedNativeRank != expected.selectedNativeRank ||
		   actual.requiredInfPaths != expected.requiredInfPaths ||
		   actual.activeRequiredInfPaths != expected.activeRequiredInfPaths ||
		   actual.requiredComponents != expected.requiredComponents ||
		   actual.unresolvedIncludeNeeds != expected.unresolvedIncludeNeeds) {
			return fromWin32( ERROR_RETRY) ;
		}

		return verifyWindowsInfPackageIntegrity( *inspected.workspace, actual) ;
	} ;
	const auto baseError =
		// 元基本INFの再確認です。
		verifyPackage( inspected.closure.packages.front()) ;
	// 基本INF失敗後に追加役割だけを成功へ返しません。
	if( baseError != 0) {
		return baseError ;
	}

	// 追加役割の全CATと全memberも毎回再確認します。
	for( const auto &package : inspected.requiredInfPackages) {
		const auto error = verifyPackage( package) ;	// 原CATの独立診断です。
		// 後続成功で追加役割の失敗を消しません。
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}

/** @see src/platform/common_driver_package.h 宣言側の契約を正本とします。 */
std::size_t RequiredDriverComponentPlan::count( const DriverPlanRole role) const noexcept
{
	return static_cast<std::size_t>( std::ranges::count_if(
		members_, [role]( const auto &member) { return member.role == role ; })) ;
}

/** @see src/platform/common_driver_package.h 宣言側の契約を正本とします。 */
NativeError makeRequiredDriverComponentPlan(
	const CommonInfInspection &inspected, std::span<const OfficialInfPackage> selectedPackages,
	std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	RequiredInfBindingDiagnostic					   *diagnostic)
{
	plan.reset() ;
	const auto contentError =
		// 元byte/CATを構築直前に確認します。
		reverifyCommonDriverInf( inspected) ;
	// 公開DTOや未検査の構造を必要関係の成功にしません。
	if( contentError != 0 || inspected.requiredInfPackages.size() > 7U ||
	   selectedPackages.size() != inspected.requiredInfPackages.size() + 1U ||
	   selectedPackages.front().selectedInstallSection.empty()) {
		return contentError != 0 ? contentError : fromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto &base = inspected.closure.packages.front() ;	// 既存一基本INFの元metadataです。
	// 独立したExtension/SoftwareComponentを基本候補へ変換しません。
	if( base.role != DriverPlanRole::BASE_DRIVER) {
		return fromWin32( ERROR_NOT_SUPPORTED) ;
	}

	try {
		auto made = std::make_shared<
			RequiredDriverComponentPlan>() ;	// private memberは本factoryだけが設定します。
		made->session_	= inspected.scanSessionId ;
		made->basePath_ = base.infRelativePath ;
		made->selectedPackages_.assign( selectedPackages.begin(), selectedPackages.end()) ;
		std::vector<const OfficialInfPackage *> packages ;	// 同同期選択copyだけを借用します。
		// 全importの元順を維持し、必要機能と元内容identityを別に照合します。
		for( std::size_t index = 0U; index < selectedPackages.size(); ++index) {
			const auto &package = selectedPackages[index] ;	// 選択関係を補足した元copyです。
			const auto &original =
				index ? inspected.requiredInfPackages[index - 1U] : base ;	// 元署名所有者です。
			// 選択解析を別INF/別role/別原参照の内容へ転用しません。
			if( package.infRelativePath != original.infRelativePath ||
			   package.catalogRelativePath != original.catalogRelativePath ||
			   package.className != original.className || package.classGuid != original.classGuid ||
			   package.role != original.role || package.extensionId != original.extensionId ||
			   package.hardwareIds != original.hardwareIds ||
			   package.sourceFiles != original.sourceFiles ||
			   package.driverVersion != original.driverVersion ||
			   package.driverDate != original.driverDate ||
			   package.providerName != original.providerName ||
			   package.requiredInfPaths != original.requiredInfPaths ||
			   package.hasExternalDependencies != original.hasExternalDependencies ||
			   package.unresolvedIncludeNeeds != original.unresolvedIncludeNeeds) {
				return fromWin32( ERROR_RETRY) ;
			}

			packages.push_back( &package) ;
		}

		std::vector<bool> functional(
			// 選択DDInstallの到達だけを必要機能にします。
			packages.size()) ;
		std::vector<std::size_t> queue{0U} ;	// 最大八package、一度だけ追加する有限走査です。
		functional[0] = true ;
		// 選択baseからactive CopyINFを辿り、全importとは独立した実行集合を作ります。
		for( std::size_t position = 0U; position < queue.size(); ++position) {
			const auto index = queue[position] ;	// 同選択copyの元ordinalです。
			// 当該deviceの実選択節に明示された参照だけを必要機能へ結合します。
			for( const auto &path : packages[index]->activeRequiredInfPaths) {
				const auto found = std::ranges::find_if( packages, [&]( const auto value) {
					return CompareStringOrdinal( value->infRelativePath.c_str(), -1, path.c_str(),
												-1, TRUE) == CSTR_EQUAL ;
				}) ; // 同保護閉包だけを借用します。
				// 不在とactiveな独立基本INFを自動導入計画へ追加しません。
				if( found == packages.end() || (*found)->role == DriverPlanRole::BASE_DRIVER) {
					return fromWin32( ERROR_NOT_SUPPORTED) ;
				}

				const auto child =
					// 有限元ordinalです。
					static_cast<std::size_t>( found - packages.begin()) ;
				// 共有参照を重複実行せず、後段の全import graphで循環を確認します。
				if( !functional[child]) {
					functional[child] = true ;
					queue.push_back( child) ;
				}
			}
		}

		std::vector<std::vector<std::size_t>> edges(
			// 原明示CopyINFの有限graphです。
			packages.size()) ;
		std::vector<bool> componentsUsed( packages.size()) ;	// 必要子の一意な関係だけを記録します。
		std::vector<std::wstring> extensions ;					// 同ExtensionIdの競合を検出するworker内集合です。
		// 全元宣言を一意な同保護閉包へ結合します。
		for( std::size_t index = 0U; index < packages.size(); ++index) {
			const auto &package = *packages[index] ;	// 一つの実検査済み元packageです。
			// SYSTEM/PACKAGEの未確認Include/Needsと未知の明示必要関係を消しません。
			if( (functional[index] && index != 0U && package.role == DriverPlanRole::BASE_DRIVER) ||
			   (functional[index] && package.role == DriverPlanRole::DRIVER_COMPONENT &&
				(!package.requiredComponents.empty() || !package.activeRequiredInfPaths.empty()))) {
				return fromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// 全節の観測flagを消さず、選択機能だけに独立した依存と効果検査を要求します。
			if( functional[index] && package.unresolvedIncludeNeeds) {
				InfDependencyNativeResult dependency ;	// 同元byteの非実行graphです。
				const auto				  error = CommonInfNativeAccess::inspect(
					   inspected, package, dependency, diagnostic) ;	// 独立依存検査の元診断です。
				// 未観測・未充足・曖昧・cycle・署名拒否を成功へ補正しません。
				if( error != 0) {
					return error ;
				}

				const auto &graph = dependency.dependency ;	// 同実選択seedからの元graphです。
				// 元graphの完全解決とroot証拠を失った件数を充足根拠へ使用しません。
				if( !graph.plan.referencesResolved || !graph.plan.rootEvidenceVerified ||
				   graph.edges.size() > 4096U) {
					return fromWin32( ERROR_INVALID_DATA) ;
				}

				std::size_t verifiedNeeds{} ;	// 一graph最大4096の実Needsだけです。
				// 実選択節から到達し署名・由来・効果を確認したNeedsを数えます。
				for( const auto &edge : graph.edges) {
					// Includeだけの宣言を実行前提へ投影しません。
					if( edge.directive != InfDependencyDirective::NEEDS) {
						continue ;
					}

					// 未解決の参照を件数だけで充足へ変えません。
					if( (edge.state != InfDependencyState::RESOLVED_PACKAGE &&
						edge.state != InfDependencyState::RESOLVED_SYSTEM) ||
					   edge.reason != InfDependencyReason::NONE || edge.targetIdentity == 0U) {
						return fromWin32( ERROR_INVALID_DATA) ;
					}

					++verifiedNeeds ;
				}

				// 八つの元packageと各4096辺の既存上限を累積前に保ちます。
				if( made->verifiedNeedsEdgeCount_ > 32768U ||
				   verifiedNeeds > 32768U - made->verifiedNeedsEdgeCount_) {
					return fromWin32( ERROR_FILE_TOO_LARGE) ;
				}

				made->verifiedNeedsEdgeCount_ += verifiedNeeds ;
			}

			// 同ExtensionIdの複数memberを独自の全導入へ変換しません。
			if( package.role == DriverPlanRole::EXTENSION) {
				// 大小文字の異なる同GUIDも競合として保留します。
				if( std::ranges::any_of( extensions, [&]( const auto &value) {
					   return CompareStringOrdinal( value.c_str(), -1, package.extensionId.c_str(),
												   -1, TRUE) == CSTR_EQUAL ;
				   })) {
					return fromWin32( ERROR_DUP_NAME) ;
				}

				extensions.push_back( package.extensionId) ;
			}

			// 原CopyINFの各辺を完全path一致で解決し、名称からroleを作りません。
			for( const auto &path : package.requiredInfPaths) {
				const auto found = std::ranges::find_if( packages, [&]( const auto value) {
					return CompareStringOrdinal( value->infRelativePath.c_str(), -1, path.c_str(),
												-1, TRUE) == CSTR_EQUAL ;
				}) ; // 同実閉包だけの参照です。
				// 未解決参照を一基本INFの成功へ換算しません。
				if( found == packages.end()) {
					return fromWin32( ERROR_FILE_NOT_FOUND) ;
				}

				edges[index].push_back( static_cast<std::size_t>( found - packages.begin())) ;
			}

			// 必要driver componentは元AddComponent/ComponentIDsに一意に結合します。
			for( const auto &reference : package.requiredComponents) {
				std::optional<std::size_t> target ;	// 複数候補では成功値を保持しません。
				// CopyINFで到達した全SWC metadataを元IDで照合します。
				for( std::size_t child = 1U; child < packages.size(); ++child) {
					const auto &value =
						*packages[child] ;	// 同protected byteから得た子metadataです。
					const bool matches =
						functional[index] && functional[child] &&
						value.role == DriverPlanRole::DRIVER_COMPONENT &&
						std::ranges::any_of( value.hardwareIds, [&]( const auto &id) {
							return std::ranges::any_of(
								reference.hardwareIds, [&]( const auto &expected) {
									return CompareStringOrdinal( id.c_str(), -1, expected.c_str(),
																-1, TRUE) == CSTR_EQUAL ;
								}) ;
						}) ; // 名前ではなく元SWC IDの一致です。
					// 一意な元childだけを選びます。
					if( matches) {
						// 曖昧なpackageや一子の複数必要関係を先頭へ絞りません。
						if( target || componentsUsed[child]) {
							return fromWin32( ERROR_DUP_NAME) ;
						}

						target = child ;
					}
				}

				// 元必要IDの不足を任意utilityの欠落と同じ扱いにしません。
				if( !target) {
					return fromWin32( ERROR_NOT_FOUND) ;
				}

				componentsUsed[*target] = true ;
				made->members_.push_back(
					{*target - 1U, DriverPlanRole::DRIVER_COMPONENT, index, reference.hardwareIds}) ;
			}
		}

		std::vector<unsigned char>		 visited( packages.size()) ;	// 未訪問0、訪問中1、完了2です。
		// 同同期factoryの有限graphだけを借用し、最深でも八packageで循環を拒否します。
		std::function<bool( std::size_t)> visit = [&]( const std::size_t index) {
			// 訪問中への戻りは明示CopyINF循環です。
			if( visited[index] == 1U) {
				return false ;
			}

			// 共有参照の完了済み枝は再走査しません。
			if( visited[index] == 2U) {
				return true ;
			}

			visited[index] = 1U ;
			// 全明示参照を確認し、一つの循環も残しません。
			for( const auto child : edges[index]) {
				// 循環が見つかった場合は全計画を失敗にします。
				if( !visit( child)) {
					return false ;
				}
			}

			visited[index] = 2U ;
			return true ;
		} ;
		// 元baseから全必要役割へ到達する有限閉包だけを認めます。
		if( !visit( 0U) ||
		   std::ranges::any_of( visited, []( const auto value) { return value != 2U ; })) {
			return fromWin32( ERROR_CIRCULAR_DEPENDENCY) ;
		}

		// 元CopyINFだけで到達する拡張と、元AddComponentで結ぶdriver子を区別します。
		for( std::size_t index = 1U; index < packages.size(); ++index) {
			const auto role = packages[index]->role ;	// 元Classの役割です。
			// 必要性のない同梱SWCを計画へ追加しません。
			if( functional[index] && role == DriverPlanRole::DRIVER_COMPONENT &&
			   !componentsUsed[index]) {
				return fromWin32( ERROR_NOT_FOUND) ;
			}

			// 拡張は同parentの適用性を別に確認するmemberです。
			if( functional[index] && role == DriverPlanRole::EXTENSION) {
				made->members_.push_back( {index - 1U, role, 0U, {}}) ;
			}
		}

		plan = std::move( made) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

/**
 * @see src/platform/common_driver_package.h 宣言側の契約を正本とする。
 */
bool makeCommonInfCandidateAssessment(
	const ScanSessionId scanSessionId, const UpdateCandidate &candidate,
	const CommonInfInspection &inspected, const std::uint64_t evidenceId,
	const CandidateAssessmentFinding &origin, const NativeError applicabilityError,
	const std::optional<std::uint32_t> candidateRank, CandidateAssessment &assessment)
{
	assessment = {} ;
	// 未検査、部分検査、失敗時のrank、誤った由来を合格証拠へ変換しない。
	if( inspected.scanSessionId != scanSessionId ||
	   inspected.state != CommonInfInspectionState::VERIFIED || inspected.error != 0 ||
	   !inspected.workspace || inspected.closure.packages.size() != 1U || evidenceId == 0 ||
	   (applicabilityError != 0 && candidateRank) ||
	   !isCandidateAssessmentFindingValid( CandidateAssessmentAxis::ORIGIN, origin)) {
		return false ;
	}

	const OfficialInfPackage &package =
		// 結合する内容metadata。
		inspected.closure.packages.front() ;
	// 別INFの検証結果を現在行や異なる版の候補へ使い回さない。
	if( candidate.current || candidate.packageIdentity.empty() ||
	   candidate.version != package.driverVersion || candidate.provider != package.providerName) {
		return false ;
	}

	CandidateAssessment result ;	// 結合検証後だけ公開する八軸。
	result.scanSessionId	 = scanSessionId ;
	result.candidateIdentity = candidate.identity ;
	result.deviceIdentity	 = candidate.deviceIdentity ;
	result.packageIdentity	 = candidate.packageIdentity ;
	result.origin			 = origin ;
	result.componentRole	 = CandidateComponentRole::BASE_DRIVER ;
	result.acquisition	= {CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
						   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
	result.signature	= {CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
						   CandidateEvidenceKind::WINDOWS_API, evidenceId} ;
	result.driverOnly	= result.acquisition ;
	result.requirements = {CandidateAssessmentState::NOT_APPLICABLE,
						   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
						   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
	// 明示依存の解決前でも署名・基礎適合を提示するが、構成と必須条件を合格にしない。
	if( package.hasExternalDependencies) {
		result.requirements = {CandidateAssessmentState::UNSUPPORTED,
							   CandidateAssessmentReason::FORMAT_UNSUPPORTED,
							   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
		result.driverOnly	= result.requirements ;
	}

	result.windowsSelection = {CandidateAssessmentState::NOT_CHECKED,
							   CandidateAssessmentReason::RANK_UNVERIFIED,
							   CandidateEvidenceKind::WINDOWS_API, evidenceId} ;
	result.installMethod	= CandidateInstallMethod::STANDARD_INF ;
	result.method			= {CandidateAssessmentState::UNSUPPORTED,
							   CandidateAssessmentReason::EXECUTOR_UNAVAILABLE,
							   CandidateEvidenceKind::IMPLEMENTATION_POLICY, evidenceId} ;
	// API失敗は不適合と分け、元のHRESULTを保持する。
	if( applicabilityError != 0) {
		result.applicability = {CandidateAssessmentState::FAILED,
								CandidateAssessmentReason::API_FAILURE,
								CandidateEvidenceKind::WINDOWS_API, evidenceId,
								DeviceDiagnostic{DeviceDiagnosticDomain::HRESULT_VALUE,
												 static_cast<std::uint32_t>( applicabilityError)}} ;
	} else {
		result.applicability =
			candidateRank
				? CandidateAssessmentFinding{CandidateAssessmentState::PASSED,
											 CandidateAssessmentReason::VALIDATED,
											 CandidateEvidenceKind::WINDOWS_API, evidenceId}
				: CandidateAssessmentFinding{CandidateAssessmentState::REJECTED,
											 CandidateAssessmentReason::PNP_MISMATCH,
											 CandidateEvidenceKind::WINDOWS_API, evidenceId} ;
	}

	// 由来を含む全八軸と候補identityの整合性を要求する。
	if( !isCandidateAssessmentBound( result, scanSessionId, candidate.identity,
								   candidate.deviceIdentity, candidate.packageIdentity)) {
		return false ;
	}

	assessment = std::move( result) ;
	return true ;
}

} // namespace drivercrate
