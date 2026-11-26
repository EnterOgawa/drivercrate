//------------------------------------------------------------------------------
/**
 * @file common_driver_package.cpp
 * @brief 由来と独立したdriver packageの保護取込みと個別検査
 * @version 01.49.01
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  内容署名と未解決依存の表示を分離
 * Ver.01.02.00 Shunji Ogawa  2026/10/05  非実行の保守内容検証と導入経路を独立評価
 * Ver.01.03.00 Shunji Ogawa  2026/10/05  保守内容検査だけで非圧縮EXE参照を検証
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  標準二構文識別子を通常検査・再検査へ接続
 * Ver.01.05.00 Shunji Ogawa  2026/10/07  通常19 Classを保持して内容専用21 Classへ分離
 * Ver.01.06.00 Shunji Ogawa  2026/10/07  部分保守閉包の旧全integrity誤昇格を抑止
 * Ver.01.07.00 Shunji Ogawa  2026/10/07  保守閉包の独立状態を射影し従来routeと分離
 * Ver.01.08.00 Shunji Ogawa  2026/10/08  研究compile限定で同scope最終参照をstack collectorへ借用
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  全CAT閉包から一基本INFの必要構成計画を構築
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  全import graphと選択機能graphの独立境界を追加
 * Ver.01.11.00 Shunji Ogawa  2026/10/13  選択節のInclude/Needsを元byteと独立効果の検査へ結合
 * Ver.01.12.00 Shunji Ogawa  2026/10/14  監視側の明示一INFへ通常policyの同じ実検査を接続
 * Ver.01.13.00 Shunji Ogawa  2026/10/15  同元内容の必要関係から数値拒否段階を伝播
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  実選択graphの充足Needsを追加INFと別に保持
 * Ver.01.15.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.16.00 Shunji Ogawa  2026/11/03  SystemとSecurityDevicesの標準INFを共通内容へ追加
 * Ver.01.17.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.18.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続
 * Ver.01.19.00 Shunji Ogawa  2026/11/06  元driver付属DATAとWindows標準導入scopeを分離
 * Ver.01.20.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.20.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.20.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.20.03 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.20.04 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.21.00 Shunji Ogawa  2026/11/15  非実行storage内容をcollector型へ限定し通常bindingから拒否
 * Ver.01.22.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.23.00 Shunji Ogawa  2026/11/16  MTD正式対を内容用途のみに追加
 * Ver.01.24.00 Shunji Ogawa  2026/11/17  正式TapeDriveを共通の通常内容Classへ追加
 * Ver.01.25.00 Shunji Ogawa  2026/11/18  CopyINF由来の限定registry-only内容と通常導入拒否を分離
 * Ver.01.26.00 Shunji Ogawa  2026/11/19  全CAT照合前から元DLLを固定し、収集成功前に元exportを検査
 * Ver.01.27.00 Shunji Ogawa  2026/11/19  表示用の独自クラスの再検証を導入用入口から分離
 * Ver.01.28.00 Shunji Ogawa  2026/11/20  原署名確認後にWindows標準INFへの収集依存を検査
 * Ver.01.29.00 Shunji Ogawa  2026/11/21  収集内容検査でHDCの元SYSと全選択の作用を照合
 * Ver.01.30.00 Shunji Ogawa  2026/11/21  元SYSを持つHDCの全導入節の共通名に追随
 * Ver.01.31.00 Shunji Ogawa  2026/11/21  自己媒体Portsの内容検査にWindows標準ページを接続
 * Ver.01.32.00 Shunji Ogawa  2026/11/22  一件の公式配布対象を元署名と全参照の収集検査へ接続
 * Ver.01.33.00 Shunji Ogawa  2026/11/22  署名確認済みの公式対象を導入作用の棚卸しへ接続
 * Ver.01.34.00 Shunji Ogawa  2026/11/22  公式Net対象の元SYSとWindowsイベントDLLを検証
 * Ver.01.35.00 Shunji Ogawa  2026/11/22  端末の仮想Wi-Fiバス置換を元基本の選択に限定
 * Ver.01.36.00 Shunji Ogawa  2026/11/22  公式Net収集の同梱Needsを署名済み閉包から検査
 * Ver.01.37.00 Shunji Ogawa  2026/11/22  同梱依存付き公式Netの元CAB全一覧を保持
 * Ver.01.38.00 Shunji Ogawa  2026/11/23  自動起動ストレージの現用機器読取りを接続
 * Ver.01.39.00 Shunji Ogawa  2026/11/23  WiXの保護済み単一ストレージINFを端末用に再検査
 * Ver.01.40.00 Shunji Ogawa  2026/11/23  署名済みEXEと内側ZIPを収集内容検査へ接続
 * Ver.01.41.00 Shunji Ogawa  2026/11/23  私有収集の固定元memberを共通CAT・作用検査へ接続
 * Ver.01.42.00 Shunji Ogawa  2026/11/23  指定主INFの元CopyINFを審査済み必須System補助へ照合
 * Ver.01.43.00 Shunji Ogawa  2026/11/24  公式USB Bluetoothの収集参照を同じ署名と全作用へ結合
 * Ver.01.44.00 Shunji Ogawa  2026/11/24  自前シリアル媒体の二選択を同梱依存へ結合
 * Ver.01.45.00 Shunji Ogawa  2026/11/24  審査済みシリアル配布の元ZIPから私有検査へ接続
 * Ver.01.46.00 Shunji Ogawa  2026/11/24  同梱WinUSBの検査結果を同じ公式選択の棚卸しに結合
 * Ver.01.47.00 Shunji Ogawa  2026/11/24  署名付きPEの必須補助INFを元の種類で照合
 * Ver.01.48.00 Shunji Ogawa  2026/11/24  共有Portsの元AMD64 SYSとWindows標準ページを収集で結合
 * Ver.01.49.00 Shunji Ogawa  2026/11/24  公式CABの独自クラスとKMDF元参照を収集の棚卸しへ結合
 * Ver.01.49.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note 入力と閉包をworker内だけで保持し、取得元証明や導入許可を発行しません
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
#include "platform/official_mapped_file.h"
#include "platform/official_sfx.h"
#include "platform/official_zip.h"
#include "platform/collector_property_page_export_internal.h"

// 研究EXE内だけに最終closureの同期借用を接続し、通常compileへ状態を残さない
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
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内容検査の有限policy
//------------------------------------------------------------------------------

constexpr std::uint64_t INPUT_BYTES =
	2ULL * 1024ULL * 1024ULL * 1024ULL ;	// 固定mappingする外側入力上限
constexpr std::uint64_t EXPANDED_BYTES =
	3ULL * 1024ULL * 1024ULL * 1024ULL ;							// 一意memberの共同実保持上限
constexpr std::size_t		INF_COUNT		 = 128U ;				// 全archive合計のINF数上限
constexpr std::size_t		NESTED_COUNT	 = 16U ;				// 一段nested archive数上限
constexpr DWORD				COPY_CHUNK_BYTES = 1024U * 1024U ;		// 同期copyのbyte上限
constexpr std::wstring_view COPY_NAME		 = L"input.archive" ;	// 保護copyの固定内部名
constexpr std::array		CLASSES{
	   std::wstring_view( L"Biometric"), std::wstring_view( L"Bluetooth"), std::wstring_view( L"Camera"),
	   std::wstring_view( L"Display"), std::wstring_view( L"HIDClass"), std::wstring_view( L"Image"),
	   std::wstring_view( L"Keyboard"), std::wstring_view( L"MEDIA"), std::wstring_view( L"Modem"),
	   std::wstring_view( L"Monitor"), std::wstring_view( L"Mouse"), std::wstring_view( L"Multifunction"),
	   std::wstring_view( L"Net"), std::wstring_view( L"Ports"), std::wstring_view( L"Printer"),
	   std::wstring_view( L"Sensor"), std::wstring_view( L"SmartCardReader"), std::wstring_view( L"USB"),
	   std::wstring_view( L"USBDevice"), std::wstring_view( L"System"),
	   // Class名だけでbootやfirmwareを推測せず、同じ原INF/CATを検査します
	   std::wstring_view( L"SecurityDevices"), std::wstring_view( L"TapeDrive")} ;
// 内容解析だけが扱う追加Class。通常policyと導入許可の集合へ流用しない
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
									 CLASSES[19],
									 CLASSES[20],
									 CLASSES[21],
									 std::wstring_view( L"MultiPortSerial")} ;
static_assert( CLASSES.size() == 22U && CONTENT_CLASSES.size() == 23U) ;
// 必要役割はClass同一の基本driver候補へ変換せず、関係検査の別役割へ渡します
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
									   CLASSES[19],
									   CLASSES[20],
									   CLASSES[21],
									   std::wstring_view( L"Extension"),
									   std::wstring_view( L"SoftwareComponent")} ;
constexpr std::array				  SIGNATURES{std::wstring_view( L"$Windows NT$"),
								 // 標準INF構文。CAT暗号署名とは独立
								 std::wstring_view( L"$Chicago$")} ;
constexpr OfficialInfInspectionPolicy INF_POLICY{
	.maximumHardwareIds					  = 4096U,
	.maximumSourceFiles					  = 8192U,
	.acceptedClasses					  = REQUIRED_CLASSES,
	.acceptedProviders					  = {},
	.acceptedSignatures					  = SIGNATURES,
	.acceptAnyProvider					  = true,
	.requireDriverBinary				  = false,
	.rejectUnreferencedPrograms			  = false,
	.rejectInstallActions				  = true,
	.rejectExternalDependencies			  = false,
	.allowReferencedExecutablesForContent = false,
	.allowRequiredDriverComponents		  = true,
} ; // 製品名、現在版、INF名を適合証拠にしない
// 導入構造用policyを変えず、通常archiveの非実行内容だけへ参照byte許可を加えます
constexpr auto ARCHIVE_INF_POLICY = [] {
	auto policy									   = INF_POLICY ;	// 元導入policyの独立copyです
	policy.allowReferencedExecutablesForContent	   = true ;
	policy.allowWindowsManagedDriverDataForContent = true ;
	return policy ;
}() ;
constexpr OfficialDriverClosurePolicy POLICY{
	.zipPolicy		 = {INPUT_BYTES, 512ULL * 1024ULL * 1024ULL, 6ULL * 1024ULL * 1024ULL * 1024ULL,
						4096U},
	.cabPolicy		 = {INPUT_BYTES, 512ULL * 1024ULL * 1024ULL, 6ULL * 1024ULL * 1024ULL * 1024ULL,
						4096U},
	.infPolicy		 = ARCHIVE_INF_POLICY,
	.maximumInfCount = 1U,
	.maximumClosureFiles	   = 8194U,
	.maximumClosureBytes	   = EXPANDED_BYTES,
	.maximumExpansionRatio	   = 200U,
	.maximumNestedArchiveDepth = 1U,
} ; // 各INFを独立した非実行閉包として扱う

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
} ; // 作用は実行せず、別の静的導入経路findingへ保持する
constexpr OfficialDriverClosurePolicy CONTENT_POLICY{
	.zipPolicy				   = POLICY.zipPolicy,
	.cabPolicy				   = POLICY.cabPolicy,
	.infPolicy				   = CONTENT_INF_POLICY,
	.maximumInfCount		   = POLICY.maximumInfCount,
	.maximumClosureFiles	   = POLICY.maximumClosureFiles,
	.maximumClosureBytes	   = POLICY.maximumClosureBytes,
	.maximumExpansionRatio	   = POLICY.maximumExpansionRatio,
	.maximumNestedArchiveDepth = POLICY.maximumNestedArchiveDepth,
} ; // 元入力・参照・展開量・nested境界は従来と同一

// collectorの追加rootは正式storageだけです。通常Class/保守Class集合へ混入させません
constexpr auto COLLECTOR_CLASSES = [] {
	std::array<std::wstring_view, REQUIRED_CLASSES.size() + 2U> classes{} ;	// 同root集合のcopyです
	std::ranges::copy( REQUIRED_CLASSES, classes.begin()) ;
	classes[REQUIRED_CLASSES.size()] = L"SCSIAdapter" ;
	classes.back()					 = L"MTD" ;
	return classes ;
}() ;
// 同じ元参照/作用/CAT/容量条件を保ち、内容用途と正式Classだけを追加します
constexpr auto COLLECTOR_CONTENT_POLICY = [] {
	auto policy						 = POLICY ;	// 通常導入構造policyとは独立のcopyです
	policy.infPolicy.acceptedClasses = COLLECTOR_CLASSES ;
	policy.infPolicy.purpose		 = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
	return policy ;
}() ;
// appだけが原archiveを独立検査します。用途は導入許可ではありません
constexpr auto DEVICE_STORAGE_POLICY = [] {
	// collector/通常とは区別した端末用内容policyです
	auto policy				 = COLLECTOR_CONTENT_POLICY ;
	policy.infPolicy.purpose = OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
	return policy ;
}() ;

/** @brief Copy中のfile handleを単独所有する */
class ArchiveFile final {
public:
	/**
	 * @brief 所有するhandleを設定する
	 * @param[in] handle CloseHandle対象またはINVALID_HANDLE_VALUE
	 */
	explicit ArchiveFile( const HANDLE handle) noexcept : handle_( handle)
	{
	}
	/**
	 * @brief 有効な所有handleだけを閉じる
	 */
	~ArchiveFile()
	{
		// 失敗したopenのsentinelをCloseHandleへ渡さない
		if( handle_ != INVALID_HANDLE_VALUE) {
			CloseHandle( handle_) ;
		}
	}
	/**
	 * @brief copy中の所有file handleの複製構築をコンパイル時に禁止します
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです
	 * @note 削除宣言だけで関数本体やresource操作はありません
	 */
	ArchiveFile( const ArchiveFile &other) = delete ;
	/**
	 * @brief copy中の所有file handleの複製代入をコンパイル時に禁止します
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです
	 * @note 削除宣言だけで関数本体やresource操作はありません
	 */
	ArchiveFile			&operator=( const ArchiveFile &other) = delete ;
	/**
	 * @brief 呼出し中だけ有効な非所有handleを返す
	 * @return 所有handleまたはsentinel
	 */
	[[nodiscard]] HANDLE get() const noexcept
	{
		return handle_ ;
	}

private:
	/// Scope終了で閉じる所有handle
	HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Win32診断値をHRESULTへ変換する
 * @param[in] error Windows APIまたは検査の診断値
 * @return 元のcodeを保持するHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError fromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最終path要素の拡張子をASCII小文字で得る
 * @param[in] path 呼出し中有効なpath
 * @return 拡張子または空
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring extensionOf( const std::wstring_view path)
{
	const std::size_t separator = path.find_last_of( L"/\\") ;	// 最終directory境界
	const std::size_t dot		= path.find_last_of( L'.') ;	// 拡張子の開始候補
	// Directory内のdotを拡張子として解釈しない
	if( dot == std::wstring_view::npos ||
	   (separator != std::wstring_view::npos && dot < separator)) {
		return {} ;
	}

	std::wstring extension( path.substr( dot)) ;	// 小文字化する最終拡張子
	std::ranges::transform( extension, extension.begin(), []( const wchar_t c) noexcept {
		return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c - L'A' + L'a') : c ;
	}) ;
	return extension ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのlocal通常fileを共有なしで有限copyする
 * @param[in] path 検証済み絶対local path
 * @param[in,out] workspace 初期化済みのcopy所有領域
 * @param[out] byteCount 成功時だけcopy byte数
 * @return 完全copy時0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError copyArchiveBytes( const std::wstring		 &path,
										   OfficialDownloadWorkspace &workspace,
										   std::uint64_t			 &byteCount)
{
	byteCount = 0 ;
	ArchiveFile input( CreateFileW( path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
								  FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
								  nullptr)) ;	// 共有なし入力
	// 開けないfileの内容を推測せず中止する
	if( input.get() == INVALID_HANDLE_VALUE) {
		return fromWin32( GetLastError()) ;
	}

	BY_HANDLE_FILE_INFORMATION attributes{} ;	// Handle自身の通常file属性
	// 属性取得に失敗した入力をcopyしない
	if( GetFileInformationByHandle( input.get(), &attributes) == FALSE) {
		return fromWin32( GetLastError()) ;
	}

	// Pipe、directory、reparse pointを通常archiveとして扱わない
	if( GetFileType( input.get()) != FILE_TYPE_DISK ||
	   (attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
		   0) {
		return fromWin32( ERROR_ACCESS_DENIED) ;
	}

	LARGE_INTEGER size{} ;	// Copyする実file byte数
	// Sizeを読めない入力を無制限streamとして扱わない
	if( GetFileSizeEx( input.get(), &size) == FALSE) {
		return fromWin32( GetLastError()) ;
	}

	// 空または有限上限を超えた入力を確保前に拒否する
	if( size.QuadPart <= 0 || static_cast<std::uint64_t>( size.QuadPart) > INPUT_BYTES) {
		return fromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	std::uint64_t freeBytes{} ;											// Workspace volumeの実空き容量
	NativeError	  error = workspace.queryAvailableBytes( freeBytes) ;	// 容量観測の診断値
	// 容量不足または観測失敗時はcopyを開始しない
	if( error != 0 || freeBytes < static_cast<std::uint64_t>( size.QuadPart)) {
		return error != 0 ? error : fromWin32( ERROR_DISK_FULL) ;
	}

	HANDLE outputHandle{INVALID_HANDLE_VALUE} ;	// 所有wrapperへ直ちに移す作成handle
	error = workspace.createFile( COPY_NAME, outputHandle) ;
	// 作成できなければ入力だけを閉じて終了する
	if( error != 0) {
		return error ;
	}

	ArchiveFile			   output( outputHandle) ;									// 全終了経路で閉じるcopy先
	std::vector<std::byte> buffer( COPY_CHUNK_BYTES) ;								// 固定1 MiBのcopy用heap領域
	std::uint64_t		   remaining = static_cast<std::uint64_t>( size.QuadPart) ;	// 残りbyte数
	// 固定sizeを上限に1 MiBずつcopyし、短い読取りと部分書込みを拒否する
	while( remaining != 0) {
		const DWORD requested = static_cast<DWORD>(
			std::min<std::uint64_t>( remaining, buffer.size())) ;	// 今回の有限要求量
		DWORD read{} ;												// 実際に読んだbyte数
		// API失敗時は直後の診断値を保持する
		if( ReadFile( input.get(), buffer.data(), requested, &read, nullptr) == FALSE) {
			return fromWin32( GetLastError()) ;
		}

		// 宣言sizeまで読めないfileを合格させない
		if( read != requested) {
			return fromWin32( ERROR_HANDLE_EOF) ;
		}

		DWORD written{} ;	// 実際に書いたbyte数
		// API失敗時は直後の診断値を保持する
		if( WriteFile( output.get(), buffer.data(), requested, &written, nullptr) == FALSE) {
			return fromWin32( GetLastError()) ;
		}

		// 部分書込みにstaleなGetLastErrorを割り当てない
		if( written != requested) {
			return fromWin32( ERROR_WRITE_FAULT) ;
		}

		remaining -= requested ;
	}

	byteCount = static_cast<std::uint64_t>( size.QuadPart) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全体失敗で部分閉包を破棄し、診断値だけを残す
 * @tparam Inspection 通常結果または導入非互換のcollector内容型です
 * @param[in,out] inspection 今回所有する結果
 * @param[in] error 0ではない失敗HRESULT
 * @return 指定された診断値
 */
//------------------------------------------------------------------------------
template <typename Inspection>
NativeError failInspection( Inspection &inspection, const NativeError error)
{
	inspection		 = {} ;
	inspection.error = error ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 個別INFを非実行閉包とWindows署名まで検査する
 * @tparam Inspection 指定用途と同じ通常結果またはcollector内容型です
 * @param[in] input 固定した内容入力
 * @param[in] format 外側形式
 * @param[in] nested 空または一段nested path
 * @param[in] path Inventoryが保持するINF相対path
 * @param[in] infIndex 検査内で一意な0起点INF連番。保護領域名へ用いる
 * @param[out] inspected 個別結果と成功閉包
 * @param[in] sharedWorkspace 同じflat操作だけで借用する共有出力owner。空は単独所有
 * @param[in,out] cache 同じ入力とworkspaceだけの内容cache。単独旧callerはnull
 * @param[in] policy 既に保持した別閉包を除いた有限な残量と元構造条件
 * @param[in] archiveEntries 収集の委譲検査が参照する元アーカイブ全一覧です。署名済み抽出部分集合とは独立です
 * @param[in] scopedModels 選択した一件の公式配布対象です。従来の検査はnullです
 * @param[in] collectorMembers 元readerの固定member範囲。従来のarchive形式ではnull
 */
//------------------------------------------------------------------------------
template <typename Inspection>
void inspectOneInf( const DriverArchiveInput &input, const OfficialDriverArchiveFormat format,
				   const std::wstring &nested, const std::wstring &path, const std::size_t infIndex,
				   Inspection								 &inspected,
				   std::shared_ptr<OfficialDownloadWorkspace> sharedWorkspace  = {},
				   DriverArchiveExtractionCache				 *cache			   = nullptr,
				   const OfficialDriverClosurePolicy		 &policy		   = POLICY,
				   std::span<const OfficialZipEntry>		  archiveEntries   = {},
				   const OfficialInfScopedModelsRequest		 *scopedModels	   = nullptr,
				   const CollectorArchiveMembers			 *collectorMembers = nullptr)
{
	inspected.scanSessionId			= input.scanSessionId ;
	inspected.infRelativePath		= path ;
	inspected.nestedArchivePath		= nested ;
	auto				  workspace = sharedWorkspace
										  ? std::move( sharedWorkspace)
										  : std::make_shared<OfficialDownloadWorkspace>() ;	// 同操作の出力ownerです
	OfficialDriverClosure closure ;															// 全署名成功まではlocalに保持する閉包
	const std::array	  selected{std::wstring_view( path)} ;								// 一件のINFを固定する選択
	const std::wstring	  workspaceTag =
		L"common-inf-" + std::to_wstring( infIndex) ;	// 同時保持するINF間で衝突しないtag
	const DriverClosureRequest request{
		&input,		  format, nested,	   selected,
		workspaceTag, cache,  scopedModels} ;	// 元の取得identityと一件の相対pathを結ぶ要求
	inspected.error = collectorMembers ? extractCollectorArchiveClosure( *collectorMembers, request,
																		policy, *workspace, closure)
									   : extractDriverClosure( request, policy, *workspace, closure) ;
	// 構造を検査できないINFへ署名合格を付与しない
	if( inspected.error != 0) {
		return ;
	}

	// 単一INF要求に対する内部整合性を要求する
	if( closure.packages.empty() || closure.packages.size() > 8U) {
		inspected.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return ;
	}

	OfficialMappedFile propertyDll ;	// 同じ原memberをCATとexport照合の両方が終わるまで固定します
	// 収集rootの明示要求だけを対象とし、同名の別workspaceやimportを検索しません
	if constexpr( std::is_same_v<Inspection, CollectorInfContentInspection>) {
		const auto &page =
			// 同rootの検査済み元位置です
			closure.packages.front().collectorPropertyPage ;
		// 元DLLの必要な場合だけ、抽出時の長さ/原hashと一致する実memberを固定します
		if( page) {
			const auto member = std::ranges::find_if( closure.entries, [&]( const auto &entry) {
				return CompareStringOrdinal( entry.relativePath.c_str(), -1,
											page->sourceRelativePath.c_str(), -1,
											TRUE) == CSTR_EQUAL ;
			}) ; // archive root付きの完全位置だけです
			// 違う用途・元hash欠落から検査対象を推定しません
			if( closure.packages.front().inspectionPurpose !=
				   OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
			   member == closure.entries.end() || member->sha256.size() != 64U) {
				inspected.error = HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
				return ;
			}

			const auto original =
				// 所有workspaceの元fileです
				workspace->path( member->relativePath) ;
			inspected.error = propertyDll.open( original, MAXIMUM_PROPERTY_PAGE_DLL_BYTES) ;
			// 固定handleの生存中に元抽出の全byteを照合します
			if( inspected.error == 0) {
				inspected.error = verifyOfficialFileMetadata(
					original, {member->uncompressedSize, member->sha256}) ;
			}

			// 改変や未取得を後続CATの成功で隠しません
			if( inspected.error != 0) {
				return ;
			}
		}
	}

	inspected.state = CommonInfInspectionState::SIGNATURE_REJECTED ;
	// 元CopyINFから到達した全INFの独立CAT/publisher/memberを確認します
	for( const auto &package : closure.packages) {
		inspected.error = verifyWindowsInfPackageIntegrity( *workspace, package) ;
		// 追加役割の署名失敗をbase成功の裏へ隠しません
		if( inspected.error != 0) {
			return ;
		}
	}

	// 全INF署名と全CAT memberの成立後に、同じ元DLLのexportを必須検査します
	if constexpr( std::is_same_v<Inspection, CollectorInfContentInspection>) {
		const auto &page =
			// 端末側の導入資格とは独立です
			closure.packages.front().collectorPropertyPage ;
		// callbackがない・別形式などの原診断をVERIFIEDや任意の棚卸しへ進めません
		if( page) {
			inspected.error =
				inspectCollectorPropertyPageExport( propertyDll.bytes(), page->callback) ;
			// 署名の成功と後続の内容不成立を区別します
			if( inspected.error != 0) {
				inspected.state = CommonInfInspectionState::CLOSURE_REJECTED ;
				return ;
			}
		}

		const auto &root = closure.packages.front() ;	// 元CATで確認した基本INF
		// 共有Portsでは同CATに結合したAMD64 SYSと正規Windowsページの境界を確かめる
		if( root.collectorSharedPortsPage) {
			const auto shadowsSystemPage =
				std::ranges::any_of( archiveEntries, []( const auto &entry) {
					const std::wstring_view name( entry.relativePath) ;	// 書庫の元位置
					const auto separator = name.find_last_of( L"\\/") ;	// 元ファイル名の境界
					const auto leaf = name.substr( separator == name.npos ? 0U : separator + 1U) ;
					constexpr std::wstring_view SYSTEM_PAGE =
						L"MsPorts.dll" ;	// Windowsが供給する標準名
					return leaf.size() == SYSTEM_PAGE.size() &&
						   CompareStringOrdinal(
							   leaf.data(), static_cast<int>( leaf.size()), SYSTEM_PAGE.data(),
							   static_cast<int>( SYSTEM_PAGE.size()), TRUE) == CSTR_EQUAL ;
				}) ; // 同名DLLを別階層から標準ページとして混入させない
			const auto driver =
				// 元CATのSYS
				workspace->path( root.collectorSharedPortsPage->driverSource) ;
			inspected.error = shadowsSystemPage || driver.empty()
								  ? HRESULT_FROM_WIN32( ERROR_INVALID_DATA)
								  : verifyAmd64PeFile( driver) ;
			// SYSの形式や標準ページの競合は署名の成立で置換しない
			if( inspected.error != 0U) {
				inspected.state = CommonInfInspectionState::CLOSURE_REJECTED ;
				return ;
			}
		}

		// 自己の署名付きSYSを持つPortsも元登録に対応する標準DLLを独立確認する
		if( root.nativePortsPage || root.collectorSharedPortsPage) {
			WindowsSystemFileTrust systemPage ;	// 固定DLLと同じWindows署名の非実行証拠
			inspected.error = inspectWindowsSerialPropertyPage( *workspace, systemPage) ;
			// DLL検査の失敗を元INF署名の成功で補わない
			if( inspected.error != 0U) {
				inspected.state = CommonInfInspectionState::CLOSURE_REJECTED ;
				return ;
			}
		}

		// 元SYSと元DLLを持つ混在媒体の両選択では、同梱文書とSCMの観測も一致させる
		if( root.collectorSerialMedia) {
			inspected.error = inspectCollectorSerialEnumeratorDependencies(
				*workspace, closure, archiveEntries, input.scanSessionId) ;
			// 片方の依存失敗や選択間の途中変化を成功と扱わない
			if( inspected.error != 0U) {
				inspected.state = CommonInfInspectionState::CLOSURE_REJECTED ;
				return ;
			}
		}

		const auto &groups = root.nativeHdcInstallGroups.empty()
								 ? root.collectorInboxInstallGroups
								 : root.nativeHdcInstallGroups ;	// 全選択の実在する基本節と付随節
		// 全選択に必要な元ファイルと導入作用を署名済みの同じ閉包で検査する
		for( const auto &seeds : groups) {
			// 公式Bluetoothは同じ元選択の棚卸しを取得してから全作用を照合する
			if( root.scopedModels && root.className == L"Bluetooth") {
				break ;
			}

			inspected.error = inspectCollectorInfDependencies(
				*workspace, closure, archiveEntries, seeds, seeds.front(), input.scanSessionId) ;
			// 元依存の診断を保持してこの閉包を拒否します
			if( inspected.error != 0) {
				inspected.state = CommonInfInspectionState::CLOSURE_REJECTED ;
				return ;
			}
		}
	}

	inspected.state = CommonInfInspectionState::VERIFIED ;
	// 内容型だけに全作用/不足の非許可findingを保持し、通常導入型へ流用しません
	if constexpr( std::is_same_v<Inspection, CollectorInfContentInspection>) {
		const auto &root = closure.packages.front() ;	// この同期操作の署名済み基本INF
		const bool	scopedBluetooth =
			root.scopedModels && root.className == L"Bluetooth" &&
			!root.collectorInboxInstallGroups.empty() ;	// 公式USBの空媒体形式
		bool	   bluetoothInboxVerified{} ;			// 元棚卸しと終端照合がこの呼出しで成立した場合だけtrue
		const bool scopedWinUsb =
			!root.collectorInboxWinUsbRegistrySection.empty() ;	// 検査済みの公式USB委譲
		bool winUsbInboxVerified{} ;							// 同じ元ハッシュと実選択に閉包を結合できた場合true
		const ScopedInboxNeedsVerifier verifyInboxNeeds =
			[&]( const OfficialInfInstallInventory &inventory) -> NativeError {
			// 先に確認した元署名、保護コピー、機器登録は同じ元選択の棚卸しだけに使う
			if( scopedWinUsb) {
				winUsbInboxVerified = root.scopedModels &&
									  root.collectorInboxInstallGroups.size() == 1U &&
									  root.collectorInboxInstallGroups.front().size() == 3U &&
									  inventory.infRelativePath == root.infRelativePath &&
									  inventory.infSha256 == root.scopedModels->infSha256 &&
									  inventory.selectedInstallSection ==
										  root.collectorInboxInstallGroups.front().front() ;
				return winUsbInboxVerified ? 0U : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			// 公式USBの元選択に限定し、Wi-Fiの検査結果へ流用しない
			if( scopedBluetooth) {
				// 同じUSB Bluetooth選択の同梱依存を元の閉包に照合した診断値
				const auto error = inspectScopedBluetoothUsbDependencies(
					*workspace, closure, archiveEntries, inventory, input.scanSessionId) ;
				bluetoothInboxVerified = error == 0U ;
				return error ;
			}

			return inspectScopedWifiBusDependencies( *workspace, closure, archiveEntries, inventory,
													input.scanSessionId) ;
		} ; // 同期中の同じ元アーカイブの一覧と閉包を借用します
		// rootと全importの元byteで棚卸しし、未対応作用を導入成功へ縮約しません
		for( const auto &package : closure.packages) {
			const auto *models =
				package.scopedModels ? &*package.scopedModels : nullptr ;	// 同じ原Modelsです
			const auto *inboxNeeds =
				models && &package == &closure.packages.front()
					? &verifyInboxNeeds
					: nullptr ;	// 公式の元基本だけが同梱依存の検査を呼び出せます
			const bool declarativeKernel =
				models && scopedModels && &package == &root &&
				format == OfficialDriverArchiveFormat::CABINET &&
				verifyScopedDeclarativeKernelReferences( *workspace, closure.entries, package) &&
				archiveEntries.size() ==
					// 元CABの全ファイルに結んだ独自クラス
					closure.entries.size() ;
			const std::array<std::wstring_view, 1U> verifiedClass{
				root.className} ;						// 同じ元署名で検査済みのクラス名
			auto inventoryPolicy = policy.infPolicy ;	// この署名付きINFの棚卸しに限る読取方針
			// 検査済みの元クラスをこのパッケージの棚卸しだけへ結ぶ
			if( (scopedWinUsb && &package == &root) || declarativeKernel) {
				inventoryPolicy.acceptedClasses = verifiedClass ;
			}

			MaintenanceInfStructure effects ;	// 同元INFの作用と不足だけです
			// 元選択の棚卸しと同梱参照の検査で最初に生じた診断を保持します
			auto					error = inspectMaintenanceInfStructure(
				   *workspace, closure.entries, package.infRelativePath, inventoryPolicy, effects,
				   models, models && scopedModels ? scopedModels->cancellation : nullptr, inboxNeeds) ;
			// 構造を確認できた公式範囲だけを元サービスとイベント資源の検査へ送ります
			if( models && error == 0) {
				// 同じUSB元選択と全同梱証拠に結び、他のファイル参照は未検査に残さない
				if( (scopedBluetooth || scopedWinUsb) && &package == &root) {
					const auto &installs = effects.installs ;	// 同じ公式範囲の全実選択
					const bool	verified =
						 scopedWinUsb ? winUsbInboxVerified : bluetoothInboxVerified ;	// 選択の証拠
					// 別起点や元の未確認の作用を成功に含めない
					if( !verified || !effects.officialHardwareScope ||
					   effects.parser.state != MaintenanceInspectionState::PASSED ||
					   effects.parser.error != 0U || effects.sourceSectionPresent ||
					   !effects.fileUses.empty() || !effects.sourceFileNames.empty() ||
					   installs.size() != 1U || !installs.front().issues.empty() ||
					   !installs.front().fileUses.empty() || !installs.front().services.empty()) {
						error = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
					} else {
						effects.referenceCoverage = MaintenanceInfReferenceCoverage::COMPLETE ;
					}
				}
				// 宣言型カーネル経路では一意な署名対象と閉包の確認が成立した候補だけを確定します
				else if( declarativeKernel) {
					// 同じ署名済みINFの唯一の実選択と完全媒体を保持した場合だけ確定する
					if( effects.officialHardwareScope && effects.installs.size() == 1U &&
					   effects.sourceFileNames.size() == 1U &&
					   effects.infSha256 == models->infSha256 && effects.fileUses.empty() &&
					   effects.dependency.observedReferenceCount == 0U) {
						effects.referenceCoverage = MaintenanceInfReferenceCoverage::COMPLETE ;
					}
				} else {
					error = verifyScopedNetworkEventFiles( *workspace, closure.entries, package,
														  effects) ;
				}
			}

			// 先行する棚卸し失敗を後続成功で消しません
			if( inspected.effectInventoryError == 0 && error != 0) {
				inspected.effectInventoryError = error ;
			}

			// 公式範囲の起点や到達節の検査が破綻した場合は同じ原署名でも閉包を渡しません
			if( models && error != 0) {
				inspected.error = error ;
				inspected.state = CommonInfInspectionState::CLOSURE_REJECTED ;
				return ;
			}

			// 同梱依存を確認した候補の端末では、元CAB内の同名INFとの競合も再検査します
			if( error == 0 && inboxNeeds &&
			   std::ranges::any_of( effects.installs,
								   &MaintenanceInfInstallStructure::wifiBusNeedsVerified)) {
				inspected.scopedDependencyArchiveEntries.assign( archiveEntries.begin(),
																archiveEntries.end()) ;
			}

			inspected.effects.push_back( std::move( effects)) ;
		}
	}

	// 基本候補の従来単一package形を維持し、必要役割は同じ実閉包の別集合へ移します
	for( std::size_t ordinal = 1U; ordinal < closure.packages.size(); ++ordinal) {
		inspected.requiredInfPackages.push_back( std::move( closure.packages[ordinal])) ;
	}

	closure.packages.resize( 1U) ;
	inspected.workspace = std::move( workspace) ;
	inspected.closure	= std::move( closure) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保守用一INFの内容と導入経路を非実行で独立評価する
 * @param[in] input 元archiveの固定内容identity
 * @param[in] format 外側のZIPまたはCAB
 * @param[in] nested 空または一段nested path
 * @param[in] path Inventoryが保持するINF相対path
 * @param[in] index 保護領域用の0起点連番
 * @param[out] result PathとIDを持たない個別観測
 * @param[in,out] collector 研究compileだけの同期stack所有者。Nullなら観測しない
 * @note 閉包は関数終了で破棄する。端末適合を照合せず、導入用結果を返さない
 */
//------------------------------------------------------------------------------
void inspectMaintenanceInf( const DriverArchiveInput			&input,
						   const OfficialDriverArchiveFormat format, const std::wstring &nested,
						   const std::wstring &path, const std::size_t index,
						   MaintenanceInfInspection &result
// 通常compileの引数・observer状態を変更しない
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
						   ,
						   ReachedReferenceCollector *collector
#endif
)
{
	result.archiveDepth = nested.empty() ? 0U : 1U ;
	OfficialDownloadWorkspace workspace ;												// この非実行検査だけの保護領域
	MaintenanceDriverClosure  closure ;													// 導入用型とは互換でない内容閉包
	const std::array		  selected{std::wstring_view( path)} ;						// 一つの元INFを固定する
	const std::wstring		  tag	= L"maintenance-inf-" + std::to_wstring( index) ;	// 有限連番
	const NativeError		  error = extractMaintenanceDriverClosure(
		{&input, format, nested, selected, tag}, CONTENT_POLICY, workspace, closure) ;	// 内容抽出
	// 未解析なら署名と導入経路を未検査へ残し、driver不正を断定しない
	if( error != 0) {
		result.parser = {error == fromWin32( ERROR_NOT_SUPPORTED)
							 ? MaintenanceInspectionState::UNSUPPORTED
							 : MaintenanceInspectionState::FAILED,
						 error} ;
// 元未解析rowも同runの未観測として保持し、部分closureを公開しない
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
		// 研究観測の独立失敗を元parser診断へ返さない
		if( collector != nullptr) {
			collector->append( closure, result, index) ;
		}
#endif
		return ;
	}

	// 内容入口の単一INF契約違反を隠さない
	if( closure.content.packages.size() != 1U) {
		result.parser = {MaintenanceInspectionState::FAILED,
						 static_cast<NativeError>( E_UNEXPECTED)} ;
// 同じ元FAILEDを研究観測へ残す
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
		// 通常射影を完了していないclosureは未観測として扱う
		if( collector != nullptr) {
			collector->append( MaintenanceDriverClosure{}, result, index) ;
		}
#endif
		return ;
	}

	// 同一閉包の各軸をそのまま結び、root-onlyの再計算で全署名結果を上書きしない
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

	OfficialInfReferenceInventory references ;	// 従来route用の全section参照。新summaryを更新しない
	const NativeError			  referencesError = inspectOfficialInfReferences(
		workspace, closure.content.entries, path, references) ;	// 未解決の参照を補完しない
	OfficialInfPackage routePackage ;							// 従来導入構造の静的評価だけを受ける
	const NativeError  routeError =
		inspectOfficialInfPackage( workspace, closure.content.entries, path, INF_POLICY,
								  routePackage) ;	// 従来policyを変更しない
	const NativeError routeFinding =
		routeError != 0 ? routeError
						: (referencesError != 0 ? referencesError
												: (references.hasExternalDependencies
													   ? fromWin32( ERROR_NOT_SUPPORTED)
													   : 0)) ;	// 依存未解決も保留
	result.installRoute = {routeFinding == 0 ? MaintenanceInspectionState::PASSED
											 : MaintenanceInspectionState::UNSUPPORTED,
						   routeFinding} ;
// 従来route射影後、同一extractのclosureが生存するscopeだけでconst借用する
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
	// 研究計測の容量・例外失敗でも元rowとHRESULTを保持する
	if( collector != nullptr) {
		collector->append( closure, result, index) ;
	}
#endif
}

//------------------------------------------------------------------------------
/**
 * @brief 保守検査の全体失敗で部分結果を破棄する
 * @param[in,out] result 破棄する保守観測
 * @param[in] error 0ではないHRESULT
 * @return 同じ診断値
 */
//------------------------------------------------------------------------------
NativeError failMaintenance( MaintenanceDriverPackageInspection &result, const NativeError error)
{
	result		 = {} ;
	result.error = error ;
	return error ;
}

} // namespace

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
NativeError copyLocalDriverArchive( const std::wstring_view	  selectedPath,
								   const ScanSessionId		  scanSessionId,
								   OfficialDownloadWorkspace &workspace, DriverArchiveInput &input,
								   OfficialDriverArchiveFormat &format)
{
	input = {} ;
	// Network path、device path、ADS、埋込NUL、相対pathをlocal入力へ混入させない
	if( scanSessionId == 0 || selectedPath.size() < 4U || selectedPath.size() > 32767U ||
	   selectedPath[1] != L':' || selectedPath[2] != L'\\' ||
	   !((selectedPath[0] >= L'A' && selectedPath[0] <= L'Z') ||
		 (selectedPath[0] >= L'a' && selectedPath[0] <= L'z')) ||
	   selectedPath.find( L':', 2U) != std::wstring_view::npos ||
	   selectedPath.find( L'\0') != std::wstring_view::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const std::wstring extension = extensionOf( selectedPath) ;	// 実行しない形式の選択
		// 明示対応していない形式を起動や外部展開へfallbackしない
		if( extension != L".zip" && extension != L".cab" && extension != L".exe") {
			return fromWin32( ERROR_NOT_SUPPORTED) ;
		}

		NativeError error =
			// 保護領域作成
			workspace.initialize( L"local-driver-input", scanSessionId) ;
		// 初期化失敗なら元fileを読み取らない
		if( error != 0) {
			return error ;
		}

		DriverArchiveInput copied ;	// 全copyとhash成功後だけ公開する内容identity
		error = copyArchiveBytes( std::wstring( selectedPath), workspace, copied.byteCount) ;
		// Copy失敗をhash処理で上書きしない
		if( error != 0) {
			return error ;
		}

		copied.scanSessionId  = scanSessionId ;
		copied.inspectionPath = workspace.path( COPY_NAME) ;
		error				  = computeFileSha256( copied.inspectionPath, copied.sha256) ;
		// Hashが固定できない入力を後段へ渡さない
		if( error != 0) {
			return error ;
		}

		format = extension == L".zip"	? OfficialDriverArchiveFormat::ZIP
				 : extension == L".cab" ? OfficialDriverArchiveFormat::CABINET
										: OfficialDriverArchiveFormat::SEVEN_ZIP_SFX ;
		input  = std::move( copied) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元選択一件だけを、操作の残り保持予算へ結んで検査する
 * @tparam Inspection 指定用途と同じ通常結果またはcollector内容集合です
 * @param[in] input 固定した元archiveの内容identity
 * @param[in] format 既存の非実行archive形式
 * @param[in] selectedInf 元inventoryから選んだ完全相対名
 * @param[out] inspection 個別成功または拒否行。全体失敗時は診断だけ
 * @param[in] cancellation 元同期操作だけの取消し照会
 * @param[in] nestedArchive 空または元一段archive名
 * @param[in] sharedWorkspace 同じflat操作の出力owner。Nestedでは空
 * @param[in,out] cache 元flat入力だけの共有内容cache。Nestedではnull
 * @param[in] maximumRetainedBytes 今回の作成前から適用する保持残量
 * @param[in] inspectionPolicy 通常または非実行内容の固定policyです。共有cacheで用途を変更しません
 * @param[in] scopedModels 同じ一件の収集元INFの公式配布対象です。通常はnullです
 * @param[in] requiredImportPath 署名付きPEの審査済み補助INF相対名。空なら元一覧の範囲を追加制限しない
 * @return 通常内容検査完了0。個別不合格も行へ残し、全体失敗は元HRESULT
 */
//------------------------------------------------------------------------------
template <typename Inspection>
static NativeError inspectSelectedCommonDriverPackageImpl(
	const DriverArchiveInput &input, const OfficialDriverArchiveFormat format,
	const std::wstring_view selectedInf, Inspection &inspection,
	const std::function<bool()> &cancellation, const std::wstring_view nestedArchive,
	std::shared_ptr<OfficialDownloadWorkspace> sharedWorkspace, DriverArchiveExtractionCache *cache,
	const std::uint64_t maximumRetainedBytes, const OfficialDriverClosurePolicy &inspectionPolicy,
	const OfficialInfScopedModelsRequest *scopedModels, const std::wstring_view requiredImportPath)
{
	inspection = {} ;
	// 監視側の有限な一INFだけを受理し、形式や原byte上限を緩めません
	if( input.scanSessionId == 0U || input.byteCount == 0U || input.byteCount > INPUT_BYTES ||
	   selectedInf.empty() || selectedInf.size() > 260U ||
	   (format != OfficialDriverArchiveFormat::ZIP &&
		format != OfficialDriverArchiveFormat::CABINET &&
		format != OfficialDriverArchiveFormat::SEVEN_ZIP_SFX &&
		format != OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER)) {
		return failInspection( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	}

	try {
		// 既に保持した別閉包の枠を今回の作成前から除きます
		if( maximumRetainedBytes == 0U || maximumRetainedBytes > EXPANDED_BYTES) {
			return failInspection( inspection, fromWin32( ERROR_FILE_TOO_LARGE)) ;
		}

		auto policy				   = inspectionPolicy ;	// 同操作の用途と残り保持量を保持します
		policy.maximumClosureBytes = maximumRetainedBytes ;
		// 開始前の取消しを部分内容の合格へ変えません
		if( cancellation && cancellation()) {
			return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
		}

		OfficialDriverArchiveInventory inventory ;	// 全外側entryと元archivehashです
		auto error = inspectDriverArchiveInventory( {&input, format, nestedArchive}, policy,
												   inventory) ;	// 元inventory/hashの実結果です
		// 一INF選択を理由に全archive破損やentry上限を無視しません
		if( error != 0 || inventory.entries.size() > 4096U) {
			return failInspection( inspection,
								  error != 0 ? error : fromWin32( ERROR_BUFFER_OVERFLOW)) ;
		}

		const auto selected = std::ranges::find_if( inventory.entries, [&]( const auto &entry) {
			return entry.relativePath == selectedInf ;
		}) ; // 元inventoryの完全一致だけです
		// 任意pathや別形式を選択INFへ補完しません
		if( selected == inventory.entries.end() || extensionOf( selected->relativePath) != L".inf") {
			return failInspection( inspection, fromWin32( ERROR_NOT_FOUND)) ;
		}

		// 主INFと補助を審査した元ディレクトリだけを対象とし、別OSの格納先には広げない
		if( !requiredImportPath.empty()) {
			const auto directoryEnd = selectedInf.find_last_of( L'\\') ;	// 元の親名の長さ
			const bool extraInf = std::ranges::any_of( inventory.entries, [&]( const auto &entry) {
				const auto &path = entry.relativePath ;	// 元一覧の一件の完全相対名
				return path != selectedInf && path != requiredImportPath &&
					   path.find_last_of( L'\\') == directoryEnd &&
					   (directoryEnd == std::wstring_view::npos ||
						CompareStringOrdinal( selectedInf.data(), static_cast<int>( directoryEnd),
											 path.c_str(), static_cast<int>( directoryEnd),
											 TRUE) == CSTR_EQUAL) &&
					   extensionOf( path) == L".inf" ;
			}) ; // 元一覧と二件の審査名を同期比較する
			// 同じ格納先に独立したINFがあれば、審査済み役割の閉集合として受理しない
			if( extraInf) {
				return failInspection( inspection, fromWin32( ERROR_INVALID_DATA)) ;
			}
		}

		typename decltype( inspection.infs)::value_type inspected ;	// 同用途だけの非互換個別型です
		inspectOneInf( input, format, std::wstring{nestedArchive}, selected->relativePath, 0U,
					  inspected, sharedWorkspace, cache, policy, inventory.entries, scopedModels) ;
		// 確保失敗や保持量超過を通常の内容拒否へ丸めません
		if( inspected.error == static_cast<NativeError>( E_OUTOFMEMORY) ||
		   inspected.closure.expandedBytes > EXPANDED_BYTES) {
			return failInspection( inspection, inspected.error != 0
												  ? inspected.error
												  : fromWin32( ERROR_FILE_TOO_LARGE)) ;
		}

		// 同期検査後の取消しでは所有閉包を破棄します
		if( cancellation && cancellation()) {
			return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
		}

		error = verifyOfficialFileMetadata(
			input.inspectionPath, {input.byteCount, input.sha256}) ;	// 元archiveを再確認します
		// 途中byte差替えから一INFの正常結果を発行しません
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

//------------------------------------------------------------------------------
/**
 * @brief 同じ原payloadの明示selectorを通常policyと一度の実保持で検査する
 * @tparam Inspection 用途と同じ通常結果またはcollector内容集合です
 * @param[in] input 同操作中固定する原archive identity
 * @param[in] format 明示ZIP/CAB/SFX形式。EXEは非実行解析だけを行う
 * @param[in] selectors firstが一段nested、secondが元INF相対名の検証済み集合。最大128件
 * @param[out] inspection 全成功時だけ元個別結果を保持する
 * @param[in] cancellation 空または同期workerの取消し照会
 * @param[in] inspectionPolicy 同操作で不変の通常または内容専用policyです
 * @param[in] scopedModels 同じ公式配布元の一件だけの対象です。通常はnullです
 * @param[in] requiredImportPath 署名付きPEの審査済み補助INF相対名。空なら従来の範囲を使う
 * @return 元内容検査のHRESULT。個別拒否は元行へ残す
 * @note flat集合の同じmemberだけを共有し、任意UI/pathから由来や導入権限を作らない
 */
//------------------------------------------------------------------------------
template <typename Inspection>
static NativeError inspectSelectedDriverPackages(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	std::span<const std::pair<std::wstring_view, std::wstring_view>> selectors,
	Inspection &inspection, const std::function<bool()> &cancellation,
	const OfficialDriverClosurePolicy	 &inspectionPolicy,
	const OfficialInfScopedModelsRequest *scopedModels		 = nullptr,
	const std::wstring_view				  requiredImportPath = {})
{
	inspection = {} ;
	// 空/過大選択を全INFの自動検査へ変換しません
	if( selectors.empty() || selectors.size() > INF_COUNT ||
	   (scopedModels != nullptr && selectors.size() != 1U)) {
		return failInspection( inspection, E_INVALIDARG) ;
	}

	try {
		DriverArchiveExtractionCache cache ;	// 同じflat payloadの同期ownerです
		cache.cancellation = cancellation ;
		auto workspace =
			std::make_shared<OfficialDownloadWorkspace>() ;	// 同じ実memberを一度だけ保持します
		inspection.scanSessionId = input.scanSessionId ;
		inspection.archiveSha256 = input.sha256 ;
		inspection.archiveBytes	 = input.byteCount ;
		std::uint64_t nestedBytes{} ;	// 従来nestedの独立保持だけを加算します
		const bool	  hasNested = std::ranges::any_of( selectors, []( const auto &selector) {
			   return !selector.first.empty() ;
		   }) ; // 同時に一つだけの内側archiveです
		const auto	  retainedBudget =
			EXPANDED_BYTES - (hasNested ? POLICY.zipPolicy.maximumSingleFileBytes
										: 0U) ;	// 入力2/solid3/内側0.5/保持2.5GiB以内です
		// 元選択集合だけを検査し、未選択INFを走査しません
		for( const auto &selector : selectors) {
			Inspection selected ;						// 用途と同じ非互換型の個別結果です
			const bool flat = selector.first.empty() ;	// 同じflat workspaceだけを共有します
			const auto used =
				nestedBytes +
				(flat ? 0U
					  : cache.retainedBytes()) ;	// flat cache自身の一意量はclosure側が共同加算します
			// 次の閉包の作成前に共有枠超過を拒否します
			if( used >= retainedBudget) {
				return failInspection( inspection, fromWin32( ERROR_FILE_TOO_LARGE)) ;
			}

			// 同じ入力・所有操作の元診断です
			const auto error = inspectSelectedCommonDriverPackageImpl(
				input, format, selector.second, selected, cancellation, selector.first,
				flat ? workspace : nullptr, flat ? &cache : nullptr, retainedBudget - used,
				inspectionPolicy, scopedModels, requiredImportPath) ;
			// 全体失敗時は一部の成功を返しません
			if( error != 0) {
				return failInspection( inspection, error) ;
			}

			// 別nested閉包も同じ共同保持予算を消費します
			if( !flat) {
				nestedBytes += selected.retainedBytes ;
			}

			// 同じ元memberを重複計上せず、実保持量だけで上限を判定します
			if( nestedBytes > retainedBudget ||
			   cache.retainedBytes() > retainedBudget - nestedBytes) {
				return failInspection( inspection, fromWin32( ERROR_FILE_TOO_LARGE)) ;
			}

			inspection.inventoryFileCount =
				(std::max)( inspection.inventoryFileCount, selected.inventoryFileCount) ;
			// 個別拒否も元の分母と理由へ保持します
			for( auto &inf : selected.infs) {
				inspection.infs.push_back( std::move( inf)) ;
			}
		}

		inspection.retainedBytes		  = nestedBytes + cache.retainedBytes() ;
		inspection.mappedSolidPeakBytes	  = cache.mappedPeakBytes() ;
		inspection.decodedSolidBlockCount = cache.decodedBlockCount() ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return failInspection( inspection, E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ原payloadの明示selectorを通常policyと一度の実保持で検査する
 * @param[in] input 同操作中固定する原archive identity
 * @param[in] format 明示ZIP/CAB/SFX形式。EXEは非実行解析だけを行う
 * @param[in] selectors firstが一段nested、secondが元INF相対名の検証済み集合。最大128件
 * @param[out] inspection 全成功時だけ元個別結果を保持する
 * @param[in] cancellation 空または同期workerの取消し照会
 * @return 元内容検査のHRESULT。個別拒否は元行へ残す
 * @note 通常導入Classと元INF構造条件を維持し、collectorの追加形式を受理しません
 */
//------------------------------------------------------------------------------
NativeError inspectSelectedCommonDriverPackages(
	const DriverArchiveInput &input, const OfficialDriverArchiveFormat format,
	std::span<const std::pair<std::wstring_view, std::wstring_view>> selectors,
	CommonDriverPackageInspection &inspection, const std::function<bool()> &cancellation)
{
	return inspectSelectedDriverPackages( input, format, selectors, inspection, cancellation,
										 POLICY) ;
}

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
NativeError inspectCollectorDriverPackageContent(
	const DriverArchiveInput &input, const OfficialDriverArchiveFormat format,
	std::span<const std::pair<std::wstring_view, std::wstring_view>> selectors,
	CollectorDriverPackageContent &content, const std::function<bool()> &cancellation,
	const OfficialInfScopedModelsRequest *scopedModels)
{
	return inspectSelectedDriverPackages( input, format, selectors, content, cancellation,
										 COLLECTOR_CONTENT_POLICY, scopedModels) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAT照合後の元INFから、対象Serverの全公開Hardware行を元作用の起点にする
 * @param[in,out] inspected 元閉包。成功時だけServerで検証した起点と作用を保持する
 * @param[in] selectedInf 同じ元archiveの選択INF相対名
 * @param[in] platform 元定義のWindows Server x64の明示観測点
 * @param[out] identity 同じ元INFの公開Models。すべての作用成立時だけ更新する
 * @param[in] cancellation 同じ取得操作の停止照会
 * @return 成功0、未解決の参照・作用・署名・指定OSの読み取り失敗時はHRESULT
 * @throws std::bad_alloc Modelsまたは作用の記憶域を確保できない場合
 * @note 元INFとCATの確認後に呼ぶ。端末の現在情報や別の索引からHardwareを補わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] static NativeError inspectCollectorArchiveTarget(
	CollectorInfContentInspection &inspected, const std::wstring_view selectedInf,
	const OfficialInfModelsPlatform &platform, OfficialInfPublishedIdentity &identity,
	const std::function<bool()> &cancellation)
{
	// 元CATで検証した一基本INFだけを対象Serverの作用検査へ進める
	if( inspected.state != CommonInfInspectionState::VERIFIED || !inspected.workspace ||
	   inspected.closure.packages.size() != 1U || !inspected.requiredInfPackages.empty()) {
		return fromWin32( ERROR_NOT_SUPPORTED) ;
	}

	auto	  &package = inspected.closure.packages.front() ;	// 元CATと全参照を照合した基本INF
	const auto root =
		std::ranges::find( inspected.closure.entries, selectedInf,
						  &OfficialZipEntry::relativePath) ;	// 同じ元綴りと実SHA-256を持つ原位置
	// 選択外の役割・未解決のCopyINF・別位置から対象根拠を発行しない
	if( package.role != DriverPlanRole::BASE_DRIVER || !package.unresolvedCopyInfPaths.empty() ||
	   package.infRelativePath != selectedInf || root == inspected.closure.entries.end()) {
		return fromWin32( ERROR_INVALID_DATA) ;
	}

	OfficialInfPublishedIdentity target ;	// 同じ署名済みINFから確定するServerの全公開行
	auto						 error = readOfficialInfPublishedIdentityForPlatform(
		*inspected.workspace, package, platform, root->sha256,
		target) ;	// 現hostへ代替しないWindows Models選択
	// 指定観測点の列挙が成立しない場合は作用を確認できない
	if( error != 0) {
		return error ;
	}

	std::vector<std::wstring> hardwareIds ;	// 元Hardware欄の一意な全ID。Compatible欄は含めない
	// 対象Serverの全Models節からHardware欄を広げずに集める
	for( const auto &model : target.models) {
		// 全元行を渡し、Windowsの大小文字比較で同じIDだけを再登録しない
		for( const auto &id : model.hardwareIds) {
			// 同じ元IDの複数節での出現は、後段が全元行を個別確認する
			if( std::ranges::none_of( hardwareIds, [&]( const auto &existing) {
				   return CompareStringOrdinal( existing.c_str(), -1, id.c_str(), -1, TRUE) ==
						  CSTR_EQUAL ;
			   })) {
				// 上限超過で後続の元IDを切り捨てない
				if( hardwareIds.size() == OFFICIAL_SCOPED_MODELS_MAX_TARGETS) {
					return fromWin32( ERROR_BUFFER_OVERFLOW) ;
				}

				hardwareIds.push_back( id) ;
			}
		}
	}

	OfficialInfScopedModelsEvidence models ;	// 元Hardware全件と実DDInstall起点を結んだ原証拠
	error = readOfficialInfScopedModels( *inspected.workspace, selectedInf, root->sha256, &platform,
										hardwareIds, models, cancellation) ;
	// 起点が曖昧・未読取り・取消しの場合は元署名だけで作用成功にしない
	if( error != 0) {
		return error ;
	}

	package.scopedModels = std::move( models) ;
	MaintenanceInfStructure effects ;	// 指定Serverに属する同一原INFの作用と参照の観測
	error = inspectMaintenanceInfStructure( *inspected.workspace, inspected.closure.entries,
										   selectedInf, COLLECTOR_CONTENT_POLICY.infPolicy, effects,
										   &*package.scopedModels, &cancellation) ;
	// 同梱外依存の補完を許さず、ここで確認した原作用だけをイベント検査へ送る
	if( error == 0) {
		error = verifyScopedNetworkEventFiles( *inspected.workspace, inspected.closure.entries,
											  package, effects) ;
	}

	// 既存検査が確認できなかった付随作用や未固定参照を成功へ数えない
	if( error != 0 || effects.parser.state != MaintenanceInspectionState::PASSED ||
	   effects.referenceCoverage != MaintenanceInfReferenceCoverage::COMPLETE) {
		return error != 0 ? error : fromWin32( ERROR_NOT_SUPPORTED) ;
	}

	inspected.effects.clear() ;
	inspected.effects.push_back( std::move( effects)) ;
	inspected.effectInventoryError = 0 ;
	identity					   = std::move( target) ;
	return 0 ;
}

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
NativeError inspectCollectorArchiveMembers( const CollectorArchiveMembers   &members,
										   const std::wstring_view			selectedInf,
										   const OfficialInfModelsPlatform &platform,
										   CollectorDriverPackageContent   &content,
										   OfficialInfPublishedIdentity	   &identity)
{
	identity				 = {} ;
	content					 = {} ;
	const auto &input		 = members.input() ;		// 読取り専用mappingから検証した原取得
	const auto	files		 = members.files() ;		// 同選択directoryの元member範囲
	const auto &cancellation = members.cancellation() ;	// 同期中に借用する取消し照会
	// 原本と結びつかないメモリー、空一覧、上限を越えた一覧を検査へ渡さない
	if( input.scanSessionId == 0U || input.byteCount == 0U || input.byteCount > INPUT_BYTES ||
	   input.workspaceMode != OfficialWorkspaceMode::CURRENT_USER_INSPECTION || files.empty() ||
	   files.size() > COLLECTOR_CONTENT_POLICY.zipPolicy.maximumEntryCount) {
		return E_INVALIDARG ;
	}

	try {
		// 取消し済みの操作では閉包用のworkspaceを作らない
		if( cancellation && cancellation()) {
			return fromWin32( ERROR_CANCELLED) ;
		}

		// 収集で固定した元INFの相対パスが閉じたメンバー集にあるかを示す位置
		const auto selected =
			std::ranges::find( files, selectedInf, &CollectorArchiveMemberView::relativePath) ;
		// 完全に一致する原INFだけを選択する
		if( selected == files.end() || extensionOf( selectedInf) != L".inf") {
			return fromWin32( ERROR_NOT_FOUND) ;
		}

		std::vector<OfficialZipEntry> inventory ;	// 共通作用・依存検査へ渡す選択範囲の元一覧
		inventory.reserve( files.size()) ;
		// ファイル本体を作成せず、同梱依存の元pathと長さだけを投影する
		for( const auto &member : files) {
			inventory.push_back( {std::wstring( member.relativePath), member.bytes.size()}) ;
		}

		CollectorInfContentInspection inspected ;	// 全体成功まで公開しない個別結果
		inspectOneInf( input, OfficialDriverArchiveFormat::ZIP, {}, std::wstring( selectedInf), 0U,
					  inspected, {}, nullptr, COLLECTOR_CONTENT_POLICY, inventory, nullptr,
					  &members) ;
		// 元個別診断と取消しを成功closed集合へ変換しない
		if( inspected.error != 0) {
			return inspected.error ;
		}

		OfficialInfPublishedIdentity target ;	// CATと対象Serverの原作用の全成功まで非公開
		// 元閉包と採用したプラットフォーム上で選択INFの内容を再照合した診断値
		const auto					 error =
			inspectCollectorArchiveTarget( inspected, selectedInf, platform, target, cancellation) ;
		// 元作用、全参照または対象Modelsを確認できない閉包は破棄する
		if( error != 0) {
			return error ;
		}

		// 署名照合や作用検査中に停止した場合は所有閉包を破棄する
		if( cancellation && cancellation()) {
			return fromWin32( ERROR_CANCELLED) ;
		}

		CollectorDriverPackageContent verified ;	// 元の原byteと全選択結果をまとめてから返す
		verified.scanSessionId		= input.scanSessionId ;
		verified.archiveSha256		= input.sha256 ;
		verified.archiveBytes		= input.byteCount ;
		verified.inventoryFileCount = inventory.size() ;
		verified.retainedBytes		= inspected.closure.expandedBytes ;
		verified.infs.push_back( std::move( inspected)) ;
		content	 = std::move( verified) ;
		identity = std::move( target) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		// Readerから借用した同期照会等の例外はworker境界へ漏らさない
		return E_UNEXPECTED ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 混在シリアルの署名済み元選択に、公式対象Windowsの宣言を結ぶ
 * @param[in] inspected 同梱依存まで検査を終えた私有の元閉包
 * @param[in] selectedInf 元書庫にある完全なINF名
 * @param[in] platform 元配布が指定するWindows観測点
 * @param[out] target 全確認に成功した公開Models。失敗時は空
 * @param[in] cancellation 同じ取得操作の非blockingな停止照会
 * @return 実閉包と対象が一致した場合は0、元照合・読取り・取消し失敗はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] static NativeError inspectCollectorReviewedSerialTarget(
	const CollectorInfContentInspection &inspected, const std::wstring_view selectedInf,
	const OfficialInfModelsPlatform &platform, OfficialInfPublishedIdentity &target,
	const std::function<bool()> &cancellation)
{
	// 選択し書き出した元四ファイルと一つの確認済み基本INFだけを後段へ進める
	if( inspected.state != CommonInfInspectionState::VERIFIED || !inspected.workspace ||
	   inspected.closure.packages.size() != 1U || inspected.closure.entries.size() != 4U ||
	   !inspected.requiredInfPackages.empty()) {
		return fromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto &package = inspected.closure.packages.front() ;	// 署名と元作用を照合した基本INF
	const auto	root =
		std::ranges::find( inspected.closure.entries, selectedInf,
						  &OfficialZipEntry::relativePath) ;	// 同じ元名とハッシュを持つ閉包項目
	// 別の選択、未解決CopyINFや別用途の元閉包を公開Modelsへ転用しない
	if( !package.collectorSerialMedia || package.role != DriverPlanRole::BASE_DRIVER ||
	   package.infRelativePath != selectedInf || !package.unresolvedCopyInfPaths.empty() ||
	   root == inspected.closure.entries.end() || root->sha256.size() != 64U) {
		return fromWin32( ERROR_INVALID_DATA) ;
	}

	// 署名・同梱依存の確認中に届いた停止を対象Modelsの読取り前に反映する
	if( cancellation && cancellation()) {
		return fromWin32( ERROR_CANCELLED) ;
	}

	return readOfficialInfPublishedIdentityForPlatform( *inspected.workspace, package, platform,
													   root->sha256, target) ;
}

/**
 * @brief 元ZIPとNSISの照合で得た原範囲だけを混在シリアル内容へ接続する
 */
class CollectorReviewedSerialArchiveReader final {
public:
	/**
	 * @brief 元四ファイルを検査し、同梱依存とWindowsクライアントの元Modelsを同じ結果へ結ぶ
	 * @param[in] input 同じ私有収集で取得した元ZIPの同一性
	 * @param[in] reviewed 元ZIPとNSISの四項目の審査条件
	 * @param[in] selectedInf 元書庫内の完全なINF名
	 * @param[in] platform 公式配布対象のWindows x64の明示観測点
	 * @param[out] content 全検査を通過した元閉包。失敗時は変更しない
	 * @param[out] identity 元INFの公開Models。失敗時は変更しない
	 * @param[in] cancellation 同じ収集操作の停止照会
	 * @return 全検査成功時0、元同一性、照合、取消しの失敗はHRESULT
	 * @throws std::bad_alloc 検査結果に必要な領域を確保できない場合
	 */
	[[nodiscard]] static NativeError inspect( const DriverArchiveInput		 &input,
											 const OfficialReviewedNsisZip	 &reviewed,
											 std::wstring_view				  selectedInf,
											 const OfficialInfModelsPlatform &platform,
											 CollectorDriverPackageContent	 &content,
											 OfficialInfPublishedIdentity	 &identity,
											 const std::function<bool()>	 &cancellation) ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 取得済みの元ZIPと内側NSISの四項目を、私有内容検査の元範囲へ結ぶ
 * @param[in] input 元ZIPの取得同一性
 * @param[in] reviewed 元ZIP、内側EXEと各展開ファイルの審査条件
 * @param[in] selectedInf 名前を変換しない元INFの完全相対名
 * @param[in] platform 対象Windowsクライアントの明示観測点
 * @param[out] content 全検査に成功した元ZIPの一基本INFと閉包。失敗時は変更しない
 * @param[out] identity 同じ元INF由来の公開Models。失敗時は変更しない
 * @param[in] cancellation 同じ操作の非blockingな停止照会
 * @return 原配布、署名、参照、作用と対象Modelsの確認成功は0、失敗は元HRESULT
 * @throws std::bad_alloc 同期検査の記憶域を確保できない場合
 */
//------------------------------------------------------------------------------
NativeError CollectorReviewedSerialArchiveReader::inspect( const DriverArchiveInput		&input,
														  const OfficialReviewedNsisZip &reviewed,
														  const std::wstring_view selectedInf,
														  const OfficialInfModelsPlatform &platform,
														  CollectorDriverPackageContent	  &content,
														  OfficialInfPublishedIdentity	  &identity,
														  const std::function<bool()> &cancellation)
{
	// 取消し済みの収集から元ファイルを開かない
	if( cancellation && cancellation()) {
		return fromWin32( ERROR_CANCELLED) ;
	}

	std::vector<OfficialZipFile> files ;	// 元ZIPと元NSISへハッシュで結んだ所有バイト
	const auto					 read =
		// 実取得の構造と原バイト
		readOfficialReviewedNsisZipMembers( input, reviewed, files) ;
	// 改変や別配布を既存のZIP検査へ再解釈しない
	if( read != 0U) {
		return read ;
	}

	// 読取り元と一致する四ファイル全体にだけ私有内容検査を発行する
	if( files.size() != 4U) {
		return fromWin32( ERROR_INVALID_DATA) ;
	}

	// 元ZIP検査中の停止を、閉包の展開・署名検査に入る前に反映する
	if( cancellation && cancellation()) {
		return fromWin32( ERROR_CANCELLED) ;
	}

	std::array<CollectorArchiveMemberView, 4U> views ;		// 同期検査中だけ所有元ファイルを借りる
	std::array<OfficialZipEntry, 4U>		   inventory ;	// 同じ四つの原名・長さ・ハッシュ
	// 完全な元四項目だけを、元定義の順序で私有検査に渡す
	for( std::size_t index = 0U; index < views.size(); ++index) {
		const auto &file = files[index] ;	// 展開・長さ・SHA-256の照合を通過した元通常ファイル
		views[index]	 = {file.relativePath, file.bytes} ;
		inventory[index] = {file.relativePath, file.bytes.size(),
							std::wstring( reviewed.members[index].sha256)} ;
	}

	const CollectorArchiveMembers members( input, views,
										  cancellation) ;	// 同じ取得元と展開済み元バイトの同期結合
	auto policy = COLLECTOR_CONTENT_POLICY ;				// 既存の閉包・署名条件を共有する私有用途
	policy.infPolicy.collectorSerialMedia = true ;
	CollectorInfContentInspection inspected ;	// 検査成功まで公開しない選択結果
	inspectOneInf( input, OfficialDriverArchiveFormat::ZIP, {}, std::wstring( selectedInf), 0U,
				  inspected, {}, nullptr, policy, inventory, nullptr, &members) ;
	// 閉包、署名、同梱依存の元診断を保つ
	if( inspected.error != 0U) {
		return inspected.error ;
	}

	OfficialInfPublishedIdentity target ;	// 同じ元閉包から得る公式対象の公開Models
	const auto					 checked = inspectCollectorReviewedSerialTarget(
		  inspected, selectedInf, platform, target, cancellation) ;	// 元構造から確認した両選択との照合
	// 署名成立だけで公式対象の検査まで成功と扱わない
	if( checked != 0U) {
		return checked ;
	}

	// 終了直前に期限または取消しが成立した結果を渡さない
	if( cancellation && cancellation()) {
		return fromWin32( ERROR_CANCELLED) ;
	}

	CollectorDriverPackageContent complete ;	// 元ZIPの同一性と署名済み選択を一括で公開する
	complete.scanSessionId		= input.scanSessionId ;
	complete.archiveSha256		= input.sha256 ;
	complete.archiveBytes		= input.byteCount ;
	complete.inventoryFileCount = inventory.size() ;
	complete.retainedBytes		= inspected.closure.expandedBytes ;
	complete.infs.push_back( std::move( inspected)) ;
	content	 = std::move( complete) ;
	identity = std::move( target) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 審査済みZIPから混在シリアル内容と対象Windowsクライアントの公開Modelsを確認する
 * @param[in] input 同じ私有収集で取得した元ZIPのパス・長さ・SHA-256
 * @param[in] reviewed 同じZIPと内側NSISの審査条件
 * @param[in] selectedInf 大小文字を保持した完全な元INF名
 * @param[in] platform 公式配布対象のWindowsクライアントx64観測点
 * @param[out] content 全検査済みの元配布と閉包。失敗時は空
 * @param[out] identity 同じ元INFが明示する公開Models。失敗時は空
 * @param[in] cancellation 同じ取得操作の停止照会。空は省略
 * @return 元内容、同梱依存と対象Modelsが成立すれば0、その他は元HRESULT
 * @note 実行、公開許可、端末導入は行わない
 */
//------------------------------------------------------------------------------
NativeError inspectCollectorReviewedSerialNsisContent( const DriverArchiveInput		  &input,
													  const OfficialReviewedNsisZip	  &reviewed,
													  const std::wstring_view		   selectedInf,
													  const OfficialInfModelsPlatform &platform,
													  CollectorDriverPackageContent	  &content,
													  OfficialInfPublishedIdentity	  &identity,
													  const std::function<bool()>	  &cancellation)
{
	content	 = {} ;
	identity = {} ;
	// 元取得を保持する私有領域、明示クライアント対象と四つの審査条件へ限定する
	if( input.scanSessionId == 0U || input.resourceContent ||
	   input.workspaceMode != OfficialWorkspaceMode::CURRENT_USER_INSPECTION ||
	   platform.processorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
	   platform.productType != VER_NT_WORKSTATION || reviewed.members.size() != 4U) {
		return E_INVALIDARG ;
	}

	try {
		// 同じ審査に含まれる明示INF一件だけを元ZIPから選ぶ
		if( extensionOf( selectedInf) != L".inf" ||
		   std::ranges::find( reviewed.members, selectedInf,
							 &OfficialReviewedNsisMember::relativePath) == reviewed.members.end()) {
			return E_INVALIDARG ;
		}

		return CollectorReviewedSerialArchiveReader::inspect( input, reviewed, selectedInf, platform,
															 content, identity, cancellation) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		// 同期の停止照会などから出る例外をworkerへ漏らさない
		return E_UNEXPECTED ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済み内側ZIPを現在user保護領域の固定名へ完全に保存する
 * @param[in,out] workspace 作成済みの現在user検査領域
 * @param[in] name 同領域へ新規作成する固定相対名
 * @param[in] bytes 元署名と完全相対名を照合した内側ZIPの原byte
 * @return 保存成功時0、元長、空き容量、作成または書込みの失敗はHRESULT
 */
//------------------------------------------------------------------------------
static NativeError storeCollectorZipMember( OfficialDownloadWorkspace	   &workspace,
										   const std::wstring_view			name,
										   const std::span<const std::byte> bytes)
{
	// 書込み長へ収まらない入力や空データを内側ZIPにしない
	if( bytes.empty() || bytes.size() > MAXDWORD) {
		return fromWin32( ERROR_BAD_LENGTH) ;
	}

	std::uint64_t freeBytes{} ;												// 同じ保護volumeの実空き容量
	const auto	  capacity = workspace.queryAvailableBytes( freeBytes) ;	// 容量観測の元診断値
	// 容量を確認できない場合は新しい一時ファイルを確保しない
	if( capacity != 0 || freeBytes < bytes.size()) {
		return capacity != 0 ? capacity : fromWin32( ERROR_DISK_FULL) ;
	}

	HANDLE	   handle{INVALID_HANDLE_VALUE} ;					// 新規ファイルを受け取る所有handle
	const auto created = workspace.createFile( name, handle) ;	// CREATE_NEWと領域登録の結果
	// 安全に作成したファイルだけへ原byteを保存する
	if( created != 0) {
		return created ;
	}

	const ArchiveFile file( handle) ;	// 検査前に同じ書込みhandleを閉じる所有者
	DWORD			  written{} ;		// 実際に書き込んだbyte数
	// 原API失敗を短い書込みと区別する
	if( !WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &written, nullptr)) {
		return fromWin32( GetLastError()) ;
	}

	return written == bytes.size() ? 0 : fromWin32( ERROR_WRITE_FAULT) ;
}

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
 *                    元の相対名をWindows区切りと原表記で指定する
 * @return 成功時0、取得、署名、選択INF、必須依存、Modelsまたは取消しの失敗時はHRESULT
 * @note 外側署名の証明書取得はcache内に限定する。EXE実行、公開、導入権限の発行は行わない
 */
//------------------------------------------------------------------------------
NativeError inspectCollectorSignedPeZipContent(
	const DriverArchiveInput &input, const std::span<const std::wstring_view> acceptedPublishers,
	const std::wstring_view zipMember, const std::wstring_view infMember,
	const OfficialInfModelsPlatform &platform, CollectorSignedPeZipContent &content,
	const std::function<bool()>						 &cancellation,
	const std::optional<CollectorPeZipRequiredImport> requiredImport)
{
	content = {} ;
	// 端末導入用途や別形式の計画を、公式Server向けの私有検査へ流用しない
	if( input.scanSessionId == 0U || input.resourceContent ||
	   input.workspaceMode != OfficialWorkspaceMode::CURRENT_USER_INSPECTION ||
	   platform.processorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
	   (platform.productType != VER_NT_SERVER &&
		platform.productType != VER_NT_DOMAIN_CONTROLLER)) {
		return E_INVALIDARG ;
	}

	try {
		const std::wstring_view requiredPath =
			requiredImport ? requiredImport->relativePath
						   : std::wstring_view{} ;	// 実閉包に要求する補助INF名
		// 同じ元配布の内側ZIP、主INFと別名の指定補助だけを選択として扱う
		if( extensionOf( zipMember) != L".zip" || extensionOf( infMember) != L".inf" ||
		   (requiredImport && (requiredPath.size() > 260U || requiredPath == infMember ||
							   extensionOf( requiredPath) != L".inf" ||
							   !isSafeOfficialArchiveMember( requiredPath, L'\\') ||
							   (requiredImport->role != CollectorPeZipImportRole::REGISTRY_ONLY &&
								requiredImport->role != CollectorPeZipImportRole::NULL_SERVICE)))) {
			return E_INVALIDARG ;
		}

		// 開始前に取消しが届いた場合は元ファイルを開かない
		if( cancellation && cancellation()) {
			return fromWin32( ERROR_CANCELLED) ;
		}

		constexpr auto MEMORY_BYTES =
			128ULL * 1024ULL * 1024ULL ;	// 外側ZIPの全展開を一時メモリーに置く上限
		constexpr OfficialZipExtractionPolicy LIMITS{
			MEMORY_BYTES, MEMORY_BYTES, MEMORY_BYTES,
			COLLECTOR_CONTENT_POLICY.zipPolicy.maximumEntryCount} ;	// 元ZIPの有限読取り条件
		const OfficialSignedExecutableSource source{input.inspectionPath, input.byteCount,
													input.sha256, acceptedPublishers,
													true} ;	// 同じ元取得と定義の許可主署名者
		std::vector<std::byte>				 memberBytes ;	// 元取得を検証して選んだ内側ZIPの原byte
		auto								 error =
			readVerifiedOfficialSignedPeZipMember( source, LIMITS, zipMember,
												  memberBytes) ;	// 元署名と内側ZIPの選択結果
		// 認証済みの元ZIPだけを保護領域へ接続する
		if( error != 0) {
			return error ;
		}

		// 外側の署名確認中に届いた取消しを内容検査前に反映する
		if( cancellation && cancellation()) {
			return fromWin32( ERROR_CANCELLED) ;
		}

		OfficialDownloadWorkspace memberWorkspace ;	// 内側ZIPだけを保持する私有一時領域
		error = memberWorkspace.initialize( L"collector-pe-zip", input.scanSessionId,
										   input.workspaceMode) ;
		constexpr std::wstring_view MEMBER_NAME = L"signed-member.zip" ;	// 原相対名と区別する内部名
		// 同じ操作の保護領域が成立した場合だけ、内側ZIPを一時保存する
		if( error == 0) {
			error = storeCollectorZipMember( memberWorkspace, MEMBER_NAME, memberBytes) ;
		}

		// 保存できない原byteを検査済み入力として発行しない
		if( error != 0) {
			return error ;
		}

		DriverArchiveInput inner{
			input.scanSessionId, memberWorkspace.path( MEMBER_NAME), memberBytes.size(), {}, {},
			input.workspaceMode} ;	// 元EXEと独立した内側の同一性
		OfficialMappedFile staged ;	// 読み戻した内側ZIPを署名元の比較から内容検査まで固定するowner
		error = staged.open( inner.inspectionPath, MEMORY_BYTES) ;
		// 保存直後に変更や差し替えが起きた場合は元署名の内容として扱わない
		if( error != 0 || !std::ranges::equal( staged.bytes(), memberBytes)) {
			return error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		// 元ZIPの読取りと共通展開のメモリーを同時に保持しない
		std::vector<std::byte>().swap( memberBytes) ;
		error = computeFileSha256( inner.inspectionPath, inner.sha256) ;
		// 固定byte数と実ハッシュがそろった入力だけを共通ZIP検査へ渡す
		if( error != 0) {
			return error ;
		}

		CollectorSignedPeZipContent verified ;	// 全検査成功時まで公開しない結果
		const std::array<std::pair<std::wstring_view, std::wstring_view>, 1U> selectors{
			std::pair<std::wstring_view, std::wstring_view>{{},
															infMember}} ;	// 内側ZIP直下から選ぶ一件
		error = inspectSelectedDriverPackages( inner, OfficialDriverArchiveFormat::ZIP, selectors,
											  verified.inner, cancellation,
											  COLLECTOR_CONTENT_POLICY, nullptr, requiredPath) ;
		// 共通閉包の全体失敗と選択結果の欠落を区別する
		if( error != 0 || verified.inner.infs.size() != 1U) {
			return error != 0 ? error : fromWin32( ERROR_INVALID_DATA) ;
		}

		const auto &selected = verified.inner.infs.front() ;	// CATと参照ファイルを検査した明示INF
		// 内容検査が未成立の閉包からServer Modelsを読まない
		if( selected.error != 0 || selected.state != CommonInfInspectionState::VERIFIED ||
		   !selected.workspace || selected.closure.packages.size() != 1U) {
			return selected.error != 0 ? selected.error : fromWin32( ERROR_INVALID_DATA) ;
		}

		const auto &package = selected.closure.packages.front() ;	// 原署名と照合した唯一の主INF
		const auto	entry =
			std::ranges::find( selected.closure.entries, package.infRelativePath,
							  &OfficialZipEntry::relativePath) ;	// 同じ閉包内の元INFと実ハッシュ
		// 選択と元名の大小文字が異なる場合も別の元INFとして扱う
		if( package.infRelativePath != infMember || entry == selected.closure.entries.end()) {
			return fromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		const auto requiredCount = requiredImport ? 1U : 0U ;	// 指定した補助の件数
		// 補助の有無と主INFの全CopyINFを版の指定件数へ固定する
		if( selected.requiredInfPackages.size() != requiredCount ||
		   package.requiredInfPaths.size() != requiredCount ||
		   !package.unresolvedCopyInfPaths.empty()) {
			return fromWin32( ERROR_INVALID_DATA) ;
		}

		// 追加する一件は主INFの元CopyINFが解決した署名済みSystem補助へ限定する
		if( requiredImport) {
			const auto &companion =
				// 同じ閉包のCAT検査済み補助
				selected.requiredInfPackages.front() ;
			const bool nullService =
				requiredImport->role ==
				CollectorPeZipImportRole::NULL_SERVICE ;	// 版別条件が指定する補助形式
			// 元ZIP名は審査した綴り、元CopyINFの解決先はWindowsのファイル名比較で確認する
			if( package.role != DriverPlanRole::BASE_DRIVER ||
			   package.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
			   companion.infRelativePath != requiredPath ||
			   CompareStringOrdinal( package.requiredInfPaths.front().c_str(), -1,
									companion.infRelativePath.c_str(), -1, TRUE) != CSTR_EQUAL ||
			   companion.inspectionPurpose !=
				   OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT ||
			   companion.requiredRegistryOnlyCompanion == nullService ||
			   companion.requiredNullCompanion != nullService ||
			   (nullService && !companion.sourceFiles.empty()) ||
			   !companion.requiredInfPaths.empty() || !companion.unresolvedCopyInfPaths.empty() ||
			   companion.unresolvedIncludeNeeds || !companion.requiredComponents.empty()) {
				return fromWin32( ERROR_INVALID_DATA) ;
			}
		}

		error = readOfficialInfPublishedIdentityForPlatform( *selected.workspace, package, platform,
															entry->sha256, verified.identity) ;
		// 指定OSのModelsが読めない場合は現在hostのModelsへ切り替えない
		if( error != 0) {
			return error ;
		}

		// すべて読めても取消しが届いていれば私有成功結果を生成しない
		if( cancellation && cancellation()) {
			return fromWin32( ERROR_CANCELLED) ;
		}

		verified.executableBytes  = input.byteCount ;
		verified.executableSha256 = input.sha256 ;
		verified.zipMember		  = zipMember ;
		verified.platform		  = platform ;
		content					  = std::move( verified) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		// 呼出側の取消し照会等の例外を私有収集workerへ漏らさない
		return E_UNEXPECTED ;
	}
}

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
NativeError inspectSelectedDeviceDriverPackages(
	const DriverArchiveInput &input, const OfficialDriverArchiveFormat format,
	std::span<const std::pair<std::wstring_view, std::wstring_view>> selectors,
	CommonDriverPackageInspection &inspection, const std::function<bool()> &cancellation)
{
	return inspectSelectedDriverPackages( input, format, selectors, inspection, cancellation,
										 DEVICE_STORAGE_POLICY) ;
}

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
NativeError inspectRetainedStorageInf( const ScanSessionId								session,
									  const std::shared_ptr<OfficialDownloadWorkspace> &workspace,
									  const OfficialDriverClosure					   &original,
									  CommonInfInspection							   &inspected)
{
	// 元WiXの一段で確定した単一閉包だけを管理者保護領域から読む
	if( session == 0U || !workspace ||
	   workspace->protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   original.archiveDepth != 1U || original.packages.size() != 1U ||
	   original.entries.size() < 3U ||
	   original.entries.size() > DEVICE_STORAGE_POLICY.maximumClosureFiles ||
	   original.expandedBytes > DEVICE_STORAGE_POLICY.maximumClosureBytes ||
	   !original.compressedSources.empty()) {
		return failInspection( inspected, E_INVALIDARG) ;
	}

	try {
		const auto &expected = original.packages.front() ;	// 元WiXの内容検査で得た単一基本INF
		// 元の役割を独立した端末検査に渡し、既存の別用途から導入候補を作らない
		if( expected.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
		   extensionOf( expected.infRelativePath) != L".inf" ||
		   std::ranges::find( original.entries, expected.infRelativePath,
							 &OfficialZipEntry::relativePath) == original.entries.end()) {
			return failInspection( inspected, fromWin32( ERROR_INVALID_DATA)) ;
		}

		std::vector<std::unique_ptr<OfficialMappedFile>> pins ;	// 再読取り・署名確認中の全ファイル
		pins.reserve( original.entries.size()) ;
		const auto lessPath = []( const std::wstring_view left, const std::wstring_view right) {
			return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
										static_cast<int>( right.size()), TRUE) == CSTR_LESS_THAN ;
		} ; // 有限な保護領域内の名前をWindowsの大文字小文字を区別しない順序で比較する
		std::set<std::wstring_view, decltype( lessPath)> members ;	// 元の一意な論理ファイル名
		std::uint64_t expandedBytes{} ;								// 同じ元閉包の各ファイルを一度ずつ合算する
		bool		  hasDriverBinary{} ;							// AMD64 SYSを実際に確認した場合true
		// 元WiXが確定した平坦な全ファイルを固定し、署名検査が終わるまで差替えを防ぐ
		for( const auto &entry : original.entries) {
			const auto path = workspace->path( entry.relativePath) ;	// 同じ管理者保護領域の元位置
			// 不明な名前、空のハッシュ、元宣言を超える展開長を再検査へ渡さない
			if( path.empty() || entry.relativePath.find( L'\\') != entry.relativePath.npos ||
			   entry.sha256.size() != 64U || entry.uncompressedSize == 0U ||
			   entry.uncompressedSize > original.expandedBytes - expandedBytes ||
			   !members.insert( entry.relativePath).second) {
				return failInspection( inspected, fromWin32( ERROR_INVALID_DATA)) ;
			}

			auto pin = std::make_unique<OfficialMappedFile>() ;	// この元ファイルの読取専用固定handle
			// 個別ファイルを読取り専用で固定した結果
			auto error = pin->open( path, DEVICE_STORAGE_POLICY.cabPolicy.maximumSingleFileBytes) ;
			// 固定した状態で元の展開長と全バイトSHA-256の両方を再確認する
			if( error == 0) {
				error = verifyOfficialFileMetadata( path, {entry.uncompressedSize, entry.sha256}) ;
			}

			// 各SYSの元バイトと現在のx64実行形式を同じhandleの間に確認する
			if( error == 0 && extensionOf( entry.relativePath) == L".sys") {
				error			= verifyAmd64PeFile( path) ;
				hasDriverBinary = true ;
			}

			// 改変、参照不足、アーキテクチャ不一致の元診断を保持する
			if( error != 0) {
				return failInspection( inspected, error) ;
			}

			expandedBytes += entry.uncompressedSize ;
			pins.push_back( std::move( pin)) ;
		}

		// 元の全展開長とAMD64ドライバーが両方成立した閉包だけを読む
		if( expandedBytes != original.expandedBytes || !hasDriverBinary) {
			return failInspection( inspected, fromWin32( ERROR_INVALID_DATA)) ;
		}

		OfficialInfPackage actual ;	// 同じ元バイトから端末用ポリシーで読み直す基本INF
		const auto		   error =
			inspectOfficialInfPackage( *workspace, original.entries, expected.infRelativePath,
									  DEVICE_STORAGE_POLICY.infPolicy, actual) ;	// 端末用の元診断
		// 収集側の元合格で端末ポリシーの拒否を補わない
		if( error != 0) {
			return failInspection( inspected, error) ;
		}

		// 元のINF・CAT・全参照と同じ単一SCSI基本役割だけを後続へ渡す
		if( actual.inspectionPurpose != OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ||
		   actual.role != DriverPlanRole::BASE_DRIVER ||
		   CompareStringOrdinal( actual.className.c_str(), -1, L"SCSIAdapter", -1, TRUE) !=
			   CSTR_EQUAL ||
		   actual.infRelativePath != expected.infRelativePath ||
		   actual.catalogRelativePath != expected.catalogRelativePath ||
		   actual.className != expected.className || actual.classGuid != expected.classGuid ||
		   actual.providerName != expected.providerName ||
		   actual.driverDate != expected.driverDate ||
		   actual.driverVersion != expected.driverVersion ||
		   actual.hardwareIds != expected.hardwareIds ||
		   actual.sourceFiles != expected.sourceFiles || actual.hasExternalDependencies ||
		   actual.unresolvedIncludeNeeds || !actual.requiredInfPaths.empty() ||
		   !actual.unresolvedCopyInfPaths.empty() || !actual.requiredComponents.empty() ||
		   actual.hasUnassessedProgramReferences ||
		   original.entries.size() != actual.sourceFiles.size() + 2U ||
		   members.erase( actual.infRelativePath) != 1U ||
		   members.erase( actual.catalogRelativePath) != 1U) {
			return failInspection( inspected, fromWin32( ERROR_INVALID_DATA)) ;
		}

		// 残った元ファイルを署名付きINFの参照と一対一に照合する
		for( const auto &source : actual.sourceFiles) {
			// INF・CATとの役割重複や関係のない元ファイルを受け入れない
			if( members.erase( source) != 1U) {
				return failInspection( inspected, fromWin32( ERROR_INVALID_DATA)) ;
			}
		}

		const auto signature =
			// 同じCATと全メンバー
			verifyWindowsInfPackageIntegrity( *workspace, actual) ;
		// 元バイトが一致しても現在のWindows署名条件が成立しなければ渡さない
		if( signature != 0) {
			return failInspection( inspected, signature) ;
		}

		CommonInfInspection result ;	// 同じファイルの再解析と署名確認が成立した端末用の結果
		result.scanSessionId		 = session ;
		result.infRelativePath		 = actual.infRelativePath ;
		result.workspace			 = workspace ;
		result.closure.entries		 = original.entries ;
		result.closure.archiveDepth	 = original.archiveDepth ;
		result.closure.expandedBytes = expandedBytes ;
		result.closure.packages.push_back( std::move( actual)) ;
		result.state = CommonInfInspectionState::VERIFIED ;
		inspected	 = std::move( result) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return failInspection( inspected, E_OUTOFMEMORY) ;
	}
}

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
NativeError inspectSelectedCommonDriverPackage( const DriverArchiveInput		 &input,
											   OfficialDriverArchiveFormat	  format,
											   std::wstring_view			  selectedInf,
											   CommonDriverPackageInspection &inspection,
											   const std::function<bool()>	 &cancellation,
											   std::wstring_view			  nestedArchive)
{
	const std::array selectors{std::pair{nestedArchive, selectedInf}} ;	// 元一件だけの選択です
	return inspectSelectedCommonDriverPackages( input, format, selectors, inspection, cancellation) ;
}

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
NativeError inspectCommonDriverPackage( const DriverArchiveInput			&input,
									   const OfficialDriverArchiveFormat format,
									   CommonDriverPackageInspection	&inspection,
									   const std::function<bool()>		&cancellation)
{
	inspection = {} ;
	// 共通入口の固定上限と形式を個別parserへ渡す前に確認する
	if( input.scanSessionId == 0 || input.byteCount == 0 || input.byteCount > INPUT_BYTES ||
	   (format != OfficialDriverArchiveFormat::ZIP &&
		format != OfficialDriverArchiveFormat::CABINET &&
		format != OfficialDriverArchiveFormat::SEVEN_ZIP_SFX &&
		format != OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER)) {
		return failInspection( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	}

	try {
		inspection.scanSessionId = input.scanSessionId ;
		inspection.archiveSha256 = input.sha256 ;
		inspection.archiveBytes	 = input.byteCount ;
		std::vector<std::wstring> jobs( 1U) ;	// 最初は直下、その後は最大16の一段nested
		// 外側を先に確認し、一段内側の各archiveまでを有限回検査する
		for( std::size_t jobIndex = 0; jobIndex < jobs.size(); ++jobIndex) {
			// 取消しでは既に合格した閉包も破棄する
			if( cancellation && cancellation()) {
				return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
			}

			const std::wstring nested = jobs[jobIndex] ;	// Job追加によるvector再配置と独立したpath
			OfficialDriverArchiveInventory inventory ;		// 今回の有限inventory
			const NativeError			   error = inspectDriverArchiveInventory(
				 {&input, format, nested}, POLICY, inventory) ;	// 全entryと元入力hashの検査
			// 未知EXEからdriverを推測せず、他の通常INF/既知containerの検査を続けます
			if( error != 0 && !nested.empty() && extensionOf( nested) == L".exe" &&
			   error != static_cast<NativeError>( E_OUTOFMEMORY)) {
				continue ;
			}

			// Archive全体の破損を個別INF拒否へ縮小しない
			if( error != 0) {
				return failInspection( inspection, error) ;
			}

			// 入れ子を含めたinventory総数も有限に保つ
			if( inventory.entries.size() > 4096U - inspection.inventoryFileCount) {
				return failInspection( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
			}

			inspection.inventoryFileCount += inventory.entries.size() ;
			// Inventory順を維持し、未参照の別用途fileは閉包へ含めない
			for( const OfficialZipEntry &entry : inventory.entries) {
				const std::wstring extension = extensionOf( entry.relativePath) ;	// 静的形式の選択
				// 外側で確認したZIP／CAB／SFX候補だけを一段nested処理へ登録する
				if( jobIndex == 0 &&
				   (extension == L".zip" || extension == L".cab" || extension == L".exe")) {
					// 未検査archiveを黙って飛ばさず、全体上限として拒否する
					if( jobs.size() >= NESTED_COUNT + 1U) {
						return failInspection( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
					}

					jobs.push_back( entry.relativePath) ;
				}

				// INF以外のentryをdriver候補として解釈しない
				if( extension != L".inf") {
					continue ;
				}

				// 一部のINFだけを検査して全体完了としない
				if( inspection.infs.size() >= INF_COUNT) {
					return failInspection( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
				}

				// 各INF間でも取消しを確認する
				if( cancellation && cancellation()) {
					return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
				}

				CommonInfInspection inspected ;	// 現在INFの個別結果
				auto remainingPolicy = POLICY ;	// 前の閉包を残したまま新規分を無制限に保持しません
				remainingPolicy.maximumClosureBytes = EXPANDED_BYTES - inspection.retainedBytes ;
				inspectOneInf( input, format, nested, entry.relativePath, inspection.infs.size(),
							  inspected, {}, nullptr, remainingPolicy) ;
				// 全体resource失敗を個別の内容不適合とみなさない
				if( inspected.error == static_cast<NativeError>( E_OUTOFMEMORY)) {
					return failInspection( inspection, inspected.error) ;
				}

				// 成功閉包の累積保持量を上限以内に保つ
				if( inspected.closure.expandedBytes > EXPANDED_BYTES - inspection.retainedBytes) {
					return failInspection( inspection, fromWin32( ERROR_FILE_TOO_LARGE)) ;
				}

				inspection.retainedBytes += inspected.closure.expandedBytes ;
				inspection.infs.push_back( std::move( inspected)) ;
			}
		}

		// 最後の同期API実行中に届いた取消しを反映する
		if( cancellation && cancellation()) {
			return failInspection( inspection, fromWin32( ERROR_CANCELLED)) ;
		}

		const NativeError finalIdentityError = verifyOfficialFileMetadata(
			input.inspectionPath, {input.byteCount, input.sha256}) ;	// 公開直前の外側入力再照合
		// 最後の署名検証中に入力が変わった場合も部分合格を破棄する
		if( finalIdentityError != 0) {
			return failInspection( inspection, finalIdentityError) ;
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		return failInspection( inspection, static_cast<NativeError>( E_OUTOFMEMORY)) ;
	} catch( const std::length_error &) {
		return failInspection( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	} catch( ...) {
		// 外部取消しcallback等の例外をworker境界から漏らさない
		return failInspection( inspection, static_cast<NativeError>( E_UNEXPECTED)) ;
	}
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 通常と研究入口が共有する元有限loopを実行する
 * @param[in] input 元固定archive
 * @param[in] format 既存非実行形式
 * @param[out] inspection 元判定と通常row
 * @param[in] cancellation 元取消し契約
 * @param[in,out] collector 研究compileだけのstack借用。Nullなら観測しない
 * @return 元有限判定のHRESULT。計測失敗は元判定へ反映しない
 */
//------------------------------------------------------------------------------
NativeError inspectMaintenanceDriverPackageImpl( const DriverArchiveInput		   &input,
												const OfficialDriverArchiveFormat	format,
												MaintenanceDriverPackageInspection &inspection,
												const std::function<bool()>		   &cancellation
// 通常compileへobserver引数・callback・storeを導入しない
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
												,
												ReachedReferenceCollector *collector
#endif
)
{
	inspection = {} ;
	// 個別parserの前に従来と同じ全体予算と非実行形式を要求する
	if( input.scanSessionId == 0 || input.byteCount == 0 || input.byteCount > INPUT_BYTES ||
	   (format != OfficialDriverArchiveFormat::ZIP &&
		format != OfficialDriverArchiveFormat::CABINET &&
		format != OfficialDriverArchiveFormat::SEVEN_ZIP_SFX &&
		format != OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER)) {
		return failMaintenance( inspection, static_cast<NativeError>( E_INVALIDARG)) ;
	}

	try {
		inspection.scanSessionId = input.scanSessionId ;
		inspection.archiveSha256 = input.sha256 ;
		inspection.archiveBytes	 = input.byteCount ;
		std::vector<std::wstring> jobs( 1U) ;	// 直下と最大16件の一段nested
		// 全inventoryを有限列挙し、未検査部分を成功として隠さない
		for( std::size_t index = 0; index < jobs.size(); ++index) {
			// 取消し時は部分合格も破棄する
			if( cancellation && cancellation()) {
				return failMaintenance( inspection, fromWin32( ERROR_CANCELLED)) ;
			}

			const std::wstring			   nested = jobs[index] ;	// Vector追加と独立した借用元
			OfficialDriverArchiveInventory inventory ;				// 今回の全通常file
			NativeError					   error =
				inspectDriverArchiveInventory( {&input, format, nested}, CONTENT_POLICY,
											  inventory) ;	// 元hash・path・展開量を検証する
			// 全体破損や総file上限を個別driverの不適合にしない
			if( error != 0 || inventory.entries.size() > 4096U - inspection.inventoryFileCount) {
				return failMaintenance( inspection,
									   error != 0 ? error : fromWin32( ERROR_BUFFER_OVERFLOW)) ;
			}

			inspection.inventoryFileCount += inventory.entries.size() ;
			// 一段nestedと全INFをarchive順で検査する
			for( const OfficialZipEntry &entry : inventory.entries) {
				const std::wstring extension =
					// 非実行の形式選択
					extensionOf( entry.relativePath) ;
				// 外側で確認した非実行archiveだけを一段処理へ登録する
				if( index == 0 && (extension == L".zip" || extension == L".cab")) {
					// 上限を超えた場合に残りを黙って無視しない
					if( jobs.size() >= NESTED_COUNT + 1U) {
						return failMaintenance( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
					}

					jobs.push_back( entry.relativePath) ;
				}

				// 実行形式やその他fileをINFとして解釈しない
				if( extension != L".inf") {
					continue ;
				}

				// 全INF上限では部分結果を破棄する
				if( inspection.infs.size() >= INF_COUNT) {
					return failMaintenance( inspection, fromWin32( ERROR_BUFFER_OVERFLOW)) ;
				}

				// 各署名APIの間でも取消しを反映する
				if( cancellation && cancellation()) {
					return failMaintenance( inspection, fromWin32( ERROR_CANCELLED)) ;
				}

				MaintenanceInfInspection result ;	// 個別失敗も保持する四軸観測
				inspectMaintenanceInf( input, format, nested, entry.relativePath,
									  inspection.infs.size(), result
// 研究compileだけで同scopeの具体的collectorを明示的に渡す
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
									  ,
									  collector
#endif
				) ;
				// Resource失敗や全閉包の累積展開上限を内容不正に縮小しない
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

		// 最後のAPI呼出し中の取消しも部分合格を残さない
		if( cancellation && cancellation()) {
			return failMaintenance( inspection, fromWin32( ERROR_CANCELLED)) ;
		}

		const NativeError identityError = verifyOfficialFileMetadata(
			input.inspectionPath, {input.byteCount, input.sha256}) ;	// 公開直前の外側実byte照合
		// 元archive変化を旧内容合格で隠さない
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
		// Callback等の例外をworker境界へ漏らさず、診断値を残す
		return failMaintenance( inspection, static_cast<NativeError>( E_UNEXPECTED)) ;
	}
}
} // namespace

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
NativeError inspectMaintenanceDriverPackage( const DriverArchiveInput		   &input,
											const OfficialDriverArchiveFormat	format,
											MaintenanceDriverPackageInspection &inspection,
											const std::function<bool()>		   &cancellation)
{
	return inspectMaintenanceDriverPackageImpl( input, format, inspection, cancellation
// 研究target内の従来呼出しでも観測の有無を明示し、通常引数は保持する
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
											   ,
											   nullptr
#endif
	) ;
}

// 通常platformの公開API・DTOを変更せず、研究EXE内だけの入口を定義する
#if defined( DRIVERCRATE_REACHED_REFERENCE_RESEARCH)
//------------------------------------------------------------------------------
/**
 * @brief 研究専用compile内だけで元loopとstack collectorを接続する
 * @param[in] input 固定済み元archive
 * @param[in] format ZIPまたはCAB
 * @param[out] inspection 既存通常row。元失敗では空
 * @param[in,out] collector この同期呼出しだけの未使用所有者
 * @param[in] cancellation 既存と同じ取消し契約
 * @return 元判定のHRESULT。独立計測失敗はcollector.errorに分離する
 */
//------------------------------------------------------------------------------
NativeError inspectReachedMaintenanceDriverPackage( const DriverArchiveInput			  &input,
												   const OfficialDriverArchiveFormat   format,
												   MaintenanceDriverPackageInspection &inspection,
												   ReachedReferenceCollector		  &collector,
												   const std::function<bool()>		  &cancellation)
{
	const NativeError error = inspectMaintenanceDriverPackageImpl(
		input, format, inspection, cancellation, &collector) ;	// 元loopを一回だけ実行する
	collector.finish( inspection) ;
	return error ;
}
#endif

//------------------------------------------------------------------------------
/**
 * @brief 成功閉包の全file、metadata、署名を同一policyで再検証する
 * @param[in] inspected 保護領域を保持するVERIFIED結果
 * @param[in] allowDeclarativeClass 独自クラスの内容を再検査する端末の読み取り経路でtrue
 * @return 全fileのsize／hash、INF metadata、Windows署名一致時0、それ以外はHRESULT
 * @note 導入許可やdevice bindingの検査を代替しない。Workerから呼ぶ
 */
//------------------------------------------------------------------------------
static NativeError reverifyDriverInf( const CommonInfInspection &inspected,
									 bool						allowDeclarativeClass)
{
	// 合格閉包を所有していない値を再検証へ渡さない
	if( inspected.scanSessionId == 0 || inspected.state != CommonInfInspectionState::VERIFIED ||
	   inspected.error != 0 || !inspected.workspace || inspected.closure.packages.size() != 1U ||
	   inspected.closure.entries.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 非実行内容のDTOを通常型へ手動複写しても、元用途から導入資格を発行しません
	const auto purpose = inspected.closure.packages.front().inspectionPurpose ;	// 原基本INFの用途
	// 正式ストレージの端末用途を示す
	const bool storage = purpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
	// 読み取り入口だけで許容する独自クラスの内容用途を示す
	const bool declarative =
		allowDeclarativeClass && purpose == OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ;
	// 非権限用途とADMIN原byteの組を保ち、collector手製DTOを拒否します
	if( inspected.closure.packages.front().requiredRegistryOnlyCompanion ||
	   ((storage || declarative) &&
		inspected.workspace->protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR) ||
	   (!storage && !declarative && purpose != OfficialInfInspectionPurpose::STANDARD_DRIVER) ||
	   std::ranges::any_of( inspected.requiredInfPackages, [storage]( const auto &package) {
		   return package.requiredRegistryOnlyCompanion ||
				  (storage ? package.inspectionPurpose !=
								 OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT
						   : package.inspectionPurpose !=
									 OfficialInfInspectionPurpose::STANDARD_DRIVER ||
								 package.requiredNullCompanion) ;
	   })) {
		return fromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 取得時の全fileをsizeとhashへ照合し、差替えを最初に検出する
	for( const OfficialZipEntry &entry : inspected.closure.entries) {
		const NativeError error = verifyOfficialFileMetadata(
			inspected.workspace->path( entry.relativePath),
			{entry.uncompressedSize, entry.sha256}) ;	// 個別fileの不変性検査
		// 一つでも変更があれば署名や導入へ進めない
		if( error != 0) {
			return error ;
		}
	}

	// 同同期呼出しだけ元所有者を借り、baseと全必要役割を同じpolicyで再解析します
	const auto verifyPackage = [&]( const OfficialInfPackage &expected) {
		OfficialInfPackage actual ;	// 現在byteから再解析した元metadataです
		auto			   policy = storage || declarative ? DEVICE_STORAGE_POLICY.infPolicy
														   : ARCHIVE_INF_POLICY ;	// 同原用途の独立copyです
		std::wstring	   importedClass ;											// 同元再読取から得る内容importのClassです
		std::array<std::wstring_view, 1U> importedClasses{} ;						// このcallだけの借用です
		// rootのClass policyを変えず、同元import内容だけをWindows readerへ再結合します
		if( expected.infRelativePath != inspected.closure.packages.front().infRelativePath) {
			const auto classError =
				readOfficialInfImportClass( *inspected.workspace, expected.infRelativePath,
										   importedClass) ;	// 元Class/GUIDの再読取です
			// 不明/不正/既知Firmwareを旧metadataから受理しません
			if( classError != 0) {
				return classError ;
			}

			importedClasses.front() = importedClass ;
			policy.acceptedClasses	= importedClasses ;
			// 元root用途に合わせて正式storage用または通常のimportを再検査する
			if( storage || declarative) {
				policy.purpose = storage ? OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT
										 : OfficialInfInspectionPurpose::STANDARD_DRIVER ;
			}
		}

		// 元役割packageの再解析診断です
		const NativeError error =
			inspectOfficialInfPackage( *inspected.workspace, inspected.closure.entries,
									  expected.infRelativePath, policy, actual) ;
		// 再解析失敗を同じ内容へ補正しません
		if( error != 0) {
			return error ;
		}

		// 版/ID/fileだけでなく元必要関係と役割identityも不変であることを要求します
		if( actual.infRelativePath != expected.infRelativePath ||
		   actual.catalogRelativePath != expected.catalogRelativePath ||
		   actual.className != expected.className || actual.providerName != expected.providerName ||
		   actual.driverDate != expected.driverDate ||
		   actual.driverVersion != expected.driverVersion ||
		   actual.hardwareIds != expected.hardwareIds ||
		   actual.sourceFiles != expected.sourceFiles ||
		   actual.nativePortsPage != expected.nativePortsPage ||
		   actual.hasExternalDependencies != expected.hasExternalDependencies ||
		   actual.role != expected.role || actual.classGuid != expected.classGuid ||
		   actual.extensionId != expected.extensionId ||
		   actual.selectedInstallSection != expected.selectedInstallSection ||
		   actual.selectedBasicSection != expected.selectedBasicSection ||
		   actual.selectedNativeRank != expected.selectedNativeRank ||
		   actual.requiredInfPaths != expected.requiredInfPaths ||
		   actual.unresolvedCopyInfPaths != expected.unresolvedCopyInfPaths ||
		   actual.activeRequiredInfPaths != expected.activeRequiredInfPaths ||
		   actual.requiredComponents != expected.requiredComponents ||
		   actual.unresolvedIncludeNeeds != expected.unresolvedIncludeNeeds ||
		   actual.hasUnassessedProgramReferences != expected.hasUnassessedProgramReferences ||
		   actual.inspectionPurpose != expected.inspectionPurpose ||
		   actual.requiredNullCompanion != expected.requiredNullCompanion ||
		   actual.requiredRegistryOnlyCompanion != expected.requiredRegistryOnlyCompanion) {
			return fromWin32( ERROR_RETRY) ;
		}

		return verifyWindowsInfPackageIntegrity( *inspected.workspace, actual) ;
	} ;
	const auto baseError =
		// 元基本INFの再確認です
		verifyPackage( inspected.closure.packages.front()) ;
	// 基本INF失敗後に追加役割だけを成功へ返しません
	if( baseError != 0) {
		return baseError ;
	}

	// 追加役割の全CATと全memberも毎回再確認します
	for( const auto &package : inspected.requiredInfPackages) {
		const auto error = verifyPackage( package) ;	// 原CATの独立診断です
		// 後続成功で追加役割の失敗を消しません
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 導入候補の成功閉包を元ファイル・INF・署名から再検証する
 * @param[in] inspected 保護領域を保持するVERIFIED結果
 * @return 既存の導入対象用途で元検査と一致した場合0、それ以外はHRESULT
 * @note 導入の同意や端末照合は別に確認する
 */
//------------------------------------------------------------------------------
NativeError reverifyCommonDriverInf( const CommonInfInspection &inspected)
{
	return reverifyDriverInf( inspected, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 端末の読み取り経路で成功閉包を元ファイル・INF・署名から再検証する
 * @param[in] inspected 管理領域で検査した元閉包または既存の標準検査結果
 * @return 元用途と全ファイルの内容・署名が一致した場合0、それ以外はHRESULT
 * @note この確認だけでは独自クラスの導入資格を発行しない
 */
//------------------------------------------------------------------------------
NativeError reverifyCommonDriverInfContent( const CommonInfInspection &inspected)
{
	return reverifyDriverInf( inspected, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非秘密の役割件数だけを返します
 * @param[in] role 観測する追加役割です
 * @return 一計画内0～7の確認済みmember数です
 */
//------------------------------------------------------------------------------
std::size_t RequiredDriverComponentPlan::count( const DriverPlanRole role) const noexcept
{
	return static_cast<std::size_t>( std::ranges::count_if(
		members_, [role]( const auto &member) { return member.role == role ; })) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実検査した元基本INF閉包から必要役割の関係を構築します
 * @param[in] inspected 元保護byteと全署名を保持する同workerの内容検査です
 * @param[in] selectedPackages baseと全importの元順copyです。選択機能関係は私有native nodeから解析します
 * @param[out] plan 成功時だけ元閉包へ結合した不変計画です。失敗時は空です
 * @param[out] diagnostic 任意の数値診断です。nullなら採取せず合否へ使用しません
 * @param[in] registeredDeviceRead 自動起動ストレージの同じ選択機器を同期読取する操作。指定しない場合はnull
 * @return 内容と関係の一意な確認0、未対応・欠損・曖昧・循環は元HRESULTです
 * @note 計画は内容関係だけで、同意・復旧・PnP・私有install bindingを代替しません
 */
//------------------------------------------------------------------------------
NativeError makeRequiredDriverComponentPlan(
	const CommonInfInspection &inspected, std::span<const OfficialInfPackage> selectedPackages,
	std::shared_ptr<const RequiredDriverComponentPlan> &plan,
	RequiredInfBindingDiagnostic					   *diagnostic,
	const StorageRegisteredDeviceRead				   *registeredDeviceRead)
{
	const auto rejected = [diagnostic]( const NativeError error, const InfBindingReject reason,
									   const std::uint32_t observed = 0U) {
		return diagnostic ? diagnostic->reject( error, reason, observed) : error ;
	} ; // 同呼出しの原拒否だけです

	plan.reset() ;
	const auto contentError =
		// 元byte/CATを構築直前に確認します
		reverifyCommonDriverInf( inspected) ;
	// 公開DTOや未検査の構造を必要関係の成功にしません
	if( contentError != 0 || inspected.requiredInfPackages.size() > 7U ||
	   selectedPackages.size() != inspected.requiredInfPackages.size() + 1U ||
	   selectedPackages.front().selectedInstallSection.empty()) {
		return rejected( contentError != 0 ? contentError : fromWin32( ERROR_NOT_SUPPORTED),
						InfBindingReject::PLAN_INPUT) ;
	}

	const auto &base = inspected.closure.packages.front() ;	// 既存一基本INFの元metadataです
	// 同元用途が端末storage専用であるという非権限分類です
	const bool	storage =
		base.inspectionPurpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
	// 独立したExtension/SoftwareComponentを基本候補へ変換しません
	if( base.role != DriverPlanRole::BASE_DRIVER) {
		return rejected( fromWin32( ERROR_NOT_SUPPORTED), InfBindingReject::BASE_ROLE,
						static_cast<std::uint32_t>( base.role)) ;
	}

	try {
		auto made = std::make_shared<
			RequiredDriverComponentPlan>() ;	// private memberは本factoryだけが設定します
		made->session_	= inspected.scanSessionId ;
		made->basePath_ = base.infRelativePath ;
		made->selectedPackages_.assign( selectedPackages.begin(), selectedPackages.end()) ;
		std::vector<const OfficialInfPackage *> packages ;	// 同同期選択copyだけを借用します
		// 全importの元順を維持し、必要機能と元内容identityを別に照合します
		for( std::size_t index = 0U; index < selectedPackages.size(); ++index) {
			const auto &package = selectedPackages[index] ;	// 選択関係を補足した元copyです
			const auto &original =
				index ? inspected.requiredInfPackages[index - 1U] : base ;	// 元署名所有者です
			// 選択解析を別INF/別role/別原参照の内容へ転用しません
			if( package.infRelativePath != original.infRelativePath ||
			   package.catalogRelativePath != original.catalogRelativePath ||
			   package.className != original.className || package.classGuid != original.classGuid ||
			   package.role != original.role || package.extensionId != original.extensionId ||
			   package.hardwareIds != original.hardwareIds ||
			   package.sourceFiles != original.sourceFiles ||
			   package.nativePortsPage != original.nativePortsPage ||
			   package.driverVersion != original.driverVersion ||
			   package.driverDate != original.driverDate ||
			   package.providerName != original.providerName ||
			   package.requiredInfPaths != original.requiredInfPaths ||
			   package.unresolvedCopyInfPaths != original.unresolvedCopyInfPaths ||
			   package.hasExternalDependencies != original.hasExternalDependencies ||
			   package.unresolvedIncludeNeeds != original.unresolvedIncludeNeeds ||
			   package.hasUnassessedProgramReferences != original.hasUnassessedProgramReferences ||
			   package.inspectionPurpose != original.inspectionPurpose ||
			   package.requiredNullCompanion != original.requiredNullCompanion ||
			   package.requiredRegistryOnlyCompanion != original.requiredRegistryOnlyCompanion) {
				return fromWin32( ERROR_RETRY) ;
			}

			packages.push_back( &package) ;
		}

		std::vector<bool> functional(
			// 選択DDInstallの到達だけを必要機能にします
			packages.size()) ;
		std::vector<bool>		 activeImports( packages.size()) ;	// 実選択CopyINFの到達だけです
		std::vector<std::size_t> queue{0U} ;						// 最大八package、一度だけ追加する有限走査です
		functional[0]	 = true ;
		activeImports[0] = true ;
		// 選択baseからactive CopyINFを辿り、全importとは独立した実行集合を作ります
		for( std::size_t position = 0U; position < queue.size(); ++position) {
			const auto index = queue[position] ;	// 同選択copyの元ordinalです
			// 当該deviceの実選択節に明示された参照だけを必要機能へ結合します
			for( const auto &path : packages[index]->activeRequiredInfPaths) {
				const auto found = std::ranges::find_if( packages, [&]( const auto value) {
					return CompareStringOrdinal( value->infRelativePath.c_str(), -1, path.c_str(),
												-1, TRUE) == CSTR_EQUAL ;
				}) ; // 同保護閉包だけを借用します
				// 原importの不在を選択基本INFだけの成功へ変換しません
				if( found == packages.end()) {
					return rejected( fromWin32( ERROR_NOT_SUPPORTED),
									InfBindingReject::COPY_INF_MISSING) ;
				}

				// 元required importの0起点位置です
				const auto importOrdinal	 = static_cast<std::size_t>( found - packages.begin()) ;
				activeImports[importOrdinal] = true ;
				// 独立baseはWindows CopyINF用のstage内容です。別deviceの導入memberを作りません
				if( (*found)->role == DriverPlanRole::BASE_DRIVER) {
					continue ;
				}

				const auto child =
					// 有限元ordinalです
					static_cast<std::size_t>( found - packages.begin()) ;
				// 共有参照を重複実行せず、後段の全import graphで循環を確認します
				if( !functional[child]) {
					functional[child] = true ;
					queue.push_back( child) ;
				}
			}
		}

		std::vector<std::vector<std::size_t>> edges(
			// 原明示CopyINFの有限graphです
			packages.size()) ;
		std::vector<bool> componentsUsed( packages.size()) ;	// 必要子の一意な関係だけを記録します
		std::vector<std::wstring> extensions ;					// 同ExtensionIdの競合を検出するworker内集合です
		// 全元宣言を一意な同保護閉包へ結合します
		for( std::size_t index = 0U; index < packages.size(); ++index) {
			const auto &package = *packages[index] ;	// 一つの実検査済み元packageです
			// storageの全importは内容成功だけで作用を許可せず、元roleを分類します
			if( storage && index != 0U && package.role == DriverPlanRole::BASE_DRIVER) {
				// 未分類base importを限定nullの登録資格へ変換しません
				if( !package.requiredNullCompanion || package.requiredRegistryOnlyCompanion ||
				   package.inspectionPurpose !=
					   OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT ||
				   !package.sourceFiles.empty() || !package.requiredInfPaths.empty()) {
					return rejected( fromWin32( ERROR_NOT_SUPPORTED),
									InfBindingReject::FUNCTIONAL_ROLE) ;
				}

				// 全潜在importの内容検査と、実選択枝だけのOS登録集合を分けます
				if( activeImports[index]) {
					made->stageOnlyImportOrdinals_.push_back( index - 1U) ;
				}
			}

			// SYSTEM/PACKAGEの未確認Include/Needsと未知の明示必要関係を消しません
			if( (functional[index] && index != 0U && package.role == DriverPlanRole::BASE_DRIVER) ||
			   (functional[index] && package.role == DriverPlanRole::DRIVER_COMPONENT &&
				(!package.requiredComponents.empty() || !package.activeRequiredInfPaths.empty()))) {
				return rejected( fromWin32( ERROR_NOT_SUPPORTED), InfBindingReject::FUNCTIONAL_ROLE,
								static_cast<std::uint32_t>( package.role)) ;
			}

			// 元未評価作用flagは保持し、Windows-only計画の実選択scopeを別に検査します
			if( functional[index] &&
			   (package.hasUnassessedProgramReferences || (storage && index == 0U))) {
				const auto scopeError = inspectSelectedWindowsDriverPackageScope(
					*inspected.workspace, inspected.closure.entries, package,
					diagnostic) ;	// 全内容再検証後の原scopeです
				// 同元コピー/service/softwareへ結合しないprogramを通常driverへ追加しません
				if( scopeError != 0) {
					return rejected( scopeError, InfBindingReject::WINDOWS_COPY) ;
				}
			}

			// 全節の観測flagを消さず、未解決Include/Needsだけを独立した元依存へ解決します
			if( functional[index] && (package.unresolvedIncludeNeeds || (storage && index == 0U))) {
				InfDependencyNativeResult dependency ;	// 同元byteの非実行graphです
				const auto				  error = CommonInfNativeAccess::inspect(
					   inspected, package, dependency, diagnostic,
					   index == 0U ? registeredDeviceRead
											   : nullptr) ;	// 元基本選択への同期読取だけを渡す
				// 未観測・未充足・曖昧・cycle・署名拒否を成功へ補正しません
				if( error != 0) {
					return rejected( error, InfBindingReject::DEPENDENCY,
									diagnostic ? diagnostic->stage : 0U) ;
				}

				const auto &graph = dependency.dependency ;	// 同実選択seedからの元graphです
				// 元graphの完全解決とroot証拠を失った件数を充足根拠へ使用しません
				if( !graph.plan.referencesResolved || !graph.plan.rootEvidenceVerified ||
				   graph.edges.size() > 4096U) {
					return fromWin32( ERROR_INVALID_DATA) ;
				}

				std::size_t verifiedNeeds{} ;	// 一graph最大4096の実Needsだけです
				// 実選択節から到達し署名・由来・効果を確認したNeedsを数えます
				for( const auto &edge : graph.edges) {
					// Includeだけの宣言を実行前提へ投影しません
					if( edge.directive != InfDependencyDirective::NEEDS) {
						continue ;
					}

					// 未解決の参照を件数だけで充足へ変えません
					if( (edge.state != InfDependencyState::RESOLVED_PACKAGE &&
						edge.state != InfDependencyState::RESOLVED_SYSTEM) ||
					   edge.reason != InfDependencyReason::NONE || edge.targetIdentity == 0U) {
						return fromWin32( ERROR_INVALID_DATA) ;
					}

					++verifiedNeeds ;
				}

				// 八つの元packageと各4096辺の既存上限を累積前に保ちます
				if( made->verifiedNeedsEdgeCount_ > 32768U ||
				   verifiedNeeds > 32768U - made->verifiedNeedsEdgeCount_) {
					return fromWin32( ERROR_FILE_TOO_LARGE) ;
				}

				made->verifiedNeedsEdgeCount_ += verifiedNeeds ;
				made->dependencyFiles_.insert( made->dependencyFiles_.end(),
											  dependency.fixedFiles.begin(),
											  dependency.fixedFiles.end()) ;
				made->systemFiles_.insert( made->systemFiles_.end(), dependency.systemFiles.begin(),
										  dependency.systemFiles.end()) ;
				made->systemEffects_.insert( made->systemEffects_.end(),
											dependency.systemEffects.begin(),
											dependency.systemEffects.end()) ;
				made->systemServices_.insert( made->systemServices_.end(),
											 dependency.systemServices.begin(),
											 dependency.systemServices.end()) ;
				// 選択した親デバイスの観測を子や別クラスのフィルター置換へ流用しません
				if( dependency.replacesWifiBusUpperFilters) {
					// 元Net基本の作用だけを選択端末への再照合へ送ります
					if( index != 0U || package.role != DriverPlanRole::BASE_DRIVER ||
					   CompareStringOrdinal( package.className.c_str(), -1, L"Net", -1, TRUE) !=
						   CSTR_EQUAL) {
						return rejected( fromWin32( ERROR_NOT_SUPPORTED),
										InfBindingReject::FUNCTIONAL_ROLE) ;
					}

					made->replacesWifiBusUpperFilters_ = true ;
				}

				made->delayedRegistration_ =
					made->delayedRegistration_ || dependency.delayedRegistration ;
				// 同元storage全作用を通常SYSTEM結果と別の非権限値へ保持します
				if( storage && index == 0U) {
					// 全storage作用が欠けた計画を元内容成功だけで発行しません
					if( !dependency.storageEffects) {
						return rejected( fromWin32( ERROR_NOT_SUPPORTED),
										InfBindingReject::DEPENDENCY) ;
					}

					made->storageEffects_ = std::move( dependency.storageEffects) ;
				}
			}

			// 同ExtensionIdの複数memberを独自の全導入へ変換しません
			if( package.role == DriverPlanRole::EXTENSION) {
				// 大小文字の異なる同GUIDも競合として保留します
				if( std::ranges::any_of( extensions, [&]( const auto &value) {
					   return CompareStringOrdinal( value.c_str(), -1, package.extensionId.c_str(),
												   -1, TRUE) == CSTR_EQUAL ;
				   })) {
					return fromWin32( ERROR_DUP_NAME) ;
				}

				extensions.push_back( package.extensionId) ;
			}

			// 原CopyINFの各辺を完全path一致で解決し、名称からroleを作りません
			for( const auto &path : package.requiredInfPaths) {
				const auto found = std::ranges::find_if( packages, [&]( const auto value) {
					return CompareStringOrdinal( value->infRelativePath.c_str(), -1, path.c_str(),
												-1, TRUE) == CSTR_EQUAL ;
				}) ; // 同実閉包だけの参照です
				// 未解決参照を一基本INFの成功へ換算しません
				if( found == packages.end()) {
					return fromWin32( ERROR_FILE_NOT_FOUND) ;
				}

				edges[index].push_back( static_cast<std::size_t>( found - packages.begin())) ;
			}

			// 必要driver componentは元AddComponent/ComponentIDsに一意に結合します
			for( const auto &reference : package.requiredComponents) {
				std::optional<std::size_t> target ;	// 複数候補では成功値を保持しません
				// CopyINFで到達した全SWC metadataを元IDで照合します
				for( std::size_t child = 1U; child < packages.size(); ++child) {
					const auto &value = *packages[child] ;	// 同protected byteから得た子metadataです
					const bool	matches =
						functional[index] && functional[child] &&
						value.role == DriverPlanRole::DRIVER_COMPONENT &&
						std::ranges::any_of( value.hardwareIds, [&]( const auto &id) {
							return std::ranges::any_of(
								reference.hardwareIds, [&]( const auto &expected) {
									return CompareStringOrdinal( id.c_str(), -1, expected.c_str(),
																-1, TRUE) == CSTR_EQUAL ;
								}) ;
						}) ; // 名前ではなく元SWC IDの一致です
					// 一意な元childだけを選びます
					if( matches) {
						// 曖昧なpackageや一子の複数必要関係を先頭へ絞りません
						if( target || componentsUsed[child]) {
							return fromWin32( ERROR_DUP_NAME) ;
						}

						target = child ;
					}
				}

				// 元必要IDの不足を任意utilityの欠落と同じ扱いにしません
				if( !target) {
					return fromWin32( ERROR_NOT_FOUND) ;
				}

				componentsUsed[*target] = true ;
				made->members_.push_back(
					{*target - 1U, DriverPlanRole::DRIVER_COMPONENT, index, reference.hardwareIds}) ;
			}
		}

		std::vector<unsigned char>		 visited( packages.size()) ;	// 未訪問0、訪問中1、完了2です
		// 同同期factoryの有限graphだけを借用し、最深でも八packageで循環を拒否します
		std::function<bool( std::size_t)> visit = [&]( const std::size_t index) {
			// 訪問中への戻りは明示CopyINF循環です
			if( visited[index] == 1U) {
				return false ;
			}

			// 共有参照の完了済み枝は再走査しません
			if( visited[index] == 2U) {
				return true ;
			}

			visited[index] = 1U ;
			// 全明示参照を確認し、一つの循環も残しません
			for( const auto child : edges[index]) {
				// 循環が見つかった場合は全計画を失敗にします
				if( !visit( child)) {
					return false ;
				}
			}

			visited[index] = 2U ;
			return true ;
		} ;
		// 元baseから全必要役割へ到達する有限閉包だけを認めます
		if( !visit( 0U) ||
		   std::ranges::any_of( visited, []( const auto value) { return value != 2U ; })) {
			return fromWin32( ERROR_CIRCULAR_DEPENDENCY) ;
		}

		// 元CopyINFだけで到達する拡張と、元AddComponentで結ぶdriver子を区別します
		for( std::size_t index = 1U; index < packages.size(); ++index) {
			const auto role = packages[index]->role ;	// 元Classの役割です
			// 必要性のない同梱SWCを計画へ追加しません
			if( functional[index] && role == DriverPlanRole::DRIVER_COMPONENT &&
			   !componentsUsed[index]) {
				return fromWin32( ERROR_NOT_FOUND) ;
			}

			// 拡張は同parentの適用性を別に確認するmemberです
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
bool makeCommonInfCandidateAssessment(
	const ScanSessionId scanSessionId, const UpdateCandidate &candidate,
	const CommonInfInspection &inspected, const std::uint64_t evidenceId,
	const CandidateAssessmentFinding &origin, const NativeError applicabilityError,
	const std::optional<std::uint32_t> candidateRank, CandidateAssessment &assessment)
{
	assessment = {} ;
	// 未検査、部分検査、失敗時のrank、誤った由来を合格証拠へ変換しない
	if( inspected.scanSessionId != scanSessionId ||
	   inspected.state != CommonInfInspectionState::VERIFIED || inspected.error != 0 ||
	   !inspected.workspace || inspected.closure.packages.size() != 1U || evidenceId == 0 ||
	   (applicabilityError != 0 && candidateRank) ||
	   !isCandidateAssessmentFindingValid( CandidateAssessmentAxis::ORIGIN, origin)) {
		return false ;
	}

	const OfficialInfPackage &package =
		// 結合する内容metadata
		inspected.closure.packages.front() ;
	// 別INFの検証結果を現在行や異なる版の候補へ使い回さない
	if( candidate.current || candidate.packageIdentity.empty() ||
	   candidate.version != package.driverVersion || candidate.provider != package.providerName) {
		return false ;
	}

	CandidateAssessment result ;	// 結合検証後だけ公開する八軸
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
	// 明示依存の解決前でも署名・基礎適合を提示するが、構成と必須条件を合格にしない
	if( package.hasExternalDependencies || package.hasUnassessedProgramReferences) {
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
	// API失敗は不適合と分け、元のHRESULTを保持する
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

	// 由来を含む全八軸と候補identityの整合性を要求する
	if( !isCandidateAssessmentBound( result, scanSessionId, candidate.identity,
								   candidate.deviceIdentity, candidate.packageIdentity)) {
		return false ;
	}

	assessment = std::move( result) ;
	return true ;
}

} // namespace drivercrate
