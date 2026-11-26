//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native.cpp
 * @brief 実path・署名・OSを固定する非実行INF依存adapterの実装
 * @version 01.51.01
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  製品に含めない同期API障害注入境界を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/06  封印所有者の使用中固定へpackage由来を接続
 * Ver.01.03.00 Shunji Ogawa  2026/10/06  封印CATの原位置・size・hashだけを署名根拠にする
 * Ver.01.04.00 Shunji Ogawa  2026/10/07  到達file用途の有限観測と不在以外の節読取診断を追加
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  元共通閉包と完全内部APIから選択依存と有限効果を再検査
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  正確なNeeds設置文脈から有限HKR設定を全行検査
 * Ver.01.06.01 Shunji Ogawa  2026/10/15  Needs効果の宣言契約をCopyFilesとAddRegへ整合
 * Ver.01.06.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける
 * Ver.01.06.03   Shunji Ogawa  2026/10/24 不在比較のHRESULT値をNativeErrorへ明示変換する
 * Ver.01.06.04 Shunji Ogawa  2026/10/24  必須解析の型・有限所有buffer・失敗制御を明示
 * Ver.01.07.00 Shunji Ogawa  2026/11/08  正規選択Include文脈と同名Needs転送を有限接続
 * Ver.01.07.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.07.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.07.03 Shunji Ogawa  2026/11/13  Needs AddRegの元拒否leafを既匿名診断へ接続
 * Ver.01.07.04 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.07.05 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.08.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.09.00 Shunji Ogawa  2026/11/20  収集原閉包と全一覧からWindows同梱INFの選択依存と作用を検査
 * Ver.01.10.00 Shunji Ogawa  2026/11/20  SDHost収集の標準サービスを元INFと同CATのコピーへ結合
 * Ver.01.11.00 Shunji Ogawa  2026/11/20  標準Portsの実サービスと元所有ページを非実行で照合
 * Ver.01.12.00 Shunji Ogawa  2026/11/20  標準NVMeとPCIの元文書・空リスト・保護コピーを照合
 * Ver.01.13.00 Shunji Ogawa  2026/11/21  標準AHCIの元文書と保護コピーを収集で照合
 * Ver.01.14.00 Shunji Ogawa  2026/11/21  選択メディアチェンジャーの起動グループを終端まで照合
 * Ver.01.15.00 Shunji Ogawa  2026/11/21  HDCの元SYSと共有作用を収集の固定ファイル検査へ接続
 * Ver.01.16.00 Shunji Ogawa  2026/11/21  元HDCの端末選択に型付き作用と現在サービスを結合
 * Ver.01.17.00 Shunji Ogawa  2026/11/21  HDCの既存SYSを同名と完全SHA-256で再照合
 * Ver.01.18.00 Shunji Ogawa  2026/11/21  HDCの修飾なし元基本節を同じAMD64選択に結合
 * Ver.01.19.00 Shunji Ogawa  2026/11/21  収集と端末でWindows標準シリアルページを検査
 * Ver.01.20.00 Shunji Ogawa  2026/11/22  仮想Wi-FiバスのSYSを元Driver StoreとCATに照合
 * Ver.01.21.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの元コピーと端末照合の必要性を検査
 * Ver.01.22.00 Shunji Ogawa  2026/11/22  元フィルター置換を端末照合に必要な作用として保持
 * Ver.01.23.00 Shunji Ogawa  2026/11/22  公式収集の同梱仮想Wi-Fiバスを独立した元作用へ照合
 * Ver.01.24.00 Shunji Ogawa  2026/11/22  公式選択の同梱辺を双方向に照合し現状態の証拠を返す
 * Ver.01.25.00 Shunji Ogawa  2026/11/22  保護された同梱仮想Wi-Fi INFの署名と内容を同期確認
 * Ver.01.26.00 Shunji Ogawa  2026/11/22  補助サービスの元コピー行と再起動後の置換指定を照合
 * Ver.01.27.00 Shunji Ogawa  2026/11/22  端末計画に補助サービスの読み取りと再観測を接続
 * Ver.01.28.00 Shunji Ogawa  2026/11/23  自動起動ストレージの署名付き元電源設定を読取り検査へ接続
 * Ver.01.29.00 Shunji Ogawa  2026/11/23  自動起動ストレージの署名付き元AutoLoggerを読取り検査へ接続
 * Ver.01.30.00 Shunji Ogawa  2026/11/23  元ACPI・DMA・イベントを既存のストレージ作用グラフへ接続
 * Ver.01.31.00 Shunji Ogawa  2026/11/23  正規ACPIとAutoLoggerの現在保護を元のストレージ選択に結合
 * Ver.01.32.00 Shunji Ogawa  2026/11/23  六欄で明示したSystemイベントの現在登録を選択へ結合
 * Ver.01.33.00 Shunji Ogawa  2026/11/23  元自動起動補助に現在のSCMとDriver Storeファイルを結合
 * Ver.01.34.00 Shunji Ogawa  2026/11/23  自動起動作用を選択機器の現用登録読取りへ接続
 * Ver.01.35.00 Shunji Ogawa  2026/11/23  自動起動の現用登録・共通イベント・共有設定を再観測
 * Ver.01.36.00 Shunji Ogawa  2026/11/23  現用電源設定を元選択と共有先の再観測に保持
 * Ver.01.37.00 Shunji Ogawa  2026/11/23  署名付き現用登録の電源定義との照合を通常計画へ接続
 * Ver.01.38.00 Shunji Ogawa  2026/11/23  自動起動補助とSystemイベントの共有先を端末で比較
 * Ver.01.39.00 Shunji Ogawa  2026/11/23  起動サービスとSYSを候補の保護付き観測へ接続
 * Ver.01.40.00 Shunji Ogawa  2026/11/23  自動起動型の元コピーと端末観測を私有計画へ接続
 * Ver.01.41.00 Shunji Ogawa  2026/11/23  名前付きイベントDLLを元CATへ再照合し現用確認まで保留
 * Ver.01.42.00 Shunji Ogawa  2026/11/23  イベントDLLのCAT確認後に配置と現用登録を照合
 * Ver.01.43.00 Shunji Ogawa  2026/11/23  Windowsの選択節から単一起動ストレージの元作用を検査
 * Ver.01.44.00 Shunji Ogawa  2026/11/24  元選択と同梱Wi-Fiバスの旧名転送をそれぞれ照合
 * Ver.01.45.00 Shunji Ogawa  2026/11/24  USB Bluetoothの同梱INFへの全参照を収集で確認
 * Ver.01.46.00 Shunji Ogawa  2026/11/24  USB Bluetoothの同梱SYSの元コピーとWindows署名を照合
 * Ver.01.47.00 Shunji Ogawa  2026/11/24  USB Bluetoothの機器キー追加・削除と同梱PCIの元電源設定を照合
 * Ver.01.48.00 Shunji Ogawa  2026/11/24  USB Bluetoothの共有登録と保護Windows資源を元作用に照合
 * Ver.01.49.00 Shunji Ogawa  2026/11/24  USB Bluetoothの全同梱作用を公式選択の収集証拠へ結合
 * Ver.01.50.00 Shunji Ogawa  2026/11/24  混在シリアルの元参照を同梱Serenumの実体へ照合
 * Ver.01.51.00 Shunji Ogawa  2026/11/24  同梱WinUSBの元文書と保護SYSと機器登録を照合
 * Ver.01.51.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note 共通内容factoryの私有選択節へ接続します。旧引数経路のpackage由来は未検査を維持します
 * @see docs/adr/0270-read-only-inf-dependency-native-adapter.md
 */
//------------------------------------------------------------------------------

#include "platform/inf_dependency_native.h"
#include "platform/inf_dependency_native_internal.h"
#include "platform/system_inf_effects_internal.h"
#include "platform/common_driver_package.h"
#include "platform/collector_property_page_export_internal.h"
#include "platform/driver_package_signature_internal.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/official_inf_archive_binding.h"
#include "platform/official_zip.h"
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
#include "support/inf_dependency_native_test_api.h"
#endif

#include <Windows.h>
#include <SetupAPI.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace inf_dependency_native_detail {
namespace {
thread_local const Api *ownedApi{} ;	// 同threadの所有scopeだけを借用します
}
//------------------------------------------------------------------------------
/**
 * @brief 検証済み完全表を同threadへ固定します
 * @param[in] api 所有権を移す完全表です
 */
//------------------------------------------------------------------------------
ScopedFixture::ScopedFixture( Api api) : api_( std::move( api))
{
	ownedApi = &api_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 所有表を解除します。作成threadで破棄します
 */
//------------------------------------------------------------------------------
ScopedFixture::~ScopedFixture()
{
	ownedApi = nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定native処理または完全内部表へ同期分岐します
 * @return 内部scopeがある場合だけ非所有表、製品ではnullptrです
 */
//------------------------------------------------------------------------------
const Api *activeApi() noexcept
{
	return ownedApi ;
}
#ifdef DRIVERCRATE_INTERNAL_INDEX_TESTS
//------------------------------------------------------------------------------
/**
 * @brief 欠落表と再入を拒否して所有scopeを作ります
 * @param[in] api 元五APIと、Store投影時は完全readPathを持つ表です
 * @return 正常時のscope、不完全または再入時nullptrです
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedFixture> Access::create( Api api)
{
	// 欠落表と二重scopeを実nativeへ補完しません
	if( ownedApi != nullptr || !api.version || !api.windowsDirectory || !api.infSignature ||
	   !api.catalogSignature || !api.driverStore || (api.projectedStore && !api.readPath)) {
		return {} ;
	}

	return std::unique_ptr<ScopedFixture>( new ScopedFixture( std::move( api))) ;
}
#endif
} // namespace inf_dependency_native_detail
namespace {
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
thread_local const test::InfDependencyNativeTestApi
	*testApi{} ;	// 専用targetの一同期runだけを借用する
#endif
constexpr std::uint64_t MAX_INF_BYTES	= 4U * 1024U * 1024U ;		// 一INFの実byte上限
constexpr std::uint64_t MAX_CAT_BYTES	= 32U * 1024U * 1024U ;		// 一CATの有限上限
constexpr std::uint64_t MAX_TOTAL_BYTES = 128U * 1024U * 1024U ;	// 全固定fileの累積上限
constexpr std::size_t	MAX_FILES		= 256U ;					// INF・CAT・対応Storeを含む固定file上限

//------------------------------------------------------------------------------
/**
 * @brief Windows ordinalで有限path／明示名を比較する
 * @param[in] left 一方の有限名称
 * @param[in] right 他方の有限名称
 * @return 大小文字を除いて一致する場合true
 */
//------------------------------------------------------------------------------
bool					equalName( std::wstring_view left, std::wstring_view right)
{
	return left.size() < MAX_PATH && right.size() < MAX_PATH &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元一覧から大小文字を除いて同じ完全相対位置のentryを得る
 * @param[in] entries 同じ容器又は抽出閉包の安全な一意entry一覧
 * @param[in] name 元INFまたはCATが指定する完全相対位置
 * @return 一致した元entryの同期借用値。見つからなければnull
 */
//------------------------------------------------------------------------------
const OfficialZipEntry *dependencyEntry( std::span<const OfficialZipEntry> entries,
										std::wstring_view				  name)
{
	const auto match = std::ranges::find_if( entries, [name]( const auto &entry) {
		return equalName( entry.relativePath, name) ;
	}) ; // basenameだけの一致は同じ所有元へ結びません
	return match == entries.end() ? nullptr : &*match ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一相対componentのdevice aliasを拒否する
 * @param[in] part 末尾正規化を含まない一component
 * @return 予約device名の場合true
 */
//------------------------------------------------------------------------------
bool reservedName( std::wstring_view part)
{
	const auto base = part.substr( 0U, part.find( L'.')) ;	// 拡張子前のdevice名
	return equalName( base, L"CON") || equalName( base, L"PRN") || equalName( base, L"AUX") ||
		   equalName( base, L"CONIN$") || equalName( base, L"CONOUT$") || equalName( base, L"NUL") ||
		   (base.size() == 4U &&
			((base[3] >= L'1' && base[3] <= L'9') || base[3] == L'\u00b9' || base[3] == L'\u00b2' ||
			 base[3] == L'\u00b3') &&
			(equalName( base.substr( 0U, 3U), L"COM") || equalName( base.substr( 0U, 3U), L"LPT"))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同期中のCommon閉包の再検査を製品の署名境界または専用試験の原本へ結ぶ
 * @param[in] content 端末の選択検査が保持する元のCommon閉包
 * @return 全byteと署名の再検査に成功すれば0、失敗時は元HRESULT
 */
//------------------------------------------------------------------------------
NativeError recheckCommonContent( const CommonInfInspection &content)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// この試験呼出しで明示した元内容を検査する場合だけ、専用fixtureの再検証を使います
	if( testApi != nullptr && testApi->reverifyCommonInf != nullptr) {
		return testApi->reverifyCommonInf( content) ;
	}
#endif
	return reverifyCommonDriverInf( content) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Win32失敗をHRESULTへ変換する
 * @param[in] error 最初のWin32診断値
 * @return 非零HRESULT。診断欠損はE_FAIL
 */
//------------------------------------------------------------------------------
NativeError winError( DWORD error)
{
	return error == 0U ? E_FAIL : HRESULT_FROM_WIN32( error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示openの不在だけを後続の検証失敗から分離する
 * @param[in] error CreateFileWの直後の元診断
 * @param[out] missing 任意の不在観測出力。file／path不在の場合だけtrue
 * @return 元の失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError openError( DWORD error, bool *missing)
{
	// 有効handle取得後の属性・hash・CAT等の失敗から不在を生成しない
	if( missing != nullptr) {
		*missing = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ;
	}

	return winError( error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 初回／終了の実OS情報を取得する。注入は専用targetだけで有効
 * @param[out] version EX layoutのversion・product type
 * @param[out] native OSのnative architecture
 * @return 取得0、APIの失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError nativeVersion( OSVERSIONINFOEXW &version, SYSTEM_INFO &native)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// このthreadの明示API集合だけを同期借用する
	if( testApi != nullptr) {
		return testApi->version( version, native) ;
	}
#endif
	// 所有された完全内部表以外は固定native経路です
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->version( version, native) ;
	}

	using VersionFunction = LONG( WINAPI *)( OSVERSIONINFOEXW *) ;	// RtlGetVersionのEX対応ABI
	const HMODULE module  = GetModuleHandleW( L"ntdll.dll") ;		// process内の非所有module
	// Windows関数addressを公式layoutの同期署名へ変換するAPI境界
	const auto	  query = module == nullptr ? nullptr
											: reinterpret_cast<VersionFunction>( GetProcAddress(
												  module, "RtlGetVersion")) ;	// 非所有の関数pointer
	// 関数不在または照会失敗を未知OSとして止める
	if( query == nullptr || query( &version) != 0) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	GetNativeSystemInfo( &native) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief OS起点を取得する。環境変数や任意入力を使用しない
 * @param[out] path 成功時の終端を除いた有限位置
 * @return 取得0、容量またはAPI失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError nativeWindowsDirectory( std::wstring &path)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// このthreadの明示API集合だけを同期借用する
	if( testApi != nullptr) {
		return testApi->windowsDirectory( path) ;
	}
#endif
	// 起点だけを任意の製品設定へ公開しません
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->windowsDirectory( path) ;
	}

	std::array<wchar_t, MAX_PATH> windows{} ;	// 実Windows位置の有限buffer
	const UINT					  count =
		// 明示OS起点
		GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
	// 過長や空の起点を有効なprefixにしない
	if( count == 0U || count >= windows.size()) {
		return count == 0U ? winError( GetLastError()) : E_INVALIDARG ;
	}

	path.assign( windows.data(), count) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF自身の現OS署名情報を取得する
 * @param[in] path 固定INFの絶対位置
 * @param[in,out] signer cbSizeを設定した有限応答
 * @return 署名情報取得0、元の失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError nativeInfSignature( const std::wstring &path, SP_INF_SIGNER_INFO_W &signer)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 架空署名を実trust処理へ渡さない専用compile境界
	if( testApi != nullptr) {
		return testApi->infSignature( path, signer) ;
	}
#endif
	// 同workerの完全表を使用し、不完全な実署名混在を行いません
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->infSignature( path, signer) ;
	}

	return driver_package_signature_detail::setupVerifyInf( path.c_str(), nullptr, &signer)
			   ? 0
			   : winError( GetLastError()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じCATとINF memberを共通署名検証へ渡す
 * @param[in] catalog 安全に固定したCAT位置
 * @param[in] members 同期借用するINF member集合
 * @return 検証0、元の失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError nativeCatalogSignature( const std::wstring			&catalog,
								   std::span<const std::wstring> members)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 専用targetでは必須callbackでOS trust通信を置換する
	if( testApi != nullptr) {
		return testApi->catalogSignature( catalog, members) ;
	}
#endif
	// 全memberを同じ低位表へ渡します
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->catalogSignature( catalog, members) ;
	}

	return verifyOfficialCatalogMembers( catalog, members) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現OSの対応Store位置を有限に取得する
 * @param[in] path 固定INF位置
 * @param[out] location 成功時の有限対応位置
 * @return 照会0、応答不正または元の失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError nativeDriverStore( const std::wstring &path, std::wstring &location)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 元INFへの対応変更だけを注入し、実byte読取は置換しない
	if( testApi != nullptr) {
		return testApi->driverStore( path, location) ;
	}
#endif
	// 対応Storeだけを実SYSTEMへfallbackしません
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->driverStore( path, location) ;
	}

	std::array<wchar_t, MAX_PATH> store{} ;		// OS対応位置の有限buffer
	DWORD						  required{} ;	// 終端を含む必要容量
	// 失敗を空の成功応答へ変換しない
	if( !SetupGetInfDriverStoreLocationW( path.c_str(), nullptr, nullptr, store.data(),
										static_cast<DWORD>( store.size()), &required)) {
		return winError( GetLastError()) ;
	}

	// 元APIの不正終端と容量超過を止める
	if( required == 0U || required > store.size() || store[required - 1U] != L'\0') {
		return E_UNEXPECTED ;
	}

	location.assign( store.data(), required - 1U) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 開いたhandleの実属性を取得する
 * @param[in] handle 同期借用する固定handle
 * @param[out] attributes 実属性または専用targetの架空応答
 * @return 照会0、元の失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError nativeAttributes( HANDLE handle, FILE_ATTRIBUTE_TAG_INFO &attributes)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 任意属性注入がない場合は実APIを維持する
	if( testApi != nullptr && testApi->attributes) {
		return testApi->attributes( handle, attributes) ;
	}
#endif
	return GetFileInformationByHandleEx( handle, FileAttributeTagInfo, &attributes,
										sizeof( attributes))
			   ? 0
			   : winError( GetLastError()) ;
}

/** @brief Windows handleを単独所有して全return経路で閉じる */
struct HandleCloser {
	/**
	 * @brief 有効な所有handleを閉じる
	 * @param[in] value 所有する一handle
	 */
	void operator()( void *value) const noexcept
	{
		// nullptrは未取得、INVALID_HANDLE_VALUEは取得失敗で解放しない
		if( value != nullptr && value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
/**
 * @brief 所有handleのRAII型
 */
using Handle = std::unique_ptr<void, HandleCloser> ;

/** @brief 固定fileと全祖先のhandle・原hashを所有する */
struct PinnedFile {
	/// 正規化せず確認したlocal絶対位置
	std::wstring			   path ;
	/// run中のrenameを拒否する全祖先directory
	std::vector<Handle>		   parents ;
	/// 書込み／削除を共有しない通常file
	Handle					   file ;
	/// 開始時のvolume・file identityとsize
	BY_HANDLE_FILE_INFORMATION information{} ;
	/// 原byteの小文字SHA-256
	std::wstring			   sha256 ;
	/// 1以上の固定size
	std::uint64_t			   bytes{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief pathとhandleの同じ位置・種類を確認する
 * @param[in] handle 固定済みのfile／directory
 * @param[in] path 終端付き通常DOS位置
 * @param[in] directory directoryを期待する場合true
 * @return 境界一致0、reparse・位置差・API失敗のHRESULT
 */
//------------------------------------------------------------------------------
NativeError checkHandle( HANDLE handle, const std::wstring &path, bool directory)
{
	FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// Handleが示す実属性
	// 名前の属性だけでreparseや異なる種類を採用しない
	const auto				attributeError = nativeAttributes( handle, attributes) ;	// 属性の独立照会
	// 元API診断を後続位置検査で消さない
	if( attributeError != 0) {
		return attributeError ;
	}

	// Reparseの最終参照先を通常fileとして読み替えない
	if( (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
	   ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory) {
		return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
	}

	std::array<wchar_t, MAX_PATH + 4U> finalPath{} ;	// DOS接頭辞を含む有限最終位置
	const DWORD						   count =
		GetFinalPathNameByHandleW( handle, finalPath.data(), static_cast<DWORD>( finalPath.size()),
								  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 実位置
	// 異なる位置や過長応答は固定済みpathへ結合できない
	if( count == 0U || count >= finalPath.size()) {
		return count == 0U ? winError( GetLastError()) : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	const std::wstring_view name( finalPath.data(), count) ;	// 終端を除く応答
	return name.starts_with( L"\\\\?\\") && equalName( name.substr( 4U), path)
			   ? 0
			   : HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 開始と終了の物理file・size・時刻を比較する
 * @param[in] left 開始観測
 * @param[in] right 再観測
 * @return 同じfile・size・最終書込時刻の場合true
 */
//------------------------------------------------------------------------------
bool sameFile( const BY_HANDLE_FILE_INFORMATION &left, const BY_HANDLE_FILE_INFORMATION &right)
{
	return left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
		   left.nFileIndexHigh == right.nFileIndexHigh &&
		   left.nFileIndexLow == right.nFileIndexLow && left.nFileSizeHigh == right.nFileSizeHigh &&
		   left.nFileSizeLow == right.nFileSizeLow &&
		   left.ftLastWriteTime.dwHighDateTime == right.ftLastWriteTime.dwHighDateTime &&
		   left.ftLastWriteTime.dwLowDateTime == right.ftLastWriteTime.dwLowDateTime ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実OS version・product typeとnative x64を取得する
 * @param[in] observationId 非零のrun世代
 * @param[out] context 成功時の実OS文脈
 * @return 完了0、未知OSまたはAPI失敗のHRESULT
 */
//------------------------------------------------------------------------------
NativeError currentContext( std::uint64_t observationId, InfDependencyContext &context)
{
	OSVERSIONINFOEXW version{} ;	// 実versionとproduct type
	version.dwOSVersionInfoSize = sizeof( version) ;
	SYSTEM_INFO native{} ;									// OSのnative architecture
	const auto	error = nativeVersion( version, native) ;	// 開始／終了の独立OS照会
	// 元APIの失敗後に構造体の零値から文脈を生成しない
	if( error != 0) {
		return error ;
	}

	// 未知product typeをclientと推測せず、x64以外も拒否する
	if( version.dwMajorVersion == 0U || version.dwBuildNumber == 0U || observationId == 0U ||
	   native.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
	   (version.wProductType != VER_NT_WORKSTATION && version.wProductType != VER_NT_SERVER &&
		version.wProductType != VER_NT_DOMAIN_CONTROLLER)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	context = {version.dwMajorVersion,
			   version.dwMinorVersion,
			   version.dwBuildNumber,
			   0x8664U,
			   version.wProductType != VER_NT_WORKSTATION,
			   observationId} ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全値が同じOS／run文脈であることを確認する
 * @param[in] left 開始値
 * @param[in] right 再確認値
 * @return 全field一致の場合true
 */
//------------------------------------------------------------------------------
bool sameContext( const InfDependencyContext &left, const InfDependencyContext &right)
{
	return left.major == right.major && left.minor == right.minor && left.build == right.build &&
		   left.machine == right.machine && left.windowsServer == right.windowsServer &&
		   left.observationId == right.observationId ;
}

/** @brief 一INF handleを所有する。Appendや導入を行わない */
struct InfCloser {
	/**
	 * @brief 単独のINF解析handleを閉じる
	 * @param[in] value 所有する有効handle
	 */
	void operator()( void *value) const noexcept
	{
		SetupCloseInfFile( value) ;
	}
} ;
/**
 * @brief 単独INFのRAII型
 */
using InfHandle = std::unique_ptr<void, InfCloser> ;

//------------------------------------------------------------------------------
/**
 * @brief fieldの原値を有限bufferへ取得する
 * @param[in,out] line SetupAPIの同期context
 * @param[in] index keyは0、valueは1以上
 * @param[out] value 成功時の有限field
 * @return 完了0、過長またはSetupAPI失敗のHRESULT
 */
//------------------------------------------------------------------------------
NativeError field( INFCONTEXT &line, DWORD index, std::wstring &value)
{
	std::array<wchar_t, 255U> buffer{} ;	// 最大254文字と終端
	DWORD					  required{} ;	// SetupAPI応答の必要容量
	// 過長名を切り捨てて別のfile／節へ照合しない
	if( !SetupGetStringFieldW( &line, index, buffer.data(), static_cast<DWORD>( buffer.size()),
							 &required)) {
		return winError( GetLastError()) ;
	}

	// 終端不正や過大の応答も全体拒否する
	if( required == 0U || required > buffer.size() || buffer[required - 1U] != L'\0') {
		return E_UNEXPECTED ;
	}

	value.assign( buffer.data(), required - 1U) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元非zero拒否へ最初のAddReg数値leafだけを結びます
 * @param[in,out] diagnostic 任意の同pair診断です。先行拒否は変更しません
 * @param[in] error 元の返却HRESULTです。0は記録しません
 * @param[in] stage 呼出し元で確定した閉じた拒否地点です
 * @param[in] observed 有界件数又は固定enum/SDK flagです。任意本文を含めません
 * @return 未変更の元HRESULTです
 * @note native API/文字列比較を追加せず、診断なしでも合否を変えません
 */
//------------------------------------------------------------------------------
NativeError needsAddRegFailure( RequiredInfBindingDiagnostic *diagnostic, const NativeError error,
							   const NeedsAddRegDiagnosticStage stage,
							   const std::uint32_t				observed = 0U) noexcept
{
	// 元の最初の拒否だけを保持し、後段の汎用位置で上書きしません
	if( diagnostic && error != 0U && diagnostic->rejection == InfBindingReject::NONE) {
		diagnostic->stage = static_cast<std::uint32_t>( stage) ;
		static_cast<void>( diagnostic->reject( error, InfBindingReject::DEPENDENCY, observed)) ;
	}

	return error ;
}

/** @brief 検証済みINBOX/SYSTEMと同選択DDInstallだけが作る局所作用文脈です */
struct NeedsSystemContext {
	/// 同OS/同原documentを固定したcanonical INF位置です
	std::wstring_view			 documentPath ;
	/// 同runの固定helper/元CAT/trust/権限を確認する同期callbackです
	std::function<NativeError()> verifyComponents ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 標準登録のGUIDを全38文字の閉じた文法で確認します
 * @param[in] value 同原SYSTEM documentから読んだ一値です
 * @return 波括弧/桁/区切り/全hexが正しい場合trueです
 */
//------------------------------------------------------------------------------
bool systemRegistrationGuid( std::wstring_view value)
{
	// 部分一致や末尾引数をGUIDへ変換しません
	if( value.size() != 38U || value.front() != L'{' || value.back() != L'}') {
		return false ;
	}

	// 固定位置の区切りと全hex桁を確認します
	for( std::size_t index = 1U; index < 37U; ++index) {
		const auto character = value[index] ;	// 同元文字を同期借用します
		// GUIDの四区切りだけにハイフンを許します
		if( index == 9U || index == 14U || index == 19U || index == 24U) {
			// 別文字を正規化しません
			if( character != L'-') {
				return false ;
			}
		}
		// 非区切り位置にはASCII hex以外を許しません
		else if( !((character >= L'0' && character <= L'9') ||
				  (character >= L'a' && character <= L'f') ||
				  (character >= L'A' && character <= L'F'))) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非実行の媒体表示文字列を有限なdataとして確認します
 * @param[in] value 同元INFから読んだ一つの設定値です
 * @return 非空/制御文字なし/未照合program参照なしの場合trueです
 */
//------------------------------------------------------------------------------
bool systemMediaText( std::wstring_view value)
{
	// 空/制御/過大値を標準表示名へ補完しません
	if( value.empty() || value.size() > 254U ||
	   std::ranges::any_of( value, []( wchar_t c) { return c < L' ' || c == 0x7f ; })) {
		return false ;
	}

	std::wstring lower( value) ;	// 比較専用の有限copyです
	// ASCIIのprogram拡張子を同値化します
	for( auto &c : lower) {
		c = c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c - L'A' + L'a') : c ;
	}

	return lower.find( L".exe") == lower.npos && lower.find( L".dll") == lower.npos &&
		   lower.find( L".sys") == lower.npos && lower.find( L".com") == lower.npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定Windows登録が参照する同原INFのinterfaceデータ全行を確認します
 * @param[in] inf 同SYSTEM原文の読取handleです
 * @param[in] section 同原commandが明示した正確なinterface節です
 * @param[in,out] registryRows 全Needsと共有する4096行予算です
 * @return CLSID/FriendlyNameの有限dataだけなら0、元API又は未対応errorです
 */
//------------------------------------------------------------------------------
NativeError verifySystemInterface( HINF inf, const std::wstring &section, std::size_t &registryRows)
{
	const LONG directives = SetupGetLineCountW( inf, section.c_str()) ;	// 正確な同原文だけです
	// 別節/未知directiveを空成功へ変換しません
	if( directives != 1L) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	INFCONTEXT line{} ;	// 同節の唯一のAddRegです
	// 元readerの失敗を保持します
	if( !SetupGetLineByIndexW( inf, section.c_str(), 0U, &line)) {
		return winError( GetLastError()) ;
	}

	std::wstring key ;								// 同一directiveの完全名です
	std::wstring settings ;							// 同原文のregistry節です
	auto		 error = field( line, 0U, key) ;	// 元読取の診断です
	// 正確な一AddReg参照以外を許可しません
	if( error != 0U || !equalName( key, L"AddReg") || SetupGetFieldCount( &line) != 1U) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	error = field( line, 1U, settings) ;
	// 不正参照や別security作用を採用しません
	if( error != 0U || settings.empty() || settings.find_first_of( L"[]\r\n") != settings.npos) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const auto security = settings + L".security" ;	// ACL作用を別に拒否します
	SetLastError( ERROR_SUCCESS) ;
	const LONG	securityRows  = SetupGetLineCountW( inf, security.c_str()) ;	// 空節も宣言です
	const DWORD securityError = GetLastError() ;								// 元API直後の独立errorです
	// 未知ACLとsecurity読取失敗を無作用にしません
	if( securityRows >= 0L ||
	   (securityError != ERROR_SUCCESS && securityError != ERROR_SECTION_NOT_FOUND)) {
		return securityRows >= 0L ? HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)
								  : winError( securityError) ;
	}

	const LONG rows = SetupGetLineCountW( inf, settings.c_str()) ;	// 全interface設定です
	// この閉じた標準登録は二つのdata値だけです
	if( rows != 2L || registryRows > 4094U) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	bool clsid{} ;		// 同じ値の重複は許可しません
	bool friendly{} ;	// 同じ値の重複は許可しません
	// 同原文の二設定を全て確認します
	for( DWORD row = 0U; row < 2U; ++row) {
		INFCONTEXT setting{} ;	// 一設定の元読取contextです
		// 部分読取後の成功を返しません
		if( !SetupGetLineByIndexW( inf, settings.c_str(), row, &setting)) {
			return winError( GetLastError()) ;
		}

		// 単一文字列以外の作用を拒否します
		if( SetupGetFieldCount( &setting) != 5U) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		std::array<std::wstring, 5U> values ;	// 同行の全元fieldです
		// 全fieldの不正を先頭値で隠しません
		for( DWORD index = 1U; index <= 5U; ++index) {
			error = field( setting, index, values[index - 1U]) ;
			// 元field errorを保持します
			if( error != 0U) {
				return error ;
			}
		}

		int flags{} ;	// 既定REG_SZだけです
		// 同interfaceの相対root/flags以外は認めません
		if( !equalName( values[0], L"HKR") || !values[1].empty() ||
		   (!values[3].empty() && (!SetupGetIntField( &setting, 4U, &flags) || flags != 0))) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		// CLSIDは同原文のGUID型であり、COM serverや任意program登録へ拡張しません
		if( equalName( values[2], L"CLSID") && !clsid && systemRegistrationGuid( values[4])) {
			clsid = true ;
		}
		// 表示名も一つの有限dataだけを要求します
		else if( equalName( values[2], L"FriendlyName") && !friendly && systemMediaText( values[4])) {
			friendly = true ;
		} else {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}
	}

	registryRows += 2U ;
	return clsid && friendly ? 0U : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同SYSTEM原文の標準媒体data又は固定SWENUM登録だけを確認します
 * @param[in] inf 同原documentの読取handleです
 * @param[in] setting 同原registry行のcontextです
 * @param[in] values 全読取済みの最大20fieldです
 * @param[in] fields 元field数です
 * @param[in] system 同原document/固定helperへ結ぶ内部文脈です
 * @param[in,out] registryRows 追加interface行にも共有する全累積です
 * @param[in,out] diagnostic 元pairのfirst-errorだけを保持します
 * @return 閉じた標準作用成立0、元API又は具体的な未対応errorです
 */
//------------------------------------------------------------------------------
NativeError verifySystemMediaRow( HINF inf, INFCONTEXT &setting,
								 const std::array<std::wstring, 20U> &values, DWORD fields,
								 const NeedsSystemContext &system, std::size_t &registryRows,
								 RequiredInfBindingDiagnostic *diagnostic)
{
	const auto reject = [&]( NeedsAddRegDiagnosticStage stage, std::uint32_t observed = 0U) {
		return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED), stage,
								  observed) ;
	} ; // 同pairの固定数値だけを記録します
	int flags{} ;	// 元INFの型です
	// 原flagsを数値読取せず既定へ補完しません
	if( fields < 5U || (!values[3].empty() && !SetupGetIntField( &setting, 4U, &flags))) {
		return reject( NeedsAddRegDiagnosticStage::SYSTEM_TYPE, fields) ;
	}

	constexpr std::wstring_view CATEGORY =
		L"SYSTEM\\CurrentControlSet\\Control\\MediaCategories\\" ;	// 標準媒体scopeです
	constexpr std::wstring_view INTERFACE =
		L"SYSTEM\\CurrentControlSet\\Control\\MediaInterfaces\\" ;	// 標準媒体scopeです
	const auto scope = [&]( std::wstring_view prefix) {
		return values[1].size() == prefix.size() + 38U &&
			   equalName( std::wstring_view( values[1]).substr( 0U, prefix.size()), prefix) &&
			   systemRegistrationGuid( std::wstring_view( values[1]).substr( prefix.size())) ;
	} ; // GUID一段だけを同原keyへ照合します
	const bool category		  = scope( CATEGORY) ;	// 同scopeを一度だけ判定します
	const bool mediaInterface = scope( INTERFACE) ;	// 同scopeを一度だけ判定します
	// 媒体dataには型ごとの完全なfield数を要求します
	if( category || mediaInterface) {
		const bool text =
			category ? equalName( values[2], L"Name") : values[2].empty() ;	// 対象値の閉じた種類です
		const bool	binary	 = category ? equalName( values[2], L"Display")
										: equalName( values[2], L"IID") ;	// 二binary種類です
		const DWORD expected = category ? 8U : 20U ;						// 4byte又は16byteです
		// Name/既定値は有限な単一文字列だけです
		if( text && flags == 0 && fields == 5U && systemMediaText( values[4])) {
			return 0U ;
		}

		// 未知型/byte数/値名を既知binaryへ正規化しません
		if( !binary || flags != 1 || fields != expected) {
			return reject( NeedsAddRegDiagnosticStage::SYSTEM_TYPE, fields) ;
		}

		// 各元binary値を1byteのhex全体として確認します
		for( DWORD index = 4U; index < fields; ++index) {
			std::wstring_view byte( values[index]) ;	// 同元fieldだけを借用します
			// 明示0xも全値を消費します
			if( byte.starts_with( L"0x") || byte.starts_with( L"0X")) {
				byte.remove_prefix( 2U) ;
			}

			// 空/過大/不正hexを切り捨てません
			if( byte.empty() || byte.size() > 2U || std::ranges::any_of( byte, []( wchar_t c) {
				   return !((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
							(c >= L'A' && c <= L'F')) ;
			   })) {
				return reject( NeedsAddRegDiagnosticStage::SYSTEM_TYPE, fields) ;
			}
		}

		return 0U ;
	}

	// 任意HKLMを媒体登録へ救済しません
	if( !equalName( values[1], L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce")) {
		return reject( NeedsAddRegDiagnosticStage::SYSTEM_SCOPE) ;
	}

	const auto				   &command	 = values[4] ;			// 同原SYSTEM文だけを私有で検査します
	constexpr std::wstring_view LAUNCHER = L"rundll32.exe " ;	// 固定Windows launcherです
	// 別registry型/起動条件/任意値名を追加しません
	if( flags != 0 || fields != 5U || values[2].empty() || values[2].size() > 64U ||
	   std::ranges::any_of( values[2],
						   []( wchar_t c) {
							   return !((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
										(c >= L'0' && c <= L'9') || c == L'_' || c == L'.' ||
										c == L'-') ;
						   }) ||
	   command.size() <= LAUNCHER.size() ||
	   !equalName( std::wstring_view( command).substr( 0U, LAUNCHER.size()), LAUNCHER)) {
		return reject( NeedsAddRegDiagnosticStage::SYSTEM_REGISTRATION) ;
	}

	const auto comma = command.find( L',', LAUNCHER.size()) ;	// 固定module/exportの境界です
	// module欠落を既定DLLへ補完しません
	if( comma == command.npos) {
		return reject( NeedsAddRegDiagnosticStage::SYSTEM_REGISTRATION) ;
	}

	const auto module = std::wstring_view( command).substr(
		// 同原module名です
		LAUNCHER.size(), comma - LAUNCHER.size()) ;
	constexpr std::wstring_view ENTRY = L"StreamingDeviceSetup " ;		// export名はcase-sensitiveです
	const auto tail = std::wstring_view( command).substr( comma + 1U) ;	// 全引数を消費します
	// 別module/exportやshellを実行可能な標準登録へ認定しません
	if( (!equalName( module, L"streamci") && !equalName( module, L"streamci.dll")) ||
	   !tail.starts_with( ENTRY)) {
		return reject( NeedsAddRegDiagnosticStage::SYSTEM_REGISTRATION) ;
	}

	std::vector<std::wstring_view> arguments ;				// 最大5個の同元引数だけです
	std::size_t					   start = ENTRY.size() ;	// export名後の引数起点です
	// 引数を最後まで消費し、余分なcommandを拒否します
	while( start <= tail.size() && arguments.size() <= 5U) {
		const auto end = tail.find( L',', start) ;	// 一引数の正確な境界です
		arguments.push_back( tail.substr( start, end == tail.npos ? end : end - start)) ;
		// 最後の引数を確認したら終了します
		if( end == tail.npos) {
			break ;
		}

		start = end + 1U ;
	}

	// 固定三GUID又は同原INF/interfaceを加えた五引数だけです
	if( (arguments.size() != 3U && arguments.size() != 5U) ||
	   !systemRegistrationGuid( arguments[0]) || !systemRegistrationGuid( arguments[1]) ||
	   !systemRegistrationGuid( arguments[2])) {
		return reject( NeedsAddRegDiagnosticStage::SYSTEM_REGISTRATION) ;
	}

	// 任意の他INFや外部節を標準登録へ追加しません
	if( arguments.size() == 5U) {
		// INF位置と正確な節名を同原documentへ結びます
		if( !equalName( arguments[3], system.documentPath) || arguments[4].empty() ||
		   arguments[4].find_first_of( L"[]\\/\r\n") != arguments[4].npos) {
			return reject( NeedsAddRegDiagnosticStage::SYSTEM_INTERFACE) ;
		}

		const auto error = verifySystemInterface( inf, std::wstring( arguments[4]),
												 registryRows) ;	// 非実行の同原作用です
		// 読取の元errorを保持し、後段で成功へ変えません
		if( error != 0U) {
			return needsAddRegFailure( diagnostic, error,
									  NeedsAddRegDiagnosticStage::SYSTEM_INTERFACE) ;
		}
	}

	const auto error = system.verifyComponents() ;	// 元Windows実体/署名/権限の独立検査です
	return error == 0U
			   ? 0U
			   : needsAddRegFailure( diagnostic, error, NeedsAddRegDiagnosticStage::SYSTEM_HELPER) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元HKR単一行のroot/相対位置/型/値を同じSetupAPI規則で確認します
 * @param[in,out] setting 同INFの元行contextです
 * @param[in] values 全読取済みfieldを所有する有限配列です
 * @param[in] fields 元の全field数です
 * @param[in,out] diagnostic first-errorだけを保持する任意診断です
 * @return 元方針成立0、元数値parser又は閉じた拒否のHRESULTです
 * @note 累積行数はcallerが管理し、registryを変更しません
 */
//------------------------------------------------------------------------------
NativeError verifyRelativeNeedsRow( INFCONTEXT &setting, const std::array<std::wstring, 20U> &values,
								   DWORD fields, RequiredInfBindingDiagnostic *diagnostic)
{
	// 既HKR/未知rootのfield上限をSYSTEM対応で広げません
	if( fields > 5U) {
		return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
								  NeedsAddRegDiagnosticStage::FIELD_COUNT,
								  (std::min)( fields, DWORD{6U})) ;
	}

	// HKR以外は同device設定の範囲へ補完しません
	if( !equalName( values[0], L"HKR")) {
		return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
								  NeedsAddRegDiagnosticStage::ROOT) ;
	}

	const auto &subkey = values[1] ;	// 同文脈の相対registry keyだけです
	std::size_t begin{} ;				// 空subkeyは元相対rootを表します
	// 空以外の全componentで絶対指定・制御文字・親移動を拒否します
	while( begin < subkey.size()) {
		const auto end = subkey.find( L'\\', begin) ;	// 元component境界です
		// 正規化前の同componentだけを同期借用します
		const auto part =
			std::wstring_view( subkey).substr( begin, end == subkey.npos ? end : end - begin) ;
		// registry keyをpath正規化で別の有効keyへ変えません
		if( part.empty() || part == L"." || part == L".." ||
		   std::ranges::any_of( part, []( const wchar_t value) {
			   return value < L' ' || value > L'~' || value == L'/' || value == L':' ;
		   })) {
			return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
									  NeedsAddRegDiagnosticStage::SUBKEY_COMPONENT) ;
		}

		begin = end == subkey.npos ? subkey.size() : end + 1U ;
	}

	// 末尾separatorも別のkeyへ暗黙補正しません
	if( !subkey.empty() && subkey.back() == L'\\') {
		return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
								  NeedsAddRegDiagnosticStage::SUBKEY_TRAILING_SEPARATOR) ;
	}

	constexpr std::array<std::wstring_view, 9U> SPECIAL_VALUES{
		L"CoInstallers32", L"Installer32",	L"EnumPropPages32",
		L"UpperFilters",   L"LowerFilters", L"Security",
		L"DeviceLoader",   L"Run",			L"RunOnce"} ;	// 実行/ACL/filterを通常設定へ混ぜません
	std::uint32_t specialValueIndex{} ;						// 元比較順の固定位置だけを数えます
	// 既知の別作用登録は一device内でも別検証を必要とします
	if( std::ranges::any_of( SPECIAL_VALUES, [&]( const auto name) {
		   ++specialValueIndex ;
		   return equalName( values[2], name) ;
	   })) {
		return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
								  NeedsAddRegDiagnosticStage::SPECIAL_VALUE, specialValueIndex) ;
	}

	int flags{} ;	// 省略/空flagsの既定REG_SZです
	// 数値flagsの解析失敗を0へ変換しません
	if( !values[3].empty() && !SetupGetIntField( &setting, 4U, &flags)) {
		return needsAddRegFailure( diagnostic, E_INVALIDARG,
								  NeedsAddRegDiagnosticStage::FLAGS_PARSE) ;
	}

	// 型以外の変更flag、未採用型、削除やkey権限変更を拒否します
	if( flags != 0 && flags != 0x00010001 && flags != 0x00020000) {
		return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
								  NeedsAddRegDiagnosticStage::FLAGS,
								  static_cast<std::uint32_t>( flags)) ;
	}

	int dword{} ;	// DWORDの全値をWindowsの同じ数値parserへ照合します
	// 不正型や欠損DWORDを文字列として許可しません
	if( flags == 0x00010001 && (fields != 5U || !SetupGetIntField( &setting, 5U, &dword))) {
		return needsAddRegFailure( diagnostic, E_INVALIDARG, NeedsAddRegDiagnosticStage::DWORD_VALUE,
								  fields) ;
	}

	std::wstring lower = values[4] ;	// 実行file参照を検出する端末内copyです
	// ASCIIの大小文字だけを同値化し、元値は出力しません
	for( auto &value : lower) {
		value = value >= L'A' && value <= L'Z' ? static_cast<wchar_t>( value - L'A' + L'a') : value ;
	}

	const std::uint32_t programReference = lower.find( L".exe") != lower.npos   ? 1U
										   : lower.find( L".dll") != lower.npos ? 2U
										   : lower.find( L".sys") != lower.npos ? 3U
										   : lower.find( L".com") != lower.npos
											   ? 4U
											   : 0U ;	// 元短絡順で閉じた拡張子だけを保持します
	// 未照合のfile登録を単なる設定文字列へ弱めません
	if( programReference != 0U) {
		return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
								  NeedsAddRegDiagnosticStage::PROGRAM_REFERENCE, programReference) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Needs到達先のAddRegを明示文脈と全行の有限policyへ照合します
 * @param[in] inf 同同期の検証済みdocument読取handleです
 * @param[in,out] line 元到達節のAddReg行です。呼出し中だけ借用します
 * @param[in] contexts DDInstallは1、HWは2、未対応文脈は4のbit集合です
 * @param[in,out] registryRows 全Needsの累積行数です。4096を上限とします
 * @param[in,out] diagnostic 任意の同pair数値診断です。最初の拒否だけを記録します
 * @param[in] system null又は同SYSTEM/INBOX原文・選択DDInstallに結ぶ局所作用文脈です
 * @return 全行確認0、元読取または未対応のHRESULTです。書込みは行いません
 */
//------------------------------------------------------------------------------
NativeError verifyNeedsAddReg( const HINF inf, INFCONTEXT &line, const unsigned char contexts,
							  std::size_t &registryRows, RequiredInfBindingDiagnostic *diagnostic,
							  const NeedsSystemContext *system = nullptr)
{
	const DWORD references = SetupGetFieldCount( &line) ;	// 一AddRegの全参照数です
	// 未選択・Services等の未対応文脈と過大参照を切り捨てません
	if( contexts == 0U || (contexts & ~3U) != 0U || references == 0U || references > 64U ||
	   registryRows > 4096U) {
		return needsAddRegFailure(
			diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
			contexts == 0U || (contexts & ~3U) != 0U ? NeedsAddRegDiagnosticStage::CONTEXT
			: references == 0U || references > 64U	 ? NeedsAddRegDiagnosticStage::REFERENCE_COUNT
												   : NeedsAddRegDiagnosticStage::INITIAL_ROW_BUDGET,
			contexts == 0U || (contexts & ~3U) != 0U ? contexts
			: references == 0U || references > 64U
				? (std::min)( references, DWORD{65U})
				: static_cast<std::uint32_t>( (std::min)( registryRows, std::size_t{4097U}))) ;
	}

	// 正確な同documentの全参照先を読み、後続の不正行も拒否します
	for( DWORD reference = 1U; reference <= references; ++reference) {
		std::wstring section ;									// 元AddRegの完全な参照節名です
		auto		 error = field( line, reference, section) ;	// 有限な同元field読取です
		// 欠損・制御文字を任意節の指定へ変換しません
		if( error != 0U || section.empty() || section.find_first_of( L"[]\r\n") != section.npos) {
			return needsAddRegFailure( diagnostic,
									  error != 0U ? error : static_cast<NativeError>( E_INVALIDARG),
									  error != 0U ? NeedsAddRegDiagnosticStage::SECTION_NAME_READ
												  : NeedsAddRegDiagnosticStage::SECTION_NAME,
									  reference) ;
		}

		const auto security = section + L".security" ;	// 未採用のACL作用を検出する正確な節です
		SetLastError( ERROR_SUCCESS) ;
		const LONG securityRows = SetupGetLineCountW( inf, security.c_str()) ;	// 空節も作用宣言です
		// security宣言を通常設定値へ縮約しません
		if( securityRows >= 0) {
			return needsAddRegFailure(
				diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
				NeedsAddRegDiagnosticStage::SECURITY_DECLARATION,
				static_cast<std::uint32_t>( (std::min)( securityRows, LONG{4097L}))) ;
		}

		const DWORD securityError = GetLastError() ;	// 不在以外のAPI失敗です
		// 不正なsecurity節読取を不在へ補完しません
		if( securityError != ERROR_SUCCESS && securityError != ERROR_SECTION_NOT_FOUND) {
			return needsAddRegFailure( diagnostic, winError( securityError),
									  NeedsAddRegDiagnosticStage::SECURITY_READ) ;
		}

		const LONG rows = SetupGetLineCountW( inf, section.c_str()) ;	// 同元節の全行数です
		// 累積4096行を読み始める前に検査し、欠損節を空設定へ変換しません
		if( rows < 0 || static_cast<std::size_t>( rows) > 4096U - registryRows) {
			return needsAddRegFailure(
				diagnostic,
				rows < 0 ? HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND)
						 : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW),
				rows < 0 ? NeedsAddRegDiagnosticStage::SECTION_ROWS
						 : NeedsAddRegDiagnosticStage::ROW_BUDGET,
				rows < 0 ? 0U
						 : static_cast<std::uint32_t>( (std::min)(
							   registryRows + static_cast<std::size_t>( rows), std::size_t{4097U}))) ;
		}

		// 全行のroot・型・値を確認し、一つでも未対応なら全効果を拒否します
		for( LONG row = 0L; row < rows; ++row) {
			// 途中のinterface追加行も含め、後続HKRへ進む前に同累積上限を守ります
			if( registryRows >= 4096U) {
				return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW),
										  NeedsAddRegDiagnosticStage::ROW_BUDGET, 4097U) ;
			}

			INFCONTEXT setting{} ;	// 同元registry設定の一行です
			// 別節や不完全な行を先頭行で補完しません
			if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( row), &setting)) {
				return needsAddRegFailure( diagnostic, winError( GetLastError()),
										  NeedsAddRegDiagnosticStage::ROW_READ,
										  static_cast<std::uint32_t>( row) + 1U) ;
			}

			const DWORD fields =
				// 一つの値だけをHKR最大5/SYSTEM最大20fieldで読みます
				SetupGetFieldCount( &setting) ;
			// 削除/複数binary等の別構文を切り捨てて許可しません
			if( fields < 3U || fields > (system ? 20U : 5U)) {
				return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
										  NeedsAddRegDiagnosticStage::FIELD_COUNT,
										  (std::min)( fields, DWORD{6U})) ;
			}

			std::array<std::wstring, 20U> values ;	// SYSTEM binaryを含む全fieldを有限長で所有します
			// flagsや値も含め全fieldを読むため、途中の長さ違反を省略しません
			for( DWORD index = 1U; index <= fields; ++index) {
				error = field( setting, index, values[index - 1U]) ;
				// 全fieldの元取得失敗を保持します
				if( error != 0U) {
					return needsAddRegFailure( diagnostic, error,
											  NeedsAddRegDiagnosticStage::FIELD_READ, index) ;
				}
			}

			// 追加の標準作用は同原SYSTEM/選択文脈からだけ許可します
			if( system && equalName( values[0], L"HKLM")) {
				error = verifySystemMediaRow( inf, setting, values, fields, *system, registryRows,
											 diagnostic) ;
				// 全row成立前に成功件数を増やしません
				if( error != 0U) {
					return error ;
				}

				// 追加interface行を含む同累積上限も維持します
				if( registryRows >= 4096U) {
					return needsAddRegFailure( diagnostic, HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW),
											  NeedsAddRegDiagnosticStage::ROW_BUDGET, 4097U) ;
				}

				++registryRows ;
				continue ;
			}

			error = verifyRelativeNeedsRow( setting, values, fields, diagnostic) ;
			// 同元policyの拒否を後続正常値で消しません
			if( error != 0U) {
				return error ;
			}

			++registryRows ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元選択seedから正確なNeeds辺だけへHKRの設置文脈を伝播します
 * @param[in] result 解決と全証拠を別に確認済みの同graphです
 * @param[in] seeds 元DDInstallと実在付随節です。先頭が基本選択です
 * @param[in] rootIdentity 同graphの元内容documentです
 * @return sectionsと同順の文脈bitです。未到達は0、未対応の経路は4を保持します
 */
//------------------------------------------------------------------------------
std::vector<unsigned char> needsRegistryContexts( const InfDependencyNativeResult	&result,
												 const std::span<const std::wstring> seeds,
												 const std::uint64_t				 rootIdentity)
{
	std::vector<unsigned char> contexts(
		// 同graphの固定ordinalです
		result.dependency.sections.size()) ;
	std::vector<std::size_t> pending ;	// 各bitの追加時だけ処理し最大3×1024項目です
	// 同rootの実在seedだけに文脈を付け、節名のsuffixから別INFを推測しません
	for( std::size_t index = 0U; index < result.dependency.sections.size(); ++index) {
		const auto &section = result.dependency.sections[index] ;	// 元訪問節です
		// 別documentや未選択節はseedへ昇格しません
		if( section.identity == rootIdentity &&
		   std::ranges::find( seeds, section.section) != seeds.end()) {
			contexts[index] = equalName( section.section, seeds.front())			   ? 1U
							  : equalName( section.section, seeds.front() + L".HW") ? 2U
																				   : 4U ;
			pending.push_back( index) ;
		}
	}

	// 有限graphの元参照だけを辿り、混在する未対応文脈も消しません
	for( std::size_t position = 0U; position < pending.size(); ++position) {
		const auto source = pending[position] ;	// 直前に文脈が増えた同元節です
		// 元Needsの全参照を処理し、共通節へ複数文脈が流れた事実を保持します
		for( const auto &edge : result.dependency.edges) {
			// Include自体は設置文脈を持つ効果節ではありません
			if( edge.directive != InfDependencyDirective::NEEDS ||
			   edge.sourceIdentity != result.dependency.sections[source].identity ||
			   !equalName( edge.sourceSection, result.dependency.sections[source].section)) {
				continue ;
			}

			// 元target identityと完全節名の一意な対象だけへ伝播します
			for( std::size_t target = 0U; target < contexts.size(); ++target) {
				const auto &section = result.dependency.sections[target] ;	// 元対象節です
				const auto	merged	= static_cast<unsigned char>(
					  contexts[target] | contexts[source]) ;	// 全incoming文脈です
				// 新bitがない共有節は再処理しません
				if( section.identity == edge.targetIdentity &&
				   equalName( section.section, edge.target) && merged != contexts[target]) {
					contexts[target] = merged ;
					pending.push_back( target) ;
				}
			}
		}
	}

	return contexts ;
}

/** @brief 実loaderの固定documentと署名根拠 */
struct NativeDocument {
	/// 共通核へ渡す独立証拠
	InfDependencyDocument	   value ;
	/// 固定INF fileの安定位置
	std::size_t				   fileIndex{} ;
	/// 未取得ならMAX_FILESの署名CAT位置
	std::size_t				   catalogIndex{MAX_FILES} ;
	/// 未取得ならMAX_FILESの対応Driver Store INF位置
	std::size_t				   storeIndex{MAX_FILES} ;
	/// 同一CATで開始時と終了時に検査するINF自身と収集原本の全参照file
	std::vector<std::wstring>  catalogMembers ;
	/// SetupAPIが返した元署名分類。maskしない
	DWORD					   signerScore{SIGNERSCORE_UNKNOWN} ;
	/// 元診断を保持する独立finding
	InfDependencyNativeFinding finding ;
} ;

/** @brief 一回の収集内容検査に限って借用する原閉包、全アーカイブ一覧と実選択です */
struct CollectorDependencySource {
	/// 抽出時に原size/hashと各INFのCAT・参照fileを固定した閉包です
	const OfficialDriverClosure		 &closure ;
	/// 同じ容器に元から存在した全通常fileです。未展開のINFも含みます
	std::span<const OfficialZipEntry> archiveEntries ;
	/// AMD64 Modelsから選択した正確な基本節名です
	std::wstring_view				  selectedBase ;
	/// 公式Netの元Modelsが選んだ仮想Wi-Fiバスの依存だけを検査する場合trueです
	bool							  scopedWifiBus{} ;
	/// 公式USB Bluetoothの空媒体と三つの元委譲節を検査した場合true
	bool							  scopedBluetoothUsb{} ;
} ;

/** @brief 一同期runのfile固定・OS根拠とcallbackを所有する */
class NativeLoader {
public:
	/**
	 * @brief 保護workspaceと閉じたmember一覧を同期借用する
	 * @param[in] workspace package所有領域
	 * @param[in] members 全INF memberの固定一覧
	 * @param[in] context 開始OS観測
	 * @param[in] binding 使用中固定の封印所有者。旧経路ではnullptr
	 * @param[in] session 同じ生存issuer。旧経路ではnullptr
	 * @param[in] archiveWorkspace 元取得領域。旧経路ではnullptr
	 * @param[in] content 元Common検査の所有結果。旧経路ではnullptr
	 * @param[out] diagnostic 元HRESULTを変更しない任意の数値診断です
	 * @param[in] selectedBase 元Commonの正規選択基本節です。旧入口は空です
	 * @param[in] storageFacts 同原選択を独立readerで確認した非権限値です。同期終了まで借用し、通常入口はnullです
	 * @param[in] collector 収集専用の原閉包と全一覧です。端末と観測入口はnullです
	 * @param[in] registeredDeviceRead 自動起動補助と同じ選択機器を読取する同期操作。指定しない入口はnull
	 */
	NativeLoader( const OfficialDownloadWorkspace			&workspace,
				 std::span<const InfDependencyPackageMember> members,
				 const InfDependencyContext &context, const OfficialInfArchiveBinding *binding,
				 const OfficialAcquisitionSession  *session,
				 const OfficialDownloadWorkspace   *archiveWorkspace,
				 const CommonInfInspection		   *content				 = nullptr,
				 RequiredInfBindingDiagnostic	   *diagnostic			 = nullptr,
				 std::wstring_view					selectedBase		 = {},
				 const SelectedStorageServiceFacts *storageFacts		 = nullptr,
				 const CollectorDependencySource   *collector			 = nullptr,
				 const StorageRegisteredDeviceRead *registeredDeviceRead = nullptr)
		: workspace_( workspace), members_( members), context_( context), binding_( binding),
		  session_( session), archiveWorkspace_( archiveWorkspace), content_( content),
		  collector_( collector),
		  collectorHdc_( collector &&
						!collector->closure.packages.front().nativeHdcInstallGroups.empty()),
		  nativeHdc_( collectorHdc_ || (storageFacts && equalName( storageFacts->className, L"HDC"))),
		  effectClosure_( collector ? &collector->closure : (content ? &content->closure : nullptr)),
		  diagnostic_( diagnostic),
		  selectedBase_( collector ? collector->selectedBase : selectedBase),
		  storageFacts_( storageFacts), registeredDeviceRead_( registeredDeviceRead)
	{
	}
	/**
	 * @brief rootを固定し共通核と全根拠の再確認へ接続する
	 * @param[in] rootIndex 開始member位置
	 * @param[in] seeds 明示節群
	 * @param[out] result 全成功時だけ保持する非実行結果
	 * @return 完了0、最初のHRESULT
	 */
	NativeError run( std::size_t rootIndex, std::span<const std::wstring> seeds,
					InfDependencyNativeResult &result) ;
	//------------------------------------------------------------------------------
	/**
	 * @brief 標準シリアルページの署名とexportを固定して再照合する
	 * @param[out] proof 現Windowsの固定DLLと保護の証拠。失敗時は空
	 * @return 元署名と同じexportが確認できた場合0、その他は原診断
	 */
	//------------------------------------------------------------------------------
	NativeError inspectSerialPropertyPage( WindowsSystemFileTrust &proof) ;
	/**
	 * @brief 固定した正規の仮想無線バスINFの内容証明を同期で照会します
	 * @param[in] inspect 署名済み同梱INFと対応Storeの絶対パス及び同元バイトを借用します
	 * @return 元署名と内容検査の前後確認が成立した場合0です
	 */
	NativeError inspectProtectedWifiBusInf(
		const std::function<NativeError( const std::wstring &, std::wstring_view,
										std::span<const std::byte>)> &inspect) ;

private:
	/// 呼出し終了まで有効なpackage所有者
	const OfficialDownloadWorkspace			   &workspace_ ;
	/// 呼出し中固定される全INF member
	std::span<const InfDependencyPackageMember> members_ ;
	/// run開始時のOSと観測ID
	InfDependencyContext						context_ ;
	/// 呼出し終了まで全元／派生fileを固定する非所有の封印結果。旧経路はnullptr
	const OfficialInfArchiveBinding			   *binding_ ;
	/// 封印結果を発行した非所有の生存issuer。旧経路はnullptr
	const OfficialAcquisitionSession		   *session_ ;
	/// 非所有の元取得領域。旧経路はnullptr
	const OfficialDownloadWorkspace			   *archiveWorkspace_ ;
	/// 私有factoryだけが渡す、全byteとCATを前後確認する元内容です
	const CommonInfInspection				   *content_ ;
	/// 収集内容の元選択と抽出前一覧です。従来入口ではnullです
	const CollectorDependencySource			   *collector_ ;
	/// 署名付き元SYSを持つHDCの収集検査を実行する場合true
	const bool									collectorHdc_ ;
	/// 収集または端末の同梱SYS形式にHDCの作用検査を使う場合true
	const bool									nativeHdc_ ;
	/// 作用検査で照合する同じ署名閉包です。旧観測と取得由来だけの入口ではnullです
	const OfficialDriverClosure				   *effectClosure_ ;
	/// 同期callだけが所有する任意の非機密診断先です。実行可否へ読み込みません
	RequiredInfBindingDiagnostic			   *diagnostic_ ;
	/// 既Common選択の元基本名です。旧read-only/Acquired入口は空です
	std::wstring								selectedBase_ ;
	/// 同期中の同元選択から実readerが固定したstorage factsです
	const SelectedStorageServiceFacts		   *storageFacts_{} ;
	/// 元選択機器の現用登録を確定する同期操作。収集と機器未指定の読取ではnullptr
	const StorageRegisteredDeviceRead		   *registeredDeviceRead_ ;
	/// 全PACKAGE作用とexact現serviceを検査した原値です
	std::optional<StorageInfEffects>			storageEffects_ ;
	/**
	 * @brief 同じ同期バックエンドで指定されたカーネルサービスの現在構成と保護を読む
	 * @param[in] name 正確なサービス名
	 * @param[out] evidence 構成と保護が検証できた場合だけ格納する元観測
	 * @return 成立時0、正式の不在・読取・保護に問題があればHRESULT
	 * @note 現在ファイルを開かず、試験用バックエンドの不足を実SCMへ補完しない
	 */
	NativeError readStorageServiceConfiguration( std::wstring_view	   name,
												SystemServiceEvidence &evidence) ;
	/**
	 * @brief 自動起動補助の元効果と現在のWindows共有設定を読み取り専用で照合する
	 * @param[in] effects 署名付き選択の検証済みACPIとAutoLogger作用
	 * @param[out] shared 現在サービスと二つの共有先の完全な観測。失敗時は空
	 * @param[out] stage 手順の固定診断番号。成功時は0
	 * @return 同じ制御セットと許容された現在値が成立すれば0、それ以外はHRESULT
	 * @note 同じ値が既存提供元を示すとは判定しない。サービス、設定、導入資格は変更しない
	 */
	NativeError readStorageSharedSettings( const StorageInfEffects	&effects,
										  StorageSharedHostSnapshot &shared, std::uint32_t &stage) ;
	/**
	 * @brief 元選択が変更する起動サービスと現在SYSを同じ端末から読む
	 * @param[in] selected 署名と元作用を検査した候補
	 * @param[in] device 同じ選択に関係する全現用登録
	 * @param[out] boot 構成と元署名への照合結果。失敗時は空
	 * @return 読取り成立0、照会・保護・位置の不成立はHRESULT
	 * @note 保護付き配置とSCMを読み取る。サービスを起動、登録、変更しない
	 */
	NativeError readStorageAutomaticBoot( const SelectedStorageServiceFacts	  &selected,
										 const StorageAutomaticDeviceSnapshot &device,
										 StorageAutomaticBootSnapshot		  &boot) ;
	/**
	 * @brief 自動起動補助の現用機器と候補に関係する現在値を一組として読み取る
	 * @param[in] effects 候補の署名付き元作用
	 * @param[in] sourceIdentity 同じ候補を検証した元文書の内部識別
	 * @param[out] host 各署名元を照合した現在値。失敗時は空
	 * @param[out] stage 元診断の固定段階
	 * @return 現用機器と共有先が同じ状態として読めた場合0、失敗はHRESULT
	 */
	NativeError readStorageAutomaticHost( const StorageInfEffects	  &effects,
										 std::uint64_t				   sourceIdentity,
										 StorageAutomaticHostSnapshot &host, std::uint32_t &stage) ;
	/**
	 * @brief 署名付き自動起動候補の現在共有先を読み、変更可否を分類する
	 * @param[in,out] storage 元作用を照合済みの候補。成功時だけ現用観測と起動サービスを保持する
	 * @param[in] sourceIdentity 同じ候補を保持する元文書の内部識別
	 * @param[out] stage 最初の読取り不成立または所有が未確認の共有先を示す固定診断
	 * @return 安定した現用観測と変更範囲が成立する場合0、それ以外はHRESULT
	 * @note 現在状態を変更せず、適用資格は発行しない
	 */
	NativeError verifyStorageAutomaticHost( StorageInfEffects &storage, std::uint64_t sourceIdentity,
										   std::uint32_t &stage) ;
	/**
	 * @brief exact storage現serviceと元binaryを読取専用で固定します
	 * @param[in] name 同原選択又はDependenciesのservice名です
	 * @param[out] evidence 全原config/SD成立時だけの元値です
	 * @param[out] binarySha256 現在SYSのSHA-256が必要な場合の出力。nullptr可
	 * @return 明示不存在又は元read/型/path/byte固定のHRESULTです
	 * @note 内部表の欠損をnativeへ補完せず、提案新版と現在旧binaryを一致させません
	 */
	NativeError readStorageService( std::wstring_view name, SystemServiceEvidence &evidence,
								   std::wstring *binarySha256 = nullptr) ;
	/**
	 * @brief 現在のWindowsの起動グループ順序を取得する
	 * @param[out] order 正しい順序の元位置。失敗時は空の値
	 * @return 順序が正しければ0、読取や元配置に問題があればHRESULT
	 * @note 試験用APIに欠落があっても実際のレジストリを読み取らない
	 */
	NativeError readStorageBootLoadOrder( StorageLoadOrder &order) ;
	/// run中保持するINF・CAT・対応Store file。最大256
	std::vector<std::unique_ptr<PinnedFile>> files_ ;
	/// 共通核と同じ一意document。最大64
	std::vector<NativeDocument>				 documents_ ;
	/// 全固定fileの累積実byte。最大128 MiB
	std::uint64_t							 totalBytes_{} ;
	/// APIで取得した現在Windows directory
	std::wstring							 windows_ ;
	/// Workspace内のroot基準位置
	std::wstring							 packageRoot_ ;
	/// 同runで原helper/CAT/trust/権限を独立検証した完全tupleです
	std::vector<WindowsSystemFileTrust>		 systemFiles_ ;
	/// 二相検査で全消費した同原文の作用tupleです
	SystemInfEffects						 typedEffects_ ;
	/// 収集選択から到達した署名済みWindows同梱sdbus.infの正確な文書IDです
	std::uint64_t							 sdBusInboxDocument_{} ;
	/// 唯一の元ページを持つPortsから到達したWindows同梱msports.infの文書IDです
	std::uint64_t							 msPortsInboxDocument_{} ;
	/// 収集元のNVMe委譲で正規Windows INFに到達したときの文書識別子です
	std::uint64_t							 storNvmeInboxDocument_{} ;
	/// 元HDCの委譲で署名・Storeを照合した標準AHCIの原文書
	std::uint64_t							 storAhciInboxDocument_{} ;
	/// 正規WindowsとDriver Storeが一致した収集専用同梱WinUSB文書。適用なしの場合0
	std::uint64_t							 winUsbInboxDocument_{} ;
	/// 元NVMeのHW節が参照する正規PCI INFの文書識別子です
	std::uint64_t							 pciNvmeInboxDocument_{} ;
	/// 固定RunOnceだけが発行する遅延登録factです
	bool									 delayedRegistration_{} ;
	/// 元用途観測と新型が共有する実際の節/行予算です
	std::vector<InfDependencyVisitedSection> observedSections_ ;
	/// 元用途観測で既に消費した全行です
	std::size_t								 observedRows_{} ;

	/**
	 * @brief fileと全祖先を安全に固定し実hashを計算する
	 * @param[in] path 検査対象の通常絶対位置
	 * @param[in] maximumBytes 一file上限
	 * @param[out] index 成功時の固定file位置
	 * @param[out] missing 明示openの不在だけを返す任意出力。nullptr可
	 * @return 完了0、path・容量・読取失敗のHRESULT
	 */
	NativeError		pin( const std::wstring &path, std::uint64_t maximumBytes, std::size_t &index,
						bool *missing = nullptr) ;
	/**
	 * @brief 固定fileのpath・identity・hashを再確認する
	 * @param[in] index 安定したfile位置
	 * @return 全一致0、改変／API失敗のHRESULT
	 */
	NativeError		recheckFile( std::size_t index) ;
	/**
	 * @brief byte固定した一INFと署名／system由来を保持する
	 * @param[in] path 候補の実位置
	 * @param[in] member package期待member。systemではnullptr
	 * @param[out] document 成功時の共通snapshot
	 * @param[out] fileMissing INF自身の明示openで不在を観測した場合だけtrue。nullptr可
	 * @return 存在観測完了0、byte／path等の全体失敗HRESULT
	 */
	NativeError		observe( const std::wstring &path, const InfDependencyPackageMember *member,
							InfDependencyDocument &document, bool *fileMissing = nullptr) ;
	/**
	 * @brief 署名と由来の根拠をbyte固定する。失敗もfindingに残す
	 * @param[in,out] document 安定したINF snapshotと根拠位置
	 * @return 境界確認完了0、固定fileの重大失敗HRESULT
	 */
	NativeError		trust( NativeDocument &document) ;
	/**
	 * @brief 検証済み署名のCAT位置・完全score・memberを終了時に再確認する
	 * @param[in] document 開始時に固定した署名根拠
	 * @return 全一致0、失効・根拠変更・API失敗のHRESULT
	 */
	NativeError		recheckTrust( const NativeDocument &document) ;
	/**
	 * @brief 同節Includeの明示候補を全照会する
	 * @param[in] source 元の固定document
	 * @param[in] target 有限Include相対名
	 * @param[out] output 全照会成功時の候補
	 * @return 完了0、最初の全体HRESULT
	 */
	NativeError		lookup( const InfDependencyDocument &source, std::wstring_view target,
						   InfDependencyLookup &output) ;
	/**
	 * @brief 一固定INFの明示節からInclude／Needsだけを読む
	 * @param[in] document 固定snapshot
	 * @param[in] name 原明示節名
	 * @param[out] output 完了時の存在状態と有限参照
	 * @return 完了0、構文・容量・改変のHRESULT
	 */
	NativeError		section( const InfDependencyDocument &document, std::wstring_view name,
							InfDependencySection &output) ;
	/**
	 * @brief 共通identityから固定documentを取得する
	 * @param[in] identity 非零のrun内identity
	 * @return 存在すれば借用pointer、不明ならnullptr
	 */
	NativeDocument *find( std::uint64_t identity) ;
	/**
	 * @brief Needs先の有限CopyFilesを実byteとCATへ結合し、AddRegの到達効果を検査します
	 * @param[in] result 解決済みの同run graphです
	 * @param[in] seeds 元選択DDInstallと実在付随節です
	 * @return 全効果確認0、未知・欠損・署名・byte差のHRESULTです
	 */
	NativeError		verifyNeedsEffects( const InfDependencyNativeResult &result,
									   std::span<const std::wstring>	seeds) ;
	/**
	 * @brief 固定Windows登録helperの元byte/署名/権限を同runへ結びます
	 * @param[in] recheck trueなら終了時も独立にtrust/権限を確認し原tupleと比較します
	 * @return 全成立0、元native/tuple差のHRESULTです
	 */
	NativeError		verifyStreamingComponents( bool recheck = false) ;
	/**
	 * @brief 同原SYSTEMの単一moduleを元file/CAT/権限tupleへ固定します
	 * @param[in] path 同Windowsの正確な提供位置です
	 * @param[in] recheck trueなら元tupleとfresh実検査を比較します
	 * @return 元trust/完全tuple一致0、元error又は差異のHRESULTです
	 */
	NativeError		verifySystemFile( const std::wstring &path, bool recheck = false) ;
	/**
	 * @brief 確認済み同梱INFのサービス実体を同じStore原媒体とCATへ結ぶ
	 * @param[in] document INBOX署名とStoreを確認済みの同文書です
	 * @param[in] path 元サービスが指定する正規System32又は同じStore上の位置です
	 * @return 原媒体・配備先・CATが一致した場合0、失敗時は元HRESULTです
	 */
	NativeError verifyInboxServiceModule( const NativeDocument &document, const std::wstring &path) ;
	/**
	 * @brief 仮想Wi-Fiバスの元コピーが元Store内の同名ファイルだけを指すことを確認する
	 * @param[in] document 元作用と同一Storeの署名・SYSが検査済みの文書です
	 * @return コピーの元指定が一致して0、別宛先・追加作用・API失敗のHRESULTです
	 */
	NativeError verifyWifiBusStoreCopy( const NativeDocument &document) const ;
	/**
	 * @brief USB Bluetoothの機器設定、共有登録、保護ファイルを同梱文書と現在のWindowsに結ぶ
	 * @param[in] result 同期中に解決した同じ依存グラフ
	 * @param[in] seeds 公式USB選択の元基本節、HW節、Services節をこの順に保持する一覧
	 * @return 機器と共有設定の元宣言、資源の署名・バイトが一致して0、失敗時は元HRESULT
	 * @note 読取り専用。機器および共有レジストリの現在値と導入資格は確定しない
	 */
	NativeError verifyBluetoothUsbActions( const InfDependencyNativeResult &result,
										  std::span<const std::wstring>	   seeds) ;
	/**
	 * @brief 元Ports基本節の一つの登録をSystem32の署名と同一バイトのAMD64 exportに結ぶ
	 * @return 原DLLの署名・権限・hash・export検査成功時0、その他は元HRESULTです
	 */
	NativeError verifySerialPropertyPage() ;
	/**
	 * @brief 元SYSTEM選択Needsの全型を二相列挙/実体/関係へ接続します
	 * @param[in] result 同原graphと全document証拠です
	 * @param[in] seeds 元正規DDInstallと実在付随節です
	 * @param[in,out] rows 元AddRegの共同累積行数です
	 * @return 全作用成立0、元API又は限定型の拒否HRESULTです
	 */
	NativeError verifyTypedEffects( const InfDependencyNativeResult &result,
								   std::span<const std::wstring> seeds, std::size_t &rows) ;
	/**
	 * @brief 全到達節とVersion／sourceのfile用途を非実行で観測する
	 * @param[in,out] result 全体成功前のgraphと有限用途観測
	 * @return 全行観測成功0、入力・読取・容量・元byte差のHRESULT
	 * @note payload位置と全member署名は解決せず、実SYSTEM fileを複写しない
	 */
	NativeError observeFileUses( InfDependencyNativeResult &result) ;
} ;

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 相対member位置と絶対local DOS位置の構文を検査する
 * @param[in] path 原位置。正規化やfilesystem探索を行わない
 * @param[in] absolute trueの場合は通常のdrive絶対path、falseの場合はASCII相対path
 * @return 構文合格の場合true。実path認証ではない
 */
//------------------------------------------------------------------------------
bool validInfDependencyPath( std::wstring_view path, bool absolute) noexcept
{
	// 通常DOS位置以外や埋込みNULを正規化で救済しない
	if( path.empty() || path.size() >= MAX_PATH ||
	   (absolute &&
		(path.size() < 4U || path[1] != L':' || path[2] != L'\\' ||
		 !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))))) {
		return false ;
	}

	std::size_t begin = absolute ? 3U : 0U ;	// driveを除いたcomponent開始
	// 全componentでpath切替・device aliasと末尾正規化を拒否する
	while( begin < path.size()) {
		const auto end	= path.find( L'\\', begin) ;									// 次componentの境界
		const auto part = path.substr( begin, end == path.npos ? end : end - begin) ;	// 有限借用
		// ASCII相対名と絶対位置の制御・予約文字を確認する
		if( part.empty() || part == L"." || part == L".." || part.back() == L'.' ||
		   part.back() == L' ' || reservedName( part) ||
		   std::ranges::any_of( part, [absolute]( wchar_t value) {
			   // 相対名は既存workspaceと同じASCII境界に限定する
			   return value < L' ' || value == 0x7f || (!absolute && value > 0x7e) ||
					  std::wstring_view( L"/:<>|\"?*%").find( value) != std::wstring_view::npos ;
		   })) {
			return false ;
		}

		// 最後のcomponentを確認したら完了する
		if( end == path.npos) {
			return true ;
		}

		begin = end + 1U ;
	}

	return false ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief fileと全祖先を安全に固定し実hashを計算する
 * @param[in] canonicalPath 検査対象の通常絶対位置
 * @param[in] maximumBytes 一file上限
 * @param[out] index 成功時の固定file位置
 * @param[out] missing 明示openの不在だけを返す任意出力。nullptr可
 * @return 完了0、path・容量・読取失敗のHRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::pin( const std::wstring &canonicalPath, std::uint64_t maximumBytes,
							  std::size_t &index, bool *missing)
{
	std::wstring path = canonicalPath ;	// 製品は常に原位置のidentity mappingです
	// 所有内部fixtureの明示全対応以外にread位置を変更しません
	if( const auto api = inf_dependency_native_detail::activeApi() ; api && api->readPath) {
		const auto mapped = api->readPath(
			canonicalPath, path) ;	// 独立した条件又は到達件数です。別条件の成功を借用しません
		// 元の不正/不一致又は不足を成功へ補完しません
		if( mapped != 0U || path.empty()) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			// 完全表の明示不在も元openErrorと同じ観測へ結びます
			if( missing != nullptr) {
				*missing = mapped == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ||
						   mapped == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND) ;
			}

			return mapped != 0U ? mapped : E_INVALIDARG ;
		}
	}

	// 再確認・属性等の失敗をopen不在へ変換しない初期値
	if( missing != nullptr) {
		*missing = false ;
	}

	// Cached pathも要求size境界を変更しない
	for( std::size_t position = 0U; position < files_.size(); ++position) {
		// 同じ確認済みpathだけを再利用する
		if( equalName( files_[position]->path, path)) {
			index = position ;
			return files_[position]->bytes <= maximumBytes
					   ? recheckFile( position)
					   : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}
	}

	// 過大集合と任意pathからfileを開かない
	if( !validInfDependencyPath( path, true) || files_.size() >= MAX_FILES) {
		return E_INVALIDARG ;
	}

	auto pinned	 = std::make_unique<PinnedFile>() ;	// run全体へ移す単独所有者
	pinned->path = path ;
	// 祖先をrootから順に固定し、子を開く前にreparseを拒否する
	for( std::size_t end = 3U; end < path.size(); ++end) {
		// Component境界だけをdirectoryとして確認する
		if( end != 3U && path[end] != L'\\') {
			continue ;
		}

		const std::wstring parent = path.substr( 0U, end) ;	// drive rootは終端separatorを含む
		// 子を開く間のrenameを拒否する祖先handle
		Handle			   handle( CreateFileW(
			parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
		// Directoryを固定できなければ子の読取りへ進まない
		if( handle.get() == INVALID_HANDLE_VALUE) {
			return openError( GetLastError(), missing) ;
		}

		const auto error = checkHandle( handle.get(), parent, true) ;	// 実位置・属性の一致
		// Reparseや位置差の根拠を後続成功で消さない
		if( error != 0) {
			return error ;
		}

		pinned->parents.push_back( std::move( handle)) ;
	}

	pinned->file.reset(
		CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)) ;
	// File不在と既存writerとの競合を元診断で返す
	if( pinned->file.get() == INVALID_HANDLE_VALUE) {
		return openError( GetLastError(), missing) ;
	}

	NativeError error = checkHandle( pinned->file.get(), path, false) ;	// 実fileの固定境界
	// File属性・identity取得を成功条件に含める
	if( error != 0 || !GetFileInformationByHandle( pinned->file.get(), &pinned->information)) {
		return error != 0 ? error : winError( GetLastError()) ;
	}

	pinned->bytes = (static_cast<std::uint64_t>( pinned->information.nFileSizeHigh) << 32U) |
					pinned->information.nFileSizeLow ;
	// size上限をhash読取前に確認し、全固定byte予算にも含める
	if( pinned->bytes == 0U || pinned->bytes > maximumBytes ||
	   pinned->bytes > MAX_TOTAL_BYTES - totalBytes_) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	error = computeFileSha256( path, pinned->sha256) ;
	// 固定失敗のfileをcacheへ入れない
	if( error != 0) {
		return error ;
	}

	index = files_.size() ;
	totalBytes_ += pinned->bytes ;
	files_.push_back( std::move( pinned)) ;
	return recheckFile( index) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定fileのpath・identity・hashを再確認する
 * @param[in] index 安定したfile位置
 * @return 全一致0、改変／API失敗のHRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::recheckFile( std::size_t index)
{
	const auto				  &file = *files_.at( index) ;					// 同期run内の安定所有者
	BY_HANDLE_FILE_INFORMATION information{} ;								// 終了時の物理identity
	NativeError error = checkHandle( file.file.get(), file.path, false) ;	// 位置と種類の再確認
	// Byte再確認前にfile差替えを止める
	if( error != 0 || !GetFileInformationByHandle( file.file.get(), &information)) {
		return error != 0 ? error : winError( GetLastError()) ;
	}

	// 同hashに見えても異なる物理fileや書込時刻への差替えを許可しない
	if( !sameFile( file.information, information)) {
		return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
	}

	std::wstring hash ;	// 完全byteの終了hash
	error = computeFileSha256( file.path, hash) ;
	return error != 0 ? error : (hash == file.sha256 ? 0 : HRESULT_FROM_WIN32( ERROR_FILE_INVALID)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通identityから固定documentを取得する
 * @param[in] identity 非零のrun内identity
 * @return 存在すれば借用pointer、不明ならnullptr
 */
//------------------------------------------------------------------------------
NativeDocument *NativeLoader::find( std::uint64_t identity)
{
	const auto found = std::ranges::find_if( documents_, [identity]( const auto &document) {
		// Nameやhashからidentityを推測しない
		return document.value.identity == identity ;
	}) ;
	return found == documents_.end() ? nullptr : &*found ;
}

//------------------------------------------------------------------------------
/**
 * @brief byte固定した一INFと署名／system由来を保持する
 * @param[in] path 候補の実位置
 * @param[in] member package期待member。systemではnullptr
 * @param[out] document 成功時の共通snapshot
 * @param[out] fileMissing INF自身の明示openで不在を観測した場合だけtrue。nullptr可
 * @return 存在観測完了0、byte／path等の全体失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::observe( const std::wstring			   &path,
								  const InfDependencyPackageMember *member,
								  InfDependencyDocument &document, bool *fileMissing)
{
	std::size_t file{} ;	// 候補INFの固定file位置
	NativeError error =
		// 明示不在とbyte結合を分離する
		pin( path, MAX_INF_BYTES, file, fileMissing) ;
	// 実byteが読めない場合を存在観測へ弱めない
	if( error != 0) {
		return error ;
	}

	// 抽出器が保持した実期待値と結合する
	if( member != nullptr &&
	   (files_[file]->sha256 != member->sha256 || files_[file]->bytes != member->byteCount)) {
		return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
	}

	// 位置の境界分類。由来検証の成功とは別の値
	const auto origin =
		member == nullptr ? InfDependencyOrigin::SYSTEM : InfDependencyOrigin::PACKAGE ;
	// 同じ物理fileの別名だけを共有し、同hashの別fileを合併しない
	for( const auto &prior : documents_) {
		// 物理identityは開いた実handleから比較する
		if( sameFile( files_[prior.fileIndex]->information, files_[file]->information)) {
			// 別の由来へ同identityを持ち替えない
			if( prior.value.origin != origin || (collector_ && member && prior.fileIndex != file)) {
				return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
			}

			document = prior.value ;
			return 0 ;
		}
	}

	// 核に到達する前にも全documentの有限数を確認する
	if( documents_.size() >= 64U) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	NativeDocument observed ;	// 全検査後にだけ共有するsnapshot
	observed.fileIndex		   = file ;
	observed.value.identity	   = documents_.size() + 1U ;
	observed.value.sha256	   = files_[file]->sha256 ;
	observed.value.byteCount   = files_[file]->bytes ;
	observed.value.origin	   = origin ;
	observed.value.byteBinding = InfDependencyEvidence::VERIFIED ;
	observed.value.context	   = context_ ;
	observed.finding.identity  = observed.value.identity ;
	error					   = trust( observed) ;
	// 固定fileの重大失敗では部分snapshotを残さない
	if( error != 0) {
		return error ;
	}

	// 収集は観測用の未確認・失敗findingを内容成功へ変換せず、元署名・Storeの失敗を返します
	if( collector_ && observed.value.signature != InfDependencyEvidence::VERIFIED) {
		return observed.finding.signatureError != 0U ? observed.finding.signatureError
													 : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// Windows同梱INFは正規位置、完全INBOX score、同byteのStoreをすべて必要とします
	if( collector_ && !member && observed.value.provenance != InfDependencyEvidence::VERIFIED) {
		return observed.finding.provenanceError != 0U ? observed.finding.provenanceError
													  : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 原取得または署名閉包への所属だけを示し、裸の観測一覧から由来を推測しません
	if( member != nullptr && (binding_ != nullptr || effectClosure_ != nullptr)) {
		observed.value.provenance = InfDependencyEvidence::VERIFIED ;
	}

	documents_.push_back( std::move( observed)) ;
	document = documents_.back().value ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名と由来の根拠をbyte固定する。失敗もfindingに残す
 * @param[in,out] document 安定したINF snapshotと根拠位置
 * @return 境界確認完了0、固定fileの重大失敗HRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::trust( NativeDocument &document)
{
	const std::wstring	 path = files_[document.fileIndex]->path ;	// callback内の安定した原位置
	SP_INF_SIGNER_INFO_W signer{} ;									// 現OSの署名根拠と完全score
	signer.cbSize = sizeof( signer) ;
	// Windows署名の失敗は存在と分離して元findingに残す
	const auto signatureError = nativeInfSignature( path, signer) ;	// 元APIの独立診断
	// 検証失敗でも実byteの存在観測は維持する
	if( signatureError != 0) {
		document.value.signature		= InfDependencyEvidence::FAILED ;
		document.finding.signatureError = signatureError ;
		return 0 ;
	}

	// 各固定array内の実終端を確認し、NUL以後の未使用slot値を終端の代替条件にしません
	if( std::wstring_view{signer.CatalogFile, MAX_PATH}.find( L'\0') == std::wstring_view::npos ||
	   std::wstring_view{signer.DigitalSigner, MAX_PATH}.find( L'\0') == std::wstring_view::npos ||
	   signer.CatalogFile[0] == L'\0' || signer.DigitalSigner[0] == L'\0') {
		return E_UNEXPECTED ;
	}

	document.signerScore = signer.SignerScore ;
	const std::wstring catalog( signer.CatalogFile) ;	// 出力しないCATの実位置
	const auto		   under = [&catalog]( const std::wstring &root) {
		// Root文字列だけの前方一致で別directoryを許可しない
		return catalog.size() > root.size() &&
			   equalName( std::wstring_view( catalog).substr( 0U, root.size()), root) ;
	} ; // 末尾separator付きの認証範囲だけへ借用照合する
	const bool allowed = document.value.origin == InfDependencyOrigin::PACKAGE
							 ? under( packageRoot_)
							 : (under( windows_ + L"\\System32\\CatRoot\\") ||
								under( windows_ + L"\\System32\\DriverStore\\FileRepository\\") ||
								// 同じ署名用途の有限領域
								under( windows_ + L"\\WinSxS\\Catalogs\\")) ;
	// 無関係CATを開かず、signature未充足と存在を分ける
	if( !allowed || !validInfDependencyPath( catalog, true)) {
		document.value.signature		= InfDependencyEvidence::FAILED ;
		document.finding.signatureError = HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		return 0 ;
	}

	const OfficialZipEntry *sealedCatalog = nullptr ;	// 封印経路の原CAT metadataの同期借用
	// 全経路で署名を照合したINF自身を終了再確認まで保持します
	document.catalogMembers.push_back( path) ;
	// 署名閉包に元CATがある場合だけ元packageの署名と全memberを検査します
	if( document.value.origin == InfDependencyOrigin::PACKAGE && effectClosure_ != nullptr) {
		const auto relative =
			// 元CAT相対位置です
			std::wstring_view( catalog).substr( packageRoot_.size()) ;
		sealedCatalog = dependencyEntry( effectClosure_->entries, relative) ;
		// 後付けCATを元署名根拠へ昇格しません
		if( sealedCatalog == nullptr) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}

		// 収集は各INFに宣言されたCATを照合し、同じ閉包内でも別INFのCATを流用しません
		if( collector_) {
			const auto package =
				std::ranges::find_if( effectClosure_->packages, [&]( const auto &item) {
					return equalName( workspace_.path( item.infRelativePath), path) ;
				}) ; // この固定INFを原本として検査した一件です
			// 署名者の返したCATが元INFの宣言と異なる場合はmember検査へ進みません
			if( package == effectClosure_->packages.end() ||
			   !equalName( package->catalogRelativePath, relative)) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_NAME) ;
			}

			// 同原INFの全参照fileを開始時・終了時の同じCATmember照合へ結びます
			for( const auto &source : package->sourceFiles) {
				const auto fixed =
					// 原hash付きの閉包memberです
					dependencyEntry( effectClosure_->entries, source) ;
				// 実byteを固定していないfileは、CATだけ合格しても内容検査へ使いません
				if( !fixed) {
					return HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ;
				}

				const auto memberPath =
					// 取得元と同じ保護領域の位置
					workspace_.path( fixed->relativePath) ;
				// 混在媒体は同梱検査の間もメーカー側SYSとDLLを元のまま固定する
				if( package->collectorSerialMedia) {
					std::size_t memberIndex{} ;	// 原閉包に属する実ファイルの固定位置
					const auto	error =
						// 読み取り固定結果
						pin( memberPath, MAX_TOTAL_BYTES, memberIndex) ;
					// 署名が通る別の元ファイルへ取り替えない
					if( error != 0U || files_[memberIndex]->sha256 != fixed->sha256 ||
					   files_[memberIndex]->bytes != fixed->uncompressedSize) {
						return error != 0U ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
					}
				}

				document.catalogMembers.push_back( memberPath) ;
			}
		}
	}

	// package CATを原container由来の固定一覧へ限定し、後から追加したCATを使わない
	if( document.value.origin == InfDependencyOrigin::PACKAGE && binding_ != nullptr) {
		const auto relative =
			// 原相対位置
			std::wstring_view( catalog).substr( packageRoot_.size()) ;
		const auto found =
			std::ranges::find_if( binding_->catalogs(), [&relative]( const auto &member) {
				// 私有封印結果の原位置だけをordinalで照合する
				return equalName( member.relativePath, relative) ;
			}) ; // bindingは同期runの全期間不変
		// 未封印CATを署名済みとせず、独立した取得由来はそのまま保持する
		if( found == binding_->catalogs().end()) {
			document.value.signature		= InfDependencyEvidence::FAILED ;
			document.finding.signatureError = HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
			return 0 ;
		}

		sealedCatalog = &*found ;
	}

	NativeError error = pin( catalog, MAX_CAT_BYTES, document.catalogIndex) ;	// 署名根拠byteの固定
	// CAT固定の競合・容量・改変を単なる署名不足へ弱めない
	if( error != 0) {
		return error ;
	}

	// 固定したCATを元size／hashへ一致させ、署名callbackの名前だけで認定しない
	if( sealedCatalog != nullptr &&
	   (files_[document.catalogIndex]->bytes != sealedCatalog->uncompressedSize ||
		files_[document.catalogIndex]->sha256 != sealedCatalog->sha256)) {
		return TRUST_E_BAD_DIGEST ;
	}

	error = nativeCatalogSignature( catalog, document.catalogMembers) ;
	document.value.signature =
		error == 0 ? InfDependencyEvidence::VERIFIED : InfDependencyEvidence::FAILED ;
	document.finding.signatureError = error ;
	// Package公式由来はこのadapterから昇格させない。別scoreも標準INFと推測しない
	if( error != 0 || document.value.origin != InfDependencyOrigin::SYSTEM ||
	   signer.SignerScore != SIGNERSCORE_INBOX) {
		return 0 ;
	}

	std::wstring storePath ;	// 現在Driver Storeの有限対応位置
	error = nativeDriverStore( path, storePath) ;
	// 元APIの不正応答は未確認へ弱めない
	if( error == E_UNEXPECTED) {
		return error ;
	}

	// OSの対応情報がない場合は存在・署名を維持し、由来だけ未検査にする
	if( error != 0) {
		document.finding.provenanceError = error ;
		return 0 ;
	}

	std::wstring storeRoot =
		windows_ +
		L"\\System32\\DriverStore\\FileRepository\\" ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
	// 内部fixtureの所有Storeだけは、原canonical INF/DIRIDと物理read位置を分けます
	// 固定用途root
	if( const auto api = inf_dependency_native_detail::activeApi() ; api && api->projectedStore) {
		const auto probe = api->projectedStore->path(
			L"Store\\probe.inf") ;	// この同期だけで保持する元値です。許可の代用にしません
		// 元の不正/不一致又は不足を成功へ補完しません
		if( probe.size() < 9U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			return E_INVALIDARG ;
		}

		storeRoot = probe.substr( 0U, probe.size() - std::wstring_view{L"probe.inf"}.size()) ;
	}

	// Storeの明示範囲外をsystem由来と認定しない
	if( storePath.size() <= storeRoot.size() ||
	   !equalName( std::wstring_view( storePath).substr( 0U, storeRoot.size()), storeRoot) ||
	   !validInfDependencyPath( storePath, true)) {
		return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
	}

	error = pin( storePath, MAX_INF_BYTES, document.storeIndex) ;
	// 対応byteを安全に固定できない結果から由来を生成しない
	if( error != 0) {
		return error ;
	}

	const auto &original = *files_[document.fileIndex] ;	// 原INF snapshot
	const auto &stored	 = *files_[document.storeIndex] ;	// OS対応先の固定byte
	const bool	matched =
		// 完全byte結合
		original.sha256 == stored.sha256 && original.bytes == stored.bytes ;
	document.value.provenance =
		matched ? InfDependencyEvidence::VERIFIED : InfDependencyEvidence::FAILED ;
	document.finding.provenanceError = matched ? 0 : HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済み署名のCAT位置・完全score・memberを終了時に再確認する
 * @param[in] document 開始時に固定した署名根拠
 * @return 全一致0、失効・根拠変更・API失敗のHRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::recheckTrust( const NativeDocument &document)
{
	// 未確認／失敗の根拠は再照会で昇格させず、正の証拠だけを失効確認する
	if( document.value.signature != InfDependencyEvidence::VERIFIED) {
		return 0 ;
	}

	SP_INF_SIGNER_INFO_W signer{} ;	// 終了時の独立した署名応答
	signer.cbSize	 = sizeof( signer) ;
	const auto &path = files_[document.fileIndex]->path ;	// 固定INFの有限位置
	// 現在の署名検証失敗後は開始時の成功を使わない
	const auto	error = nativeInfSignature( path, signer) ;	// 終了時の独立した診断
	// 検証済み署名の現在の失敗を保持する
	if( error != 0) {
		return error ;
	}

	// CAT差・分類差と不正終端を同一の証拠とみなさない
	if( document.catalogIndex == MAX_FILES ||
	   std::wstring_view{signer.CatalogFile, MAX_PATH}.find( L'\0') == std::wstring_view::npos ||
	   std::wstring_view{signer.DigitalSigner, MAX_PATH}.find( L'\0') == std::wstring_view::npos ||
	   signer.CatalogFile[0] == L'\0' || signer.DigitalSigner[0] == L'\0' ||
	   signer.SignerScore != document.signerScore ||
	   !equalName( signer.CatalogFile, files_[document.catalogIndex]->path)) {
		return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
	}

	return nativeCatalogSignature( files_[document.catalogIndex]->path, document.catalogMembers) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同節Includeの明示候補を全照会する
 * @param[in] source 元の固定document
 * @param[in] target 有限Include相対名
 * @param[out] output 全照会成功時の候補
 * @return 完了0、最初の全体HRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::lookup( const InfDependencyDocument &source, std::wstring_view target,
								 InfDependencyLookup &output)
{
	output = {} ;
	// 核が扱える相対名でも、nativeで扱えない表現は未検査を維持する
	if( !validInfDependencyPath( target, false)) {
		return 0 ;
	}

	const auto original = find( source.identity) ;	// 既知identityだけを解決する
	// 未知sourceをpath合成へ進めない
	if( original == nullptr) {
		return E_INVALIDARG ;
	}

	const std::wstring sourcePath =
		files_[original->fileIndex]->path ;	// vector再配置から独立した原位置
	const std::wstring parent =
		// 元directory
		sourcePath.substr( 0U, sourcePath.find_last_of( L'\\') + 1U) ;
	std::wstring sibling ;	// 元親がpackage内のときだけ、その親に対するInclude位置です
	// Windows側の親directoryをパッケージの同名directoryに読み替えません
	if( parent.size() >= packageRoot_.size() &&
	   equalName( std::wstring_view( parent).substr( 0U, packageRoot_.size()), packageRoot_)) {
		sibling = parent.substr( packageRoot_.size()) + std::wstring( target) ;
	}

	const auto matches = [&]( std::wstring_view relative) {
		return equalName( relative, target) || (!sibling.empty() && equalName( relative, sibling)) ;
	} ; // 元一覧と固定memberの双方で同じ親またはrootの候補だけを扱います
	// 収集では部分抽出したmemberにない同名ファイルも原アーカイブ一覧で確認します
	if( collector_) {
		std::size_t candidates{} ;	// 元親・rootに実在する異なる原entryの数です
		// 一件でも未固定、または二箇所に競合する候補があればWindows探索へ進みません
		for( const auto &entry : collector_->archiveEntries) {
			// 無関係なdirectoryにある同じbasenameは元候補に含めません
			if( !matches( entry.relativePath)) {
				continue ;
			}

			// 異なる原位置の同名候補を、同じbyteや署名で一件にまとめません
			if( ++candidates > 1U) {
				return HRESULT_FROM_WIN32( ERROR_DUP_NAME) ;
			}

			// 元閉包の独立したINF/CATとして検査できない同名アーカイブ内INFを優先も無視もしません
			if( std::ranges::none_of( members_, [&]( const auto &member) {
				   return equalName( member.relativePath, entry.relativePath) ;
			   })) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}
		}
	}

	InfDependencyLookup found ;	// 全照会成功時だけ移す一時結果
	found.checked	  = true ;
	const auto append = [&found]( const InfDependencyDocument &document) {
		// 物理共有による同identityの別名は候補を水増ししない
		if( std::ranges::none_of( found.documents, [&document]( const auto &prior) {
			   // 原identityだけを共有根拠にする
			   return prior.identity == document.identity ;
		   })) {
			found.documents.push_back( document) ;
		}
	} ; // この照会結果だけへ同期追加する借用callback
	// 閉じたpackage一覧から、元親またはrootに明示された候補だけを調べる
	for( const auto &member : members_) {
		const auto path = workspace_.path( member.relativePath) ;	// 認証済みmemberからの固定位置です
		// 全directoryのbasename探索で無関係INFを混入させない
		if( path.empty() || !matches( member.relativePath)) {
			continue ;
		}

		InfDependencyDocument document ;									// 一候補の独立観測
		const auto			  error = observe( path, &member, document) ;	// 実memberへ結合する
		// 不正memberを候補なしへ変換しない
		if( error != 0) {
			return error ;
		}

		append( document) ;
	}

	const std::array<std::wstring, 2U> roots{windows_ + L"\\INF\\",
											 windows_ + L"\\System32\\"} ;	// 明示探索範囲
	// 現OSの二つの明示位置を別々に照会し、複数存在を隠さない
	for( const auto &root : roots) {
		InfDependencyDocument document ;		// system候補の実snapshot
		bool				  fileMissing{} ;	// 元INF位置の明示openだけの不在観測
		const auto			  error =
			// 任意diskへfallbackしない
			observe( root + std::wstring( target), nullptr, document, &fileMissing) ;
		// 照会済み不在だけは欠落候補として保持する
		if( fileMissing &&
		   (error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) ||
			error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND)))) {
			continue ;
		}

		// 競合・reparse・権限・容量の失敗を未発見にしない
		if( error != 0) {
			return error ;
		}

		append( document) ;
	}

	output = std::move( found) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一固定INFの明示節からInclude／Needsだけを読む
 * @param[in] document 固定snapshot
 * @param[in] name 原明示節名
 * @param[out] output 完了時の存在状態と有限参照
 * @return 完了0、構文・容量・改変のHRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::section( const InfDependencyDocument &document, std::wstring_view name,
								  InfDependencySection &output)
{
	output			  = {} ;
	const auto stored = find( document.identity) ;	// 核が既に固定したdocument
	// 差替えた入力やbyte未結合のdocumentを直接読まない
	if( stored == nullptr || stored->value.sha256 != document.sha256 ||
	   stored->value.byteCount != document.byteCount || name.empty() || name.size() > 254U) {
		return E_INVALIDARG ;
	}

	const auto error = recheckFile( stored->fileIndex) ;	// 読取前の再確認
	// Path／byteの再確認失敗後に解析を続けない
	if( error != 0) {
		return error ;
	}

	// 単独の絶対位置だけを開く非実行解析handle
	const HINF opened = SetupOpenInfFileW( files_[stored->fileIndex]->path.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
	// 解析失敗を節なしへ変換しない
	if( opened == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	InfHandle		   inf( opened) ;		// 単独INFだけを所有しAppendしない
	const std::wstring sectionName( name) ;	// 明示名の終端付きcopy
	SetLastError( ERROR_SUCCESS) ;
	const LONG lines =
		// 空節と不存在を分離する
		SetupGetLineCountW( inf.get(), sectionName.c_str()) ;
	// API契約の不存在を明示して返す
	if( lines == -1L) {
		const DWORD lastError = GetLastError() ;	// 直後の不在またはAPI診断
		// 不在以外のAPI失敗をMISSINGへ弱めない
		if( lastError != ERROR_SUCCESS && lastError != ERROR_SECTION_NOT_FOUND) {
			return winError( lastError) ;
		}

		output.state = InfDependencyReadState::MISSING ;
		return 0 ;
	}

	// 過大本文を一部だけのgraphへ変換しない
	if( lines < 0L || lines > 4096L) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	InfDependencySection observed ;	// 全field成功後だけ返すsnapshot
	observed.state = InfDependencyReadState::PRESENT ;
	// 確定した有限行数だけを解析し、他directiveの本文は保持しない
	for( LONG ordinal = 0L; ordinal < lines; ++ordinal) {
		INFCONTEXT line{} ;	// 一行だけの同期context
		// 途中の解析失敗で部分参照を返さない
		if( !SetupGetLineByIndexW( inf.get(), sectionName.c_str(), static_cast<DWORD>( ordinal),
								 &line)) {
			return winError( GetLastError()) ;
		}

		std::wstring key ;								// 一明示keyだけ
		const auto	 keyError = field( line, 0U, key) ;	// 本文全体のcopyは行わない
		// 非keyのdata行にはInclude／Needsの作用を推測しない
		if( keyError == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER)) ||
		   keyError == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA))) {
			continue ;
		}

		// API失敗を無関係行として隠さない
		if( keyError != 0) {
			return keyError ;
		}

		const bool include = equalName( key, L"Include") ;	// 関連directiveの明示一致
		// その他directiveの作用完全性は引き続き未検査
		if( !include && !equalName( key, L"Needs")) {
			continue ;
		}

		const DWORD fields = SetupGetFieldCount( &line) ;	// 一行の有限field数
		// 空directiveもINVALID_REFERENCEの分母へ残す
		if( fields == 0U) {
			// 空fieldも累積辺上限を越えて追加しない
			if( observed.references.size() >= 4096U) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			observed.references.push_back(
				{include ? InfDependencyDirective::INCLUDE : InfDependencyDirective::NEEDS, {}}) ;
			continue ;
		}

		// 個別と累積の双方の有限上限を適用する
		if( fields > 4096U - observed.references.size()) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 原field順で、空名や不正名も核へ渡して理由を保持する
		for( DWORD index = 1U; index <= fields; ++index) {
			std::wstring target ;									// 最大254文字の一明示参照
			const auto	 fieldError = field( line, index, target) ;	// 原値だけ
			// 一fieldの容量・API失敗でも部分snapshotを返さない
			if( fieldError != 0) {
				return fieldError ;
			}

			observed.references.push_back(
				{include ? InfDependencyDirective::INCLUDE : InfDependencyDirective::NEEDS,
				 std::move( target)}) ;
		}
	}

	output = std::move( observed) ;
	return recheckFile( stored->fileIndex) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全到達節とVersion／sourceのfile用途を非実行で観測する
 * @param[in,out] result 全体成功前のgraphと有限用途観測
 * @return 全行観測成功0、入力・読取・容量・元byte差のHRESULT
 * @note payload位置と全member署名は解決せず、実SYSTEM fileを複写しない
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::observeFileUses( InfDependencyNativeResult &result)
{
	std::vector<InfDependencyVisitedSection> pending =
		result.dependency.sections ;	// 同じ到達節の所有copy
	const auto append = [&pending]( std::uint64_t identity, const std::wstring &name) {
		// 全graphとmetadataを同じ1,024節予算へ拘束し、重複を再走査しない
		if( std::ranges::none_of( pending, [identity, &name]( const auto &section) {
			   return section.identity == identity && equalName( section.section, name) ;
		   })) {
			pending.push_back( {identity, name, InfDependencyReadState::NOT_CHECKED}) ;
		}
	} ; // 同期観測中だけpendingを借用する
	// 全発見INFのVersionとsourceを観測し、到達payloadの不在を推測しない
	for( const auto &document : result.dependency.documents) {
		append( document.identity, L"Version") ;
		append( document.identity, L"SourceDisksFiles.amd64") ;
		append( document.identity, L"SourceDisksFiles") ;
	}

	// metadata追加を別runへ分割して節予算を回避しない
	if( pending.size() > 1024U) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::size_t totalLines{} ;	// 全到達節とmetadataで共有する4,096行上限
	// 固定された各documentの原明示節だけを読む。suffix補完をしない
	for( const auto &section : pending) {
		const auto stored = find( section.identity) ;	// 同runで固定済みのINF
		// 未知identityを新しいfile探索へ変換しない
		if( stored == nullptr) {
			return E_INVALIDARG ;
		}

		const auto before = recheckFile( stored->fileIndex) ;	// 元byteの読取前確認
		// 元byte差があれば全体の部分観測を破棄する
		if( before != 0) {
			return before ;
		}

		InfHandle inf( SetupOpenInfFileW( files_[stored->fileIndex]->path.c_str(), nullptr,
										INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										nullptr)) ;	// 単独読取だけの所有handle
		// INF再読取失敗をfile用途不在へ変換しない
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return winError( GetLastError()) ;
		}

		SetLastError( ERROR_SUCCESS) ;
		const LONG count = SetupGetLineCountW( inf.get(), section.section.c_str()) ;	// 確定行数
		// 任意API失敗を明示節不在として消さない
		if( count < 0L) {
			const DWORD error = GetLastError() ;	// 原節照会診断
			// 文書化された不在だけを有限な欠落観測として保持する
			if( count != -1L || (error != ERROR_SUCCESS && error != ERROR_SECTION_NOT_FOUND)) {
				return winError( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
			}

			continue ;
		}

		// 実在節の全行を共同予算へ含め、途中までの用途集合を返さない
		if( static_cast<std::size_t>( count) > 4096U - totalLines) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		totalLines += static_cast<std::size_t>( count) ;
		// 全行をindexで取得し、正常終端と途中読取失敗を取り違えない
		for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
			INFCONTEXT line{} ;	// この原行だけのcontext
			// 一行でも読取不能なら部分file用途を公開しない
			if( SetupGetLineByIndexW( inf.get(), section.section.c_str(), static_cast<DWORD>( ordinal),
									&line) == FALSE) {
				return winError( GetLastError()) ;
			}

			std::wstring key ;								// 原用途key。data行では空
			const auto	 keyError = field( line, 0U, key) ;	// 単独の元field取得
			// 無key dataの仕様以外のAPI失敗を無関係行にしない
			if( keyError != 0 &&
			   keyError != static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER)) &&
			   keyError != static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA))) {
				return keyError ;
			}

			const bool source = equalName( section.section, L"SourceDisksFiles") ||
								// 明示sourceの原行
								equalName( section.section, L"SourceDisksFiles.amd64") ;
			const bool knownNonFile =
				std::ranges::any_of( std::array<std::wstring_view, 26U>{L"Signature",
																	   L"Class",
																	   L"ClassGuid",
																	   L"Provider",
																	   L"DriverVer",
																	   L"CatalogFile",
																	   L"CatalogFile.NT",
																	   L"CatalogFile.ntamd64",
																	   L"PnpLockdown",
																	   L"Include",
																	   L"Needs",
																	   L"FeatureScore",
																	   L"ServiceType",
																	   L"StartType",
																	   L"ErrorControl",
																	   L"DisplayName",
																	   L"Description",
																	   L"LoadOrderGroup",
																	   L"Dependencies",
																	   L"BootFlags",
																	   L"KmdfLibraryVersion",
																	   L"UmdfLibraryVersion",
																	   L"UmdfServiceOrder",
																	   L"ComponentIDs",
																	   L"Characteristics",
																	   L"BusType"},
									[&key]( const auto name) {
										return equalName( key, name) ;
									}) ; // 既知非file用途の明示集合
			const bool use =
				!knownNonFile || source || key.empty() || equalName( key, L"LayoutFile") ||
				equalName( key, L"CopyFiles") || equalName( key, L"CopyINF") ||
				equalName( key, L"ServiceBinary") || equalName( key, L"UmdfServiceBinary") ||
				equalName( key, L"EventMessageFile") || equalName( key, L"EventCategoryFile") ||
				equalName( key, L"EventParameterFile") || equalName( key, L"AddReg") ||
				// 具体用途
				equalName( key, L"RegisterDlls") || equalName( key, L"UnregisterDlls") ;
			// metadataやInclude／Needsをpayload位置へ読み替えない
			if( !use) {
				continue ;
			}

			const DWORD fields = SetupGetFieldCount( &line) ;	// 原用途の有限field数
			// field上限を切り詰めて未知参照を消さない
			if( fields > 64U) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 明示多値と空宣言を原順で全て残す
			for( DWORD index = source ? 0U : 1U;
				index <= (source ? 0U : (std::max)( fields, DWORD{1U})); ++index) {
				std::wstring target ;	// 原値。位置解決やsystem file取得は行わない
				const auto	 error =
					  (!source && fields == 0U) ? 0 : field( line, index, target) ;	// 一値
				// 読取不能用途を空の無参照へ変換しない
				if( error != 0) {
					return error ;
				}

				// 未解釈用途も最大4,096の累積保持量へ含める
				if( result.fileUses.size() >= 4096U) {
					return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				}

				result.fileUses.push_back(
					{section.identity, section.section,
					 source ? L"SourceDisksFiles" : (key.empty() ? L"DataRowsNotInterpreted" : key),
					 std::move( target)}) ;
			}
		}
	}

	observedSections_ = std::move( pending) ;
	observedRows_	  = totalLines ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定Windows登録helperの元byte/署名/権限を同runへ結びます
 * @param[in] recheck trueなら終了時も独立にtrust/権限を確認し原tupleと比較します
 * @return 全成立0、元native/tuple差のHRESULTです
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifyStreamingComponents( const bool recheck)
{
	// 固定二役割を別file proofの非空値で省略しません
	for( const auto leaf : {L"rundll32.exe", L"streamci.dll"}) {
		const auto error = verifySystemFile( windows_ + L"\\System32\\" + leaf,
											recheck) ;	// 直後に保持した元API又は検査errorです
		// 元の不正/不一致又は不足を成功へ補完しません
		if( error != 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			return error ;
		}
	}

	delayedRegistration_ = true ;
	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同原SYSTEMの単一moduleを元file/CAT/権限tupleへ固定します
 * @param[in] path 同Windowsの正確な提供位置です
 * @param[in] recheck trueなら元tupleとfresh実検査を比較します
 * @return 元trust/完全tuple一致0、元error又は差異のHRESULTです
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifySystemFile( const std::wstring &path, const bool recheck)
{
	const auto old = std::ranges::find_if(	// 同原文/操作へ結ぶ検査又は結果の所有値です
		systemFiles_, [&]( const auto &value) { return equalName( value.filePath, path) ; }) ;
	// このpathの原tupleを保持中だけ重複検査を省きます
	if( old != systemFiles_.end() && !recheck) {
		return 0U ;
	}

	std::size_t file{} ;									// 同保持集合の原位置です
	auto		error = pin( path, MAX_TOTAL_BYTES, file) ;	// 全祖先/実byteを保持します
	// 名前だけで元helperを信頼しません
	if( error != 0U) {
		return error ;
	}

	WindowsSystemFileTrust proof ;	// 実backendの全成功tupleだけです
	const auto			   verify = [&]() -> NativeError {
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
		// 専用compileの不足callbackは実Windowsへfallbackしません
		if( testApi != nullptr) {
			return testApi->systemFileTrust ? testApi->systemFileTrust( path, proof) : E_NOTIMPL ;
		}
#endif
		// Worker内の完全表がある場合は新作用の不足を拒否します
		if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
			return api->systemFileTrust ? api->systemFileTrust( path, proof) : E_NOTIMPL ;
		}

		return verifyWindowsSystemFileCachedOnly( path, proof) ;
	} ; // 同同期のpath/proofを借用し、元の三枝の順序と不足拒否を保ちます
	error = verify() ;

	// 成功boolだけで原fileのtupleを生成しません
	if( error != 0U || !equalName( proof.filePath, path) ||
	   proof.fileSha256 != files_[file]->sha256 || proof.fileBytes != files_[file]->bytes ||
	   proof.fileSecurity.empty()) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	// CAT形式では原CATを同runの保持集合へ再固定します
	if( !proof.catalogPath.empty()) {
		std::size_t catalog{} ;	// 原CATの同保持位置です
		error = pin( proof.catalogPath, MAX_CAT_BYTES, catalog) ;
		// Trust時の原CATと完全一致しない新fileを採用しません
		if( error != 0U || proof.catalogSha256 != files_[catalog]->sha256 ||
		   proof.catalogBytes != files_[catalog]->bytes || proof.catalogSecurity.empty()) {
			return error != 0U ? error : TRUST_E_BAD_DIGEST ;
		}
	}
	// Embedded署名のtupleへ別CATの断片を混入させません
	else if( !proof.catalogSha256.empty() || proof.catalogBytes != 0U ||
			!proof.catalogSecurity.empty()) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	// 別形式/CAT/元SDへ元tupleを置換しません
	if( old != systemFiles_.end()) {
		return *old == proof ? 0U : HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	systemFiles_.push_back( std::move( proof)) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Windows INFが宣言したサービス実体を同じ署名付きStore原媒体に照合する
 * @param[in] document 固定した正規Windows INF、原CATと対応Storeの同期文書です
 * @param[in] path 元作用から解決した正規System32又は同じStore上の位置です
 * @return 原位置、配備先、同CATと全バイトの成立時0、失敗時は元HRESULTです
 * @note 終了時には同じ二つのファイルを元CATで再確認します
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifyInboxServiceModule( const NativeDocument &document,
												   const std::wstring	&path)
{
	const auto leaf =
		// 元作用が指定した実ファイル名です
		path.substr( path.find_last_of( L'\\') + 1U) ;
	const bool wifiBusModule =
		equalName( files_[document.fileIndex]->path, windows_ + L"\\INF\\netvwifibus.inf") &&
		// 正規同梱INFに属する唯一の役割です
		equalName( leaf, L"vwifibus.sys") ;
	const bool bluetoothUsbModule =
		collector_ && collector_->scopedBluetoothUsb &&
		equalName( files_[document.fileIndex]->path, windows_ + L"\\INF\\bth.inf") &&
		(equalName( leaf, L"bthusb.sys") || equalName( leaf, L"bthport.sys")) &&
		equalName( path,
				  windows_ + L"\\System32\\drivers\\" + leaf) ;	// 同じ公式USB選択に属する配備先
	const bool namedModule =
		(document.value.identity == msPortsInboxDocument_ &&
		 (equalName( leaf, L"serial.sys") || equalName( leaf, L"serenum.sys"))) ||
		(document.value.identity == storNvmeInboxDocument_ &&
		 // 元INFに属する登録済み役割だけです
		 equalName( leaf, L"stornvme.sys")) ||
		(document.value.identity == storAhciInboxDocument_ && equalName( leaf, L"storahci.sys")) ||
		(document.value.identity == winUsbInboxDocument_ && equalName( leaf, L"winusb.sys") &&
		 equalName( path, windows_ + L"\\System32\\drivers\\winusb.sys")) ||
		wifiBusModule || bluetoothUsbModule ;
	// 他のWindows INFに属するファイルや別の提供役割と入れ替えません
	if( document.storeIndex == MAX_FILES || !namedModule) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const auto &store =
		files_[document.storeIndex]->path ;	// 同Windows INFが実際に対応するStore位置です
	const InfHandle inf{SetupOpenInfFileW( store.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										  nullptr)} ;	// Storeの元INFです
	// 原媒体を確認できなければ、同名ファイルを初期位置から推定しません
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	std::wstring source ;	// 元媒体内のファイル位置です
	std::wstring media ;	// 元媒体の相対位置です
	auto		 error = readOfficialInfSourceDirectories( inf.get(), leaf, source,
														  media) ;	// 同INFの元指定を読み取ります
	// 曖昧な位置や読取エラーを正規ファイルへ補いません
	if( error != 0 || (!source.empty() && !validInfDependencyPath( source, false)) ||
	   (!media.empty() && !validInfDependencyPath( media, false))) {
		return error != 0 ? error : static_cast<NativeError>( E_INVALIDARG) ;
	}

	const auto original = store.substr( 0U, store.find_last_of( L'\\') + 1U) +
						  (media.empty() ? media : media + L"\\") +
						  (source.empty() ? source : source + L"\\") + leaf ;	// 原配布元です
	// ストアから実行されるWi-Fiバスの実体は同じ配布元の同一パスに限定します
	if( wifiBusModule && (!source.empty() || !media.empty() || !equalName( original, path))) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	std::size_t storeFile{} ;		// Store原本の固定位置です
	std::size_t installedFile{} ;	// 同作用が参照する実配備バイトです
	error = pin( original, MAX_TOTAL_BYTES, storeFile) ;
	// 原本の失敗を配備物の合格で隠しません
	if( error != 0) {
		return error ;
	}

	error = pin( path, MAX_TOTAL_BYTES, installedFile) ;
	// 配備実体の取得失敗と全バイトの不一致を区別します
	if( error != 0 || files_[storeFile]->sha256 != files_[installedFile]->sha256 ||
	   files_[storeFile]->bytes != files_[installedFile]->bytes) {
		return error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	const std::array members{wifiBusModule ? store : original,
							 path} ;	// 同元CATへ結ぶ二つの固定ファイルです
	error = nativeCatalogSignature( files_[document.catalogIndex]->path, members) ;
	// 原CATに属さない同名実体は採用しません
	if( error != 0) {
		return error ;
	}

	auto &verified = documents_[static_cast<std::size_t>( &document - documents_.data())]
						 .catalogMembers ;	// 同文書の終了時再照合集合です
	// 別の作用ですでに確認した位置は再照合集合に一度だけ含めます
	for( const auto &member : members) {
		// 元の位置を重複させません
		if( std::ranges::none_of( verified,
								[&]( const auto &prior) { return equalName( prior, member) ; })) {
			verified.push_back( member) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows標準PortsのページDLLをロードせずに署名と実exportを照合する
 * @return 保護System32と元Windows署名、AMD64の名前付きexportが成立すれば0、その他は元HRESULTです
 * @note 検査したバイトのハッシュを元保護ファイルの検証値と照合します
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifySerialPropertyPage()
{
	const auto path =
		windows_ + L"\\System32\\MsPorts.dll" ;	// Windows APIで確定した同OSの正規DLLだけです
	auto error = verifySystemFile( path) ;		// 元署名・権限・バイトを固定します
	// 別位置や署名だけの値からexport検査の対象を作りません
	if( error != 0) {
		return error ;
	}

	const auto	proof = std::ranges::find_if( systemFiles_, [&]( const auto &file) {
		 return equalName( file.filePath, path) ;
	 }) ;					 // 同じファイルを署名した原証拠です
	std::size_t fileIndex{} ;	// 元署名照合に使ったfile handleの保持位置です
	error = pin( path, MAXIMUM_PROPERTY_PAGE_DLL_BYTES, fileIndex) ;
	// 未確認の位置・長さから同じDLLだと推定しません
	if( error != 0 || proof == systemFiles_.end() || files_[fileIndex]->bytes != proof->fileBytes) {
		return error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	const auto	handle = files_[fileIndex]->file.get() ;					// 検証中の保護済みWindowsファイルです
	std::string bytes( static_cast<std::size_t>( proof->fileBytes), '\0') ;	// 検査対象の有限バイトです
	DWORD		readBytes{} ;												// 固定handleから実際に読み取ったバイト数です
	// WinSxSと共有する正規DLLも、署名照合済みの同じhandleから読み取ります
	if( !SetFilePointerEx( handle, LARGE_INTEGER{}, nullptr, FILE_BEGIN) ||
	   !ReadFile( handle, bytes.data(), static_cast<DWORD>( bytes.size()), &readBytes, nullptr)) {
		return winError( GetLastError()) ;
	}

	// 短い読取結果を元DLLとみなしません
	if( readBytes != bytes.size()) {
		return HRESULT_FROM_WIN32( ERROR_HANDLE_EOF) ;
	}

	std::wstring sha256 ;	// 固定handleから読んだバイトのハッシュです
	error = computeDriverContainerSha256( bytes, sha256) ;
	// 原署名のハッシュと異なるバイトへexport検査を適用しません
	if( error != 0 || sha256 != proof->fileSha256) {
		return error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	return inspectCollectorPropertyPageExport( std::as_bytes( std::span{bytes}),
											  L"SerialPortPropPageProvider") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現Windowsの標準シリアルページの固定証拠を取得する
 * @param[out] proof 両照合で一致した署名、位置、バイト、権限の証拠
 * @return 非ロードの署名と実exportの照合が成立した場合0、その他は原診断
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::inspectSerialPropertyPage( WindowsSystemFileTrust &proof)
{
	proof	   = {} ;
	auto error = nativeWindowsDirectory( windows_) ;	// 現Windows APIの起点
	// OSの起点を取得できない場合は他のDLLを探さない
	if( error != 0U) {
		return error ;
	}

	error = verifySerialPropertyPage() ;
	// 署名と固定ハッシュ、exportの全検査が必要
	if( error != 0U || systemFiles_.size() != 1U) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	error = verifySystemFile( systemFiles_.front().filePath, true) ;
	// 同じハンドルを保持した終端の再照合で差があれば保留する
	if( error == 0U) {
		proof = std::move( systemFiles_.front()) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows同梱の仮想無線バスINFを既存のINF・CAT・Store照合で固定します
 * @param[in] inspect 生存するleaseの間だけ同梱INFと対応Storeの絶対パス及び全バイトを借用します
 * @return 由来と同一バイトの確認および内容確認が成立した場合0です。最初の失敗はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::inspectProtectedWifiBusInf(
	const std::function<NativeError( const std::wstring &, std::wstring_view,
									std::span<const std::byte>)> &inspect)
{
	auto error = nativeWindowsDirectory( windows_) ;	// 現Windowsの元起点です
	// 起点や読取り処理がない場合は同梱ファイルを推定しません
	if( error != 0 || !inspect) {
		return error != 0 ? error : E_INVALIDARG ;
	}

	InfDependencyDocument info ;	// 同署名INFとStore一致の観測です
	error = observe( windows_ + L"\\INF\\netvwifibus.inf", nullptr, info) ;
	// 原署名・同Windows Store由来をすべて確認した場合だけ読取りを渡します
	if( error != 0 || info.signature != InfDependencyEvidence::VERIFIED ||
	   info.provenance != InfDependencyEvidence::VERIFIED) {
		return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const auto *document = find( info.identity) ;	// 同元署名に使った固定ファイルです
	// 読取り時に別の署名INFや対応Storeへ切り替えません
	if( !document || document->fileIndex == MAX_FILES || document->catalogIndex == MAX_FILES ||
	   document->storeIndex == MAX_FILES) {
		return E_UNEXPECTED ;
	}

	const auto &original = *files_[document->fileIndex] ;	// 署名から終端まで保持する同じ実体です
	std::string bytes( static_cast<std::size_t>( original.bytes),
					  '\0') ;	// MAX_INF_BYTES以内の元バイトです
	DWORD		read{} ;		// この保持HANDLEから読み取った長さです
	// にせの別名やhardlinkの再openを行わず、署名に使ったHANDLEからだけ読みます
	if( !SetFilePointerEx( original.file.get(), LARGE_INTEGER{}, nullptr, FILE_BEGIN) ||
	   !ReadFile( original.file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &read,
				 nullptr)) {
		return winError( GetLastError()) ;
	}

	std::wstring digest ;	// 署名と同じ元バイトであるか照合するSHA-256です
	error = computeDriverContainerSha256( bytes, digest) ;
	// 読取shorteningや異なる実体の値を署名文書へ結びません
	if( error != 0 || read != bytes.size() || digest != original.sha256) {
		return error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	error =
		inspect( original.path, files_[document->storeIndex]->path, std::as_bytes( std::span{bytes})) ;
	// 内容が確定しなければ元署名だけで合格を返しません
	if( error != 0) {
		return error ;
	}

	// 同じleaseの三ファイルと元署名を終端でも照合します
	for( const auto index : {document->fileIndex, document->catalogIndex, document->storeIndex}) {
		error = recheckFile( index) ;
		// 同一文書の変更を後続ファイルの成功で隠しません
		if( error != 0) {
			return error ;
		}
	}

	return recheckTrust( *document) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択したストレージデバイスに結び付く現在の起動順を調べる
 * @param[out] order 読み取りに成功したWindows起動グループの位置
 * @return 元API成功かつ順序が成立した場合0、それ以外はHRESULT
 * @note 架空の完全APIがある場合はこの観測にも同じAPIを使う
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::readStorageBootLoadOrder( StorageLoadOrder &order)
{
	order				 = {} ;
	const bool legacyIde = nativeHdc_ && storageFacts_ && storageFacts_->group &&
						   // 元サービスの必要な起動グループ
						   equalName( *storageFacts_->group, L"System Bus Extender") ;
	const auto read = [&]() -> NativeError {
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
		// 専用の完全APIがある場合は欠落を実Windowsで補わない
		if( testApi) {
			return testApi->storageLoadOrder ? testApi->storageLoadOrder( order) : E_NOTIMPL ;
		}
#endif
		// 呼び出し側の架空APIから現在のWindows設定を混在させない
		if( const auto api = inf_dependency_native_detail::activeApi()) {
			return api->storageLoadOrder ? api->storageLoadOrder( order) : E_NOTIMPL ;
		}

		return readStorageLoadOrder( order, legacyIde) ;
	} ;
	// 同じAPIが返した起動順の元診断
	const auto error = read() ;
	const bool valid =
		legacyIde ? order.systemBusExtender && *order.systemBusExtender < 16384U &&
						order.precedingGroups.size() < 16384U && order.miniport == 0U &&
						order.deviceClass == 0U &&
						(order.precedingGroups.empty() || order.precedingGroups.back() == L'\0') &&
						std::ranges::count( order.precedingGroups, L'\0') ==
							static_cast<std::ptrdiff_t>( *order.systemBusExtender)
				  : !order.systemBusExtender && order.precedingGroups.empty() &&
						order.miniport < order.deviceClass &&
						order.deviceClass < 16384U ;	// 元用途に対応する位置の整合
	// 元診断または不整合を返し、部分的な位置を持ち出さない
	if( error != 0U || !valid) {
		order = {} ;
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ同期バックエンドで指定されたカーネルサービスの現在構成と保護を読む
 * @param[in] name 正確なサービス名
 * @param[out] evidence 構成と保護が検証できた場合だけ格納する元観測
 * @return 成立時0、正式の不在・読取・保護に問題があればHRESULT
 * @note 現在ファイルを開かず、試験用バックエンドの不足を実SCMへ補完しない
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::readStorageServiceConfiguration( std::wstring_view		 name,
														  SystemServiceEvidence &evidence)
{
	evidence = {} ;
	SystemServiceEvidence made ;	// 保護構成を検証してから渡す
	const auto			  read = [&]() -> NativeError {
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
		// 専用内部表の不足を実SCMへ補完しません
		if( testApi) {
			return testApi->storageService ? testApi->storageService( name, made) : E_NOTIMPL ;
		}
#endif
		// 所有完全表のstorage操作も欠落時fail-closedです
		if( const auto api = inf_dependency_native_detail::activeApi()) {
			return api->storageService ? api->storageService( name, made) : E_NOTIMPL ;
		}

		return readStorageServiceEvidence( name, made) ;
	} ;
	// 下位検査の最初の診断を後続へ返す一時値です
	auto error = read() ;
	// 明示不存在と元照会失敗は別の原HRESULTのまま返します
	if( error != 0U) {
		return error ;
	}

	error = validateStorageServiceEvidence( made) ;
	// 元の保護または構成が認められない場合は読めた一部を採用しない
	if( error != 0U) {
		return error ;
	}

	evidence = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元完全backendから正確なstorage kernelの現在config/SD/旧byteを固定します
 * @param[in] name 原associated又は依存の正確なservice名です。同期中だけ借用します
 * @param[out] evidence 全成立時だけ現configと完全SDです。失敗時は空です
 * @param[out] binarySha256 現在SYSのSHA-256。失敗時は空。不要ならnullptr
 * @return 正式不存在はSERVICE_DOES_NOT_EXIST、読取/保護/旧byte成立0、その他は原HRESULTです
 * @note 既存vendorの旧byteと提案新版を同一にせず、read-onlyで安定性だけを検査します。fixture欠損を実SCMへ補完しません
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::readStorageService( std::wstring_view		name,
											 SystemServiceEvidence &evidence,
											 std::wstring		   *binarySha256)
{
	// 現在SYSの読取に入る前に元出力のハッシュを初期化する
	if( binarySha256) {
		binarySha256->clear() ;
	}

	auto error = readStorageServiceConfiguration( name, evidence) ;	// 既存の元SCM構成と保護
	// 明示不存在と照会失敗は、パスを解決する前に元診断のまま返す
	if( error != 0U) {
		return error ;
	}

	std::wstring binary = evidence.binary ;	// 現旧binaryの全値を別の原観測として固定します
	// 同OSのSystemRootとして解釈する既知表記だけです
	const std::array<std::pair<std::wstring_view, std::wstring>, 2U> prefixes{
		{{L"\\SystemRoot\\", windows_ + L"\\"}, {L"%SystemRoot%\\", windows_ + L"\\"}}} ;
	// 明示Windows起点だけを同OSへ解決し、任意環境変数を展開しません
	for( const auto &[prefix, target] : prefixes) {
		// 既知のSystemRoot表記だけを同OSの完全pathへ展開します
		if( binary.size() >= prefix.size() &&
		   equalName( std::wstring_view{binary}.substr( 0U, prefix.size()), prefix)) {
			binary = target + binary.substr( prefix.size()) ;
			break ;
		}
	}

	// 同OSのSystem32ドライバー配置起点です
	const auto system = windows_ + L"\\System32\\drivers\\" ;
	// 同OSのDriver Store配置起点です
	const auto store = windows_ + L"\\System32\\DriverStore\\FileRepository\\" ;
	// 元完全pathが許可起点の直下又は下位であるという確認値です
	const auto within = [&]( std::wstring_view prefix) {
		return binary.size() > prefix.size() &&
			   equalName( std::wstring_view{binary}.substr( 0U, prefix.size()), prefix) ;
	} ;
	// exact所有serviceの現binaryはWindows配置/単一SYSだけです。新版のhashとの一致は要求しません
	if( !validInfDependencyPath( binary, true) || (!within( system) && !within( store)) ||
	   binary.size() < 5U ||
	   !equalName( std::wstring_view{binary}.substr( binary.size() - 4U), L".sys")) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	std::size_t index{} ;	// 同runの旧fileを新packageとは独立にpinします
	error = pin( binary, MAX_TOTAL_BYTES, index) ;
	// 固定できた現在のSYSのハッシュだけを返す
	if( error == 0U && binarySha256) {
		*binarySha256 = files_[index]->sha256 ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助の元効果と現在のWindows共有設定を読み取り専用で照合する
 * @param[in] effects 署名付き選択の検証済みACPIとAutoLogger作用
 * @param[out] shared 現在サービスと二つの共有先の完全な観測。失敗時は空
 * @param[out] stage 手順の固定診断番号。成功時は0
 * @return 同じ制御セットと許容された現在値が成立すれば0、それ以外はHRESULT
 * @note 同じ値が既存提供元を示すとは判定しない。サービス、設定、導入資格は変更しない
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::readStorageSharedSettings( const StorageInfEffects	  &effects,
													StorageSharedHostSnapshot &shared,
													std::uint32_t			  &stage)
{
	shared = {} ;
	stage  = 14020U ;
	// 元選択が両方の共有先を明示した場合に限って同じ端末を観測する
	if( !effects.sharedAcpiStorageFeatures || !effects.autoLogger) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 架空端末の操作を実ACPIまたはレジストリの照会へ補完しない
	if( testApi) {
		return E_NOTIMPL ;
	}
#endif
	// 完全な内部API表の読取りでも欠落した共有レジストリは補完しない
	if( inf_dependency_native_detail::activeApi()) {
		return E_NOTIMPL ;
	}

	StorageSharedHostSnapshot made ;	// 両方の現在値と同じACPI構成が成立するまで公開しない
	auto					  error =
		// Windows固定サービスの構成
		readStorageServiceConfiguration( L"ACPI", made.acpiService) ;
	// 不在や構成保護のエラーを無名の共有先で補完しない
	if( error != 0U) {
		return error ;
	}

	constexpr std::wstring_view relativeAcpi{
		L"System32\\drivers\\ACPI.sys"} ;	// Windows同梱の固定相対位置
	const auto full =
		windows_ + L"\\" + std::wstring{relativeAcpi} ;	// 同じWindowsから解決した正式ファイル
	const auto &config = made.acpiService ;				// 現在のSCMが返した元構成
	// 元構成がブートカーネル用のACPI.sysだけを指すことを確認してからファイルを読む
	if( !equalName( config.name, L"ACPI") || config.type != SERVICE_KERNEL_DRIVER ||
	   config.start != SERVICE_BOOT_START ||
	   (!equalName( config.binary, relativeAcpi) && !equalName( config.binary, full) &&
		!equalName( config.binary, L"\\SystemRoot\\" + std::wstring{relativeAcpi}) &&
		!equalName( config.binary, L"%SystemRoot%\\" + std::wstring{relativeAcpi}))) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	error = verifySystemFile( full) ;
	// ファイルの保護とWindows署名が不成立なら共有値を読み取らない
	if( error != 0U) {
		return error ;
	}

	error = readStorageAcpiSnapshot( made.acpi) ;
	// 読めない現在値・保護を許容された不在として扱わない
	if( error != 0U) {
		return error ;
	}

	// 既存の機能ビットを失う変更は署名された選択の同じDWORDだけで許可しない
	if( made.acpi.storageSupportedFeatures &&
	   (*made.acpi.storageSupportedFeatures & ~*effects.sharedAcpiStorageFeatures) != 0U) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	stage = 14021U ;
	error = readStorageAutoLoggerSnapshot( *effects.autoLogger, made.autoLogger,
										  StorageAutoLoggerProfile::TRIAGE_BUFFER) ;
	// 既存セッションの別設定または読取り不能は新規作成にしない
	if( error != 0U) {
		return error ;
	}

	stage = 14020U ;
	StorageAcpiSnapshot freshAcpi ;	// AutoLoggerを読んだ後に同じ共有ACPIを再観測する
	error = readStorageAcpiSnapshot( freshAcpi) ;
	// 二つの観測の間で変わった現在制御セットやACPIの保護と元値は使わない
	if( error != 0U || freshAcpi != made.acpi ||
	   made.acpi.controlSet != made.autoLogger.controlSet) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	SystemServiceEvidence freshService ;	// 共有先を読んだ後のACPIの元SCM構成
	error = readStorageServiceConfiguration( L"ACPI", freshService) ;
	// 読み取った最初の構成へ確認なしに結び直さない
	if( error != 0U || freshService != made.acpiService) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	error = verifySystemFile( full, true) ;
	// 途中でWindows由来のファイルや保護が変化した場合も観測を採用しない
	if( error != 0U) {
		return error ;
	}

	shared = std::move( made) ;
	stage  = 0U ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 候補と同名の起動サービスの現在構成とSYS配置先を読取り照合する
 * @param[in] selected 同じ元選択の関連サービスと正規SYSのコピー先
 * @param[in] device 選択機器と共有機器の署名付き元登録
 * @param[out] boot 名前、現在構成、保護と分類。失敗時は空
 * @return 読取り成功0、位置、権限、構成照会が不成立ならHRESULT
 * @note SCMにサービスがない場合も、候補の正規SYS配置先の現在状態を読む
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::readStorageAutomaticBoot( const SelectedStorageServiceFacts	&selected,
												   const StorageAutomaticDeviceSnapshot &device,
												   StorageAutomaticBootSnapshot			&boot)
{
	boot = {} ;
	StorageAutomaticBootSnapshot made ;	// 固定した候補から保護と配置先を全て確認する
	made.related.name = selected.name ;
	SystemServiceEvidence observed ;											// 元の現在SCM構成と保護
	auto error = readStorageServiceConfiguration( selected.name, observed) ;	// 対象SCMの診断
	// 正常構成とWindowsが返す正式な不在だけを配置照会へ進める
	if( error == 0U) {
		made.related.evidence = std::move( observed) ;
	}
	// アクセス拒否、構成不明と一時停止を新規配置へ置き換えない
	else if( error != HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST)) {
		return error ;
	}

	error = readSystem32StorageDriverSnapshot( selected.binaryTarget, made.destination) ;
	// SCMの正式不在でも権限や別配置のエラーを無視しない
	if( error != 0U) {
		return error ;
	}

	made.change = classifyStorageAutomaticBoot( selected, device, made) ;
	boot		= std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助の現用機器と候補に関係する現在値を同じ制御セットで読み取る
 * @param[in] effects 候補の署名付き元作用
 * @param[in] sourceIdentity 同じ選択の元文書と元CATを保持する内部識別
 * @param[out] host 現用機器、電源を含む共有設定、候補のイベントと補助の現在値。失敗時は空
 * @param[out] stage 元診断の固定段階
 * @return 現用機器と共有先の読取りが成立すれば0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::readStorageAutomaticHost( const StorageInfEffects		&effects,
												   std::uint64_t				 sourceIdentity,
												   StorageAutomaticHostSnapshot &host,
												   std::uint32_t				&stage)
{
	host = {} ;
	StorageAutomaticHostSnapshot made ;	// 全読取と共通箇所の一致まで公開しない
	// 通常の機器選択でだけ、同じ機器に現在登録された元配布から観測する
	if( registeredDeviceRead_) {
		stage = 14024U ;
		// 現用の元署名、関連イベントと補助の観測を同じ選択機器へ結合する
		const auto error = (*registeredDeviceRead_)( effects.service, made.device.emplace()) ;
		// 現用登録の失敗を候補の同名サービスで補わない
		if( error != 0U) {
			return error ;
		}
	}

	// 候補が実際に更新する共有先の現在状態を独立に読み取る
	auto error = readStorageSharedSettings( effects, made.shared, stage) ;
	// 同じ候補が変更する電源設定と既定値を保護付きの現在観測へ含める
	if( error == 0U) {
		stage = 14026U ;
		error = readStoragePowerSettingsSnapshot( effects.powerSettings, made.power) ;
		// 別の制御セットへ変わった後の電源観測を以前の構成と混ぜない
		if( error == 0U && made.power.controlSet != made.shared.acpi.controlSet) {
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	// 先に読んだ現用のイベントと別の制御セットを使わない
	if( error == 0U) {
		stage = 14022U ;
		error = readNamedStorageEventSnapshot( effects.service, made.events) ;
	}

	// 明示したDLLの正規配置をイベント登録とは独立に読み、既存ファイルの有無を確定する
	if( error == 0U && effects.service.auxiliary && effects.service.auxiliary->eventMessageCopy) {
		stage = 14032U ;
		error = readStorageAutomaticEventResource( effects.service, made.eventResource) ;
	}

	// 現用登録と別名の場合も候補の変更先の正式不在・現在構成を区別する
	if( error == 0U) {
		stage = 14023U ;
		error = readAutoStartStorageAuxiliarySnapshot( effects.service, made.auxiliary) ;
	}

	// 現用と候補が両方触れる現在のイベントと補助を、取得した別観測間で照合する
	if( error == 0U) {
		stage = 14025U ;
		error = verifyStorageAutomaticHostCoherence( effects.service, made) ;
	}

	// 正式な現用機器一覧を照合できた場合だけ、候補の電源定義との差を分類する
	if( error == 0U && made.device) {
		stage = 14027U ;
		error = classifyStoragePowerChanges( effects.powerSettings, made.power, *made.device,
											made.powerChanges) ;
	}

	// 固定した同じ候補の元INFとCATから、現在の補助とイベントへ書く影響を照合する
	if( error == 0U && made.device) {
		stage			   = 14028U ;
		const auto *source = find( sourceIdentity) ;	// 保護して読んだ候補文書とCAT
		// 別の文書や元CATが確認できない候補を現用と同一にしない
		if( !source || source->value.signature != InfDependencyEvidence::VERIFIED ||
		   source->catalogIndex >= files_.size()) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		error = classifyStorageAutomaticServiceChanges( effects.service, source->value.sha256,
													   files_[source->catalogIndex]->sha256, made) ;
		// 実在する共有ログの所有は、同じ署名付き元INF・CATと実選択から確定する
		if( error == 0U && made.shared.autoLogger.existing) {
			const auto matches = [&]( const StorageAutomaticRegistrationSnapshot &current) {
				return current.package && current.package->infSha256 == source->value.sha256 &&
					   current.package->catalogSha256 == files_[source->catalogIndex]->sha256 &&
					   equalName( current.package->installedSection,
								 effects.service.selectedInstallSection) ;
			} ; // 同じ元グラフを検査済みの署名元だけを借用する
			// 名前や構成値が同じだけの既存ログを同じ署名元へ帰属させない
			if( !matches( made.device->selected) &&
			   std::ranges::none_of( made.device->owners,
									[&]( const auto &owner) { return matches( owner.registered) ; })) {
				stage = 14030U ;
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}
		}
	}

	// 現用元を確認できた機器について、候補が更新する起動サービスとSYSを合わせて読む
	if( error == 0U && made.device) {
		stage = 14029U ;
		error = readStorageAutomaticBoot( effects.service, *made.device, made.boot.emplace()) ;
	}

	// レジストリの現在値だけで実動作中の同名ETWセッションがないと判断しない
	if( error == 0U && made.device) {
		stage = 14030U ;
		error = readStorageAutoLoggerRuntimePresence( *effects.autoLogger,
													 made.autoLoggerRuntimePresent.emplace()) ;
	}

	// 保護と共通箇所が同じ観測だけを再比較へ渡す
	if( error == 0U) {
		host  = std::move( made) ;
		stage = 0U ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付き自動起動候補の現在共有先を読み、変更可否を分類する
 * @param[in,out] storage 元作用を照合済みの候補。成功時だけ現用観測と起動サービスを保持する
 * @param[in] sourceIdentity 同じ候補を保持する元文書の内部識別
 * @param[out] stage 最初の読取り不成立または所有が未確認の共有先を示す固定診断
 * @return 安定した現用観測と変更範囲が成立する場合0、それ以外はHRESULT
 * @note 現在状態を変更せず、適用資格は発行しない
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifyStorageAutomaticHost( StorageInfEffects &storage,
													 std::uint64_t		sourceIdentity,
													 std::uint32_t	   &stage)
{
	StorageAutomaticHostSnapshot host ;	// 分類を終えるまで候補へ公開しない現在観測
	// ストレージの現在の共有先を取得した元の診断値
	auto error = readStorageAutomaticHost( storage, sourceIdentity, host, stage) ;
	// 同一機器の元登録と配置をもう一度照合してから変更範囲を決める
	if( error == 0U && registeredDeviceRead_) {
		StorageAutomaticHostSnapshot fresh ;	// 独立した現用登録、共有先と保護の観測
		error = readStorageAutomaticHost( storage, sourceIdentity, fresh, stage) ;
		// 途中で置換された元ファイルや登録の新しい値を前回観測へ合成しない
		if( error == 0U && fresh != host) {
			stage = 14025U ;
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	// 下位読取りの元エラーを共有先の分類で上書きしない
	if( error != 0U) {
		return error ;
	}

	// 他機器が使用する配置や所有不明の設定を上書きできる候補にしない
	const auto unresolved = []( StorageServiceChange change) {
		return change == StorageServiceChange::UPDATE_SHARED ||
			   change == StorageServiceChange::UNVERIFIED ;
	} ;
	const bool	powerConflict = std::ranges::any_of( host.powerChanges, []( auto change) {
		 return change == StoragePowerChange::UPDATE_SHARED ||
				change == StoragePowerChange::UNVERIFIED ;
	 }) ;												   // 現用未確認または他機器が使う電源設定
	const auto &helper		  = storage.service.auxiliary ;	// 候補が触れる元補助とイベント資源
	// 内容検査だけで端末への導入用の観測を作ったことにしない
	if( !host.device || !host.serviceChanges || !host.boot || !host.autoLoggerRuntimePresent ||
	   !helper || helper->eventMessageCopy.has_value() != host.eventResource.has_value() ||
	   host.powerChanges.size() != storage.powerSettings.size()) {
		stage = 14001U ;
	}
	// 共有作用の拒否は元の固定診断で返す
	else if( powerConflict) {
		stage = 14027U ;
	}
	// 変更可否が未確定のサービスが一つでもあれば適用判定を止めます
	else if( std::ranges::any_of( *host.serviceChanges, unresolved)) {
		stage = 14028U ;
	}
	// イベント資源の置換可否を確認できないときは固有の拒否位置を残します
	else if( host.eventResource && unresolved( host.eventResource->change)) {
		stage = 14032U ;
	}
	// 起動設定の現在値を照合できない場合は、適用可能と判定しません
	else if( host.boot->change == StorageServiceChange::UNVERIFIED) {
		stage = 14029U ;
	}
	// AutoLoggerが現在利用中のときは、動作中の構成を対象にしません
	else if( *host.autoLoggerRuntimePresent) {
		stage = 14030U ;
	} else {
		storage.services.push_back( host.boot->related) ;
		storage.automaticHost = std::move( host) ;
		stage				  = 0U ;
	}

	return stage == 0U ? 0U : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 仮想Wi-Fiバスが空リストと同じStoreの同名コピーだけを指定することを確認する
 * @param[in] document 元作用と同一Storeの署名・SYSが検査済みの文書です
 * @return 全コピー指定が成立して0、欠損・別ファイル・別位置・API失敗のHRESULTです
 * @note CopyFilesの二参照は型付き作用検査が照合済みです。コピーは実行しません
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifyWifiBusStoreCopy( const NativeDocument &document) const
{
	const InfHandle inf{SetupOpenInfFileW( files_[document.fileIndex]->path.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										  nullptr)} ;	// 固定した元同梱INFです
	// 読取失敗からコピーの作用を推定しません
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	static constexpr wchar_t EMPTY_COPY[]  = L"VWiFiBus.CopyFilesInternal" ;	// 元の空リストです
	static constexpr wchar_t STORE_COPY[]  = L"CopyKMDriver" ;					// 元SYSを一つ指定するリストです
	static constexpr wchar_t DESTINATION[] = L"DestinationDirs" ;				// 同INFの明示宛先表です
	// 空リストの実在、同名コピー一件と二つの明示宛先を必要とします
	if( SetupGetLineCountW( inf.get(), EMPTY_COPY) != 0L ||
	   SetupGetLineCountW( inf.get(), STORE_COPY) != 1L ||
	   SetupGetLineCountW( inf.get(), DESTINATION) != 2L) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 両方のリストに対して追加のファイル保護指定を拒否し、元Storeの保護を維持します
	for( const auto *list : {EMPTY_COPY, STORE_COPY}) {
		const auto security = std::wstring{list} + L".security" ;	// 同じリストへの元権限指定です
		SetLastError( ERROR_SUCCESS) ;
		const auto count	 = SetupGetLineCountW( inf.get(), security.c_str()) ;	// 権限節の有無です
		const auto readError = GetLastError() ;										// 読取直後の元エラーです
		// 追加の権限変更または不明な読取エラーを許容しません
		if( count >= 0 || (readError != ERROR_SUCCESS && readError != ERROR_SECTION_NOT_FOUND)) {
			return count >= 0 ? HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) : winError( readError) ;
		}

		INFCONTEXT destination{} ;	// 元コピーリストそれぞれの宛先行です
		int		   dirId{} ;		// 完全な一つのDIRIDです
		// 既定の宛先、サブディレクトリ追加、別DIRIDへの書込みを許可しません
		if( !SetupFindFirstLineW( inf.get(), DESTINATION, list, &destination) ||
		   SetupGetFieldCount( &destination) != 1U || !SetupGetIntField( &destination, 1U, &dirId) ||
		   dirId != 13) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}
	}

	INFCONTEXT copy{} ;	// 同じ原Storeを参照する未加工のコピー指定です
	// 元文書の唯一のコピー行だけを読み直します
	if( !SetupGetLineByIndexW( inf.get(), STORE_COPY, 0U, &copy)) {
		return winError( GetLastError()) ;
	}

	std::wstring name ;	// SetupAPIが先頭キーと単一値に返す同じSYS名です
	// 同名の元ファイル一つに限り、改名、代替元、テンポラリ名、フラグは許可しません
	if( SetupGetFieldCount( &copy) != 1U || field( copy, 0U, name) != 0U ||
	   !equalName( name, L"vwifibus.sys")) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const auto error = field( copy, 1U, name) ;	// 元文書の唯一の値の読取結果です
	// 既存サービスのモジュール検査で元StoreとCATに結んだ同名ファイルだけを認めます
	if( error != 0U || !equalName( name, L"vwifibus.sys")) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元選択NeedsのSYSTEM全型とstorage PACKAGE全型を各由来のまま検査します
 * @param[in] result 同原graphと全document証拠です
 * @param[in] seeds 元正規DDInstallと実在付随節です
 * @param[in,out] rows 全registryの共同累積行数です
 * @return 全作用成立0、元API又は型/scopeの拒否HRESULTです
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifyTypedEffects( const InfDependencyNativeResult &result,
											 std::span<const std::wstring> seeds, std::size_t &rows)
{
	std::vector<SystemInfSection> reached ;	// 元Needs辺にだけ文脈を伝播します
	const auto					  root =
		// 元所有scopeへ結ぶ位置です。任意探索へ使いません
		documents_.front().value.identity ;
	// 正規選択の実在付随節名以外を文脈へ推測しません
	for( const auto &seed : seeds) {
		const auto base =
			selectedBase_.empty()
				? seeds.front()
				: selectedBase_ ;		// この同期だけで保持する元値です。許可の代用にしません
		SystemInfContext context{} ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		// 元基本との完全対応だけを使います
		if( equalName( seed, base)) {
			context = SystemInfContext::DEVICE ;
		}
		// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
		else if( equalName( seed,
						  base + L".HW")) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			context = SystemInfContext::HARDWARE ;
		}
		// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
		else if( equalName( seed,
						  base + L".Services")) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			context = SystemInfContext::SERVICES ;
		}
		// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
		else if( equalName( seed,
						  base +
							  L".Interfaces")) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			context = SystemInfContext::INTERFACES ;
		}
		// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
		else if( equalName( seed,
						  base + L".Wdf")) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			context = SystemInfContext::FRAMEWORK ;
		} else {
			// storageの全選択作用は未知付随節の存在を省略しません
			if( storageFacts_) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			continue ;
		}

		reached.push_back( {root, seed, context, context, {}}) ;
	}

	// 同graphの正確なNeedsだけを文脈/所有者へ伝播します
	for( std::size_t index = 0U; index < reached.size(); ++index) {
		const auto source =
			reached[index] ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		// 全辺を元順で確認します。Includeを実行作用へしません
		for( const auto &edge : result.dependency.edges) {
			// 元節と同じ文脈の成功Needsだけです
			if( edge.directive != InfDependencyDirective::NEEDS ||
			   edge.sourceIdentity != source.document ||
			   !equalName( edge.sourceSection, source.name) || edge.targetIdentity == 0U) {
				continue ;
			}

			SystemInfSection target{
				edge.targetIdentity, edge.target, source.context,
				source.scope,	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
				source.owner} ;
			// 複数文脈を先頭の一つに縮約しません
			if( std::ranges::none_of( reached, [&]( const auto &old) {
				   return old.document == target.document && equalName( old.name, target.name) &&
						  old.context == target.context && old.scope == target.scope &&
						  old.owner == target.owner ;
			   })) {
				// 元共同節上限を回避しません
				if( reached.size() >= 1024U) {
					return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				}

				reached.push_back( std::move( target)) ;
			}
		}
	}

	std::vector<SystemInfSection> typed ;					// SYSTEM証拠が全成立したものだけです
	std::uint64_t				  wifiBusInboxDocument{} ;	// 到達と署名を確認した正規の単一文書です
	const bool					  sdHostCollector =
		collector_ && equalName( collector_->closure.packages.front().className, L"SDHost") &&
		equalName(
			collector_->closure.packages.front().classGuid,
			L"{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}") ;	// 元署名と構造検査を通った収集rootが対象です
	const bool portsCollector =
		collector_ &&
		!collector_->closure.packages.front()
			 .collectorInboxPropertyPageSection.empty() ;	// 元Portsの単独登録が成立しています
	const bool serialEnumeratorOnly =
		collector_ && collector_->closure.packages.front()
						  .collectorSerialMedia.has_value() ;	// 自前媒体がある二つの元選択
	const bool nvmeCollector =
		collector_ && collector_->closure.packages.front()
						  .collectorInboxNvmeLists.has_value() ;	// 元NVMeの空二節が成立しています
	const bool ahciCollector =
		collector_ && !collector_->closure.packages.front().collectorInboxInstallGroups.empty() &&
		equalName( collector_->closure.packages.front().className, L"HDC") &&
		equalName( collector_->closure.packages.front().classGuid,
				  L"{4d36e96a-e325-11ce-bfc1-08002be10318}") ;	// 元HDCで検証した委譲形式
	const bool winUsbCollector =
		collector_ &&
		!collector_->closure.packages.front()
			 .collectorInboxWinUsbRegistrySection.empty() ;	// 公式直CABの元機器登録を確認済み
	// PACKAGEのglobal作用をSYSTEM署名で救済しません
	for( const auto &section : reached) {
		const auto document = find( section.document) ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		// 元documentの全証拠と実INBOX/Storeを型追加の前提にします
		if( document && document->value.origin == InfDependencyOrigin::SYSTEM) {
			// 元の不正/不一致又は不足を成功へ補完しません
			if( document->value.signature !=
				   InfDependencyEvidence::
					   VERIFIED ||	// 不明/不一致の元値を成功や別scopeへ補完しません
			   document->value.provenance != InfDependencyEvidence::VERIFIED ||
			   document->signerScore != SIGNERSCORE_INBOX || document->storeIndex == MAX_FILES) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			// 同じWindowsの正規INFを、原署名と一致するStoreの検査後にだけ型へ結びます
			if( sdHostCollector &&
			   equalName( files_[document->fileIndex]->path, windows_ + L"\\INF\\sdbus.inf")) {
				sdBusInboxDocument_ = document->value.identity ;
			}

			// 元PortsページとWindows同梱msports.infの同じ選択文書だけを結びます
			if( (portsCollector || serialEnumeratorOnly) &&
			   equalName( files_[document->fileIndex]->path, windows_ + L"\\INF\\msports.inf")) {
				msPortsInboxDocument_ = document->value.identity ;
			}
			// 混在媒体のWindows同梱側を別の同梱文書へ広げない
			else if( serialEnumeratorOnly) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			// 元NVMe参照の同正規INFだけに専用の型を結びます
			if( nvmeCollector &&
			   equalName( files_[document->fileIndex]->path, windows_ + L"\\INF\\stornvme.inf")) {
				storNvmeInboxDocument_ = document->value.identity ;
			}
			// NVMeのHWから到達したPCI作用の所有元を区別します
			else if( nvmeCollector &&
					equalName( files_[document->fileIndex]->path, windows_ + L"\\INF\\pci.inf")) {
				pciNvmeInboxDocument_ = document->value.identity ;
			}
			// 他のSYSTEM INFが必要な配布を現NVMe構造の成功に含めません
			else if( nvmeCollector) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			// 元HDCの三参照は署名済みの正規mshdc.inf一つに限定する
			if( ahciCollector) {
				// AHCIの三節は正規Windowsのmshdc.infで確認する
				if( !equalName( files_[document->fileIndex]->path, windows_ + L"\\INF\\mshdc.inf")) {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				storAhciInboxDocument_ = document->value.identity ;
			}

			// 公式の三委譲節が正規Windowsの同じ文書を選んだ場合だけWinUSBの型を渡す
			if( winUsbCollector) {
				// 別の同梱INFで不足する作用を補わない
				if( !equalName( files_[document->fileIndex]->path, windows_ + L"\\INF\\winusb.inf") ||
				   (winUsbInboxDocument_ != 0U &&
					winUsbInboxDocument_ != document->value.identity)) {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				winUsbInboxDocument_ = document->value.identity ;
			}

			// 到達したサービス節を元INBOX文書と一致する場合にだけ専用検査へ渡します
			if( section.context == SystemInfContext::SERVICES &&
			   equalName( section.name, L"VWiFiBus.Services") &&
			   equalName( files_[document->fileIndex]->path, windows_ + L"\\INF\\netvwifibus.inf")) {
				wifiBusInboxDocument = document->value.identity ;
			}

			typed.push_back( section) ;
		}
	}

	// ページを持つ元Portsに、別のWindows INFによる代替証拠を認めません
	if( (portsCollector || serialEnumeratorOnly) && msPortsInboxDocument_ == 0U) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// NVMeとPCIの元署名付き文書が二つとも選択されている場合に限ります
	if( nvmeCollector && (storNvmeInboxDocument_ == 0U || pciNvmeInboxDocument_ == 0U)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 標準AHCIの原文書を解決できない場合は空の作用結果を成功にしない
	if( ahciCollector && storAhciInboxDocument_ == 0U) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 元INFの委譲が正本に解決しない場合は検査を完了しない
	if( winUsbCollector && winUsbInboxDocument_ == 0U) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 型追加が無い既経路を別policyへ移しません
	if( typed.empty() && !storageFacts_ && !collectorHdc_) {
		return 0U ;
	}

	SystemInfEffectApi api ;	// 同同期の元NativeLoaderだけを借用します
	api.registryRows		  = &rows ;
	api.graphReferences		  = result.dependency.edges.size() ;
	api.sdBusInboxDocument	  = sdBusInboxDocument_ ;
	api.msPortsInboxDocument  = msPortsInboxDocument_ ;
	api.serialEnumeratorOnly  = serialEnumeratorOnly ;
	api.storNvmeInboxDocument = storNvmeInboxDocument_ ;
	api.pciNvmeInboxDocument  = pciNvmeInboxDocument_ ;
	api.storAhciInboxDocument = storAhciInboxDocument_ ;
	api.winUsbInboxDocument	  = winUsbInboxDocument_ ;
	api.wifiBusInboxDocument  = wifiBusInboxDocument ;
	// 同じ保護閉包の元Modelsから得た照合IDをAHCIの除外条件に渡す
	if( ahciCollector) {
		api.ahciHardwareIds = collector_->closure.packages.front().hardwareIds ;
	}

	// 同じ署名付き選択の補助サービスがDriver Store配置と自動起動を宣言した状態です
	const bool autoStartStorage = storageFacts_ && storageFacts_->auxiliary &&
								  storageFacts_->auxiliary->start == SERVICE_AUTO_START &&
								  storageFacts_->auxiliary->copy.dirid == 13 ;
	const bool eventMessageCopy = autoStartStorage &&
								  // 現用資源の所有を別途確認する型
								  storageFacts_->auxiliary->eventMessageCopy.has_value() ;
	bool singleBootStorage{} ;	// 同じ署名付き基本節がAddPowerSettingを明示した場合だけtrue
	// 読み取り中は元文書を変更せず、自動起動補助のレジストリ元行も確認します
	api.read = [this, wifiBusInboxDocument, autoStartStorage, &singleBootStorage](
				   const SystemInfSection &section, std::vector<SystemInfRow> &out) -> NativeError {
		out.clear() ;
		const auto document = find( section.document) ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		// 同署名原文だけを読み、PACKAGE転送は後でSYSTEM全tupleへ比較します
		if( !document || document->value.signature != InfDependencyEvidence::VERIFIED ||
		   document->value.provenance != InfDependencyEvidence::VERIFIED) {
			return E_INVALIDARG ;
		}

		InfHandle inf{SetupOpenInfFileW( files_[document->fileIndex]->path.c_str(),
										nullptr,	// この同期/fixtureが所有する資源又は原状態です
										INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)} ;
		// 読取不能を空節へ変換しません
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return winError( GetLastError()) ;
		}

		const auto security = section.name + L".security" ;	// 元権限/署名の照合中だけ使う証拠です
		SetLastError( ERROR_SUCCESS) ;
		const auto securityRows = SetupGetLineCountW(
			// この同期だけで保持する元値です。許可の代用にしません
			inf.get(), security.c_str()) ;
		const auto securityError = GetLastError() ;	// 直後に保持した元API又は検査errorです
		// 空security宣言も一般dataへ移しません
		if( securityRows >= 0 ||
		   (securityError != ERROR_SUCCESS && securityError != ERROR_SECTION_NOT_FOUND)) {
			return securityRows >= 0 ? HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)
									 : winError( securityError) ;
		}

		const auto count =
			// 元全長又は共同予算の有限件数です
			SetupGetLineCountW( inf.get(), section.name.c_str()) ;
		// 元行上限と実在を必要とします
		if( count < 0 || count > 4096) {
			return count < 0 ? HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND)
							 : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		const bool newSection = std::ranges::none_of(
			observedSections_,
			[&]( const auto &old) {	// この同期だけで保持する元値です。許可の代用にしません
				return old.identity == section.document && equalName( old.section, section.name) ;
			}) ;
		// 元用途観測の消費も含む一つの1024節/4096行上限です
		if( newSection) {
			// 元の不正/不一致又は不足を成功へ補完しません
			if( observedSections_.size() >= 1024U ||
			   observedRows_ > 4096U ||	// 不明/不一致の元値を成功や別scopeへ補完しません
			   static_cast<std::size_t>( count) > 4096U - observedRows_) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			observedSections_.push_back(
				{section.document, section.name, InfDependencyReadState::PRESENT}) ;
			observedRows_ += static_cast<std::size_t>( count) ;
		}

		// 全行と全fieldを元順で保持します
		for( LONG ordinal = 0; ordinal < count; ++ordinal) {
			INFCONTEXT line{} ;	// この同期だけで保持する元値です。許可の代用にしません
			// 元の不正/不一致又は不足を成功へ補完しません
			if( !SetupGetLineByIndexW(
				   inf.get(), section.name.c_str(),
				   static_cast<DWORD>( ordinal),	// 不明/不一致の元値を成功や別scopeへ補完しません
				   &line)) {
				return winError( GetLastError()) ;
			}

			SystemInfRow row ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			row.ordinal = static_cast<std::uint32_t>( ordinal) ;
			// 無keyのdata行をkey読取の失敗で置換しません
			if( section.context != SystemInfContext::REGISTRY &&
			   section.context != SystemInfContext::PROPERTY) {
				const auto error = field( line, 0U, row.key) ;	// 直後に保持した元API又は検査errorです
				// 元の不正/不一致又は不足を成功へ補完しません
				if( error != 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
					return error ;
				}
			}
			// 既知の同梱作用と選択ストレージの登録データでは、空名を含むkey指定も区別する
			else if( section.context == SystemInfContext::REGISTRY &&
					(section.document == msPortsInboxDocument_ ||
					 section.document == storNvmeInboxDocument_ ||
					 section.document == pciNvmeInboxDocument_ ||
					 section.document == storAhciInboxDocument_ ||
					 section.document == winUsbInboxDocument_ ||
					 section.document == wifiBusInboxDocument ||
					 ((nativeHdc_ || autoStartStorage || singleBootStorage) &&
					  document->value.origin == InfDependencyOrigin::PACKAGE))) {
				const auto error =
					// 無名行は元APIがERROR_INVALID_PARAMETERを返します
					field( line, 0U, row.key) ;
				// 他の読取失敗や名前付きdirectiveを無名データ行にしません
				if( error != HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER)) {
					return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
				}
			}

			const auto fields = SetupGetFieldCount(
				&line) ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			// 元の不正/不一致又は不足を成功へ補完しません
			if( fields > 64U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 空fieldも省略せず全消費します
			for( DWORD index = 1U; index <= fields; ++index) {
				std::wstring value ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
				const auto	 error =
					// 直後に保持した元API又は検査errorです
					field( line, index, value) ;
				// 元の不正/不一致又は不足を成功へ補完しません
				if( error != 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
					return error ;
				}

				row.values.push_back( std::move( value)) ;
			}

			out.push_back( std::move( row)) ;
		}

		// 元の不正/不一致又は不足を成功へ補完しません
		if( const auto observer = inf_dependency_native_detail::
			   // 不明/不一致の元値を成功や別scopeへ補完しません
		   activeApi() ;
		   observer && observer->observedSection) {
			observer->observedSection( files_[document->fileIndex]->path, section.name) ;
		}

		return recheckFile( document->fileIndex) ;
	} ;
	api.module = [this, wifiBusInboxDocument, serialEnumeratorOnly](
					 std::uint64_t identity, std::wstring_view value) -> NativeError {
		const auto document = find( identity) ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		// 同SYSTEM原文と全原値からだけ提供位置を決めます
		if( !document ||
		   (document->value.origin != InfDependencyOrigin::SYSTEM &&
			!((storageFacts_ || collectorHdc_) &&
			  document->value.origin == InfDependencyOrigin::PACKAGE)) ||
		   value.empty() || value.find( L'\0') != value.npos) {
			return E_INVALIDARG ;
		}

		// DIRID 13は正規の元INFが対応する一つのStoreパッケージにだけ解決します
		if( wifiBusInboxDocument != 0U && identity == wifiBusInboxDocument) {
			const auto &store =
				files_[document->storeIndex]->path ;	// 元SetupAPIで固定したStore INFです
			const auto module = store.substr( 0U, store.find_last_of( L'\\') + 1U) +
								L"vwifibus.sys" ;		// 元INFと同じ配布に含まれる唯一のサービスSYSです
			const auto systemRoot = windows_ + L"\\" ;	// Windows APIで取得した正規の起点です
			// SystemRootを展開した場合にも同じ正規起点へ到達する位置だけを比較します
			const bool inSystem =
				module.size() > systemRoot.size() &&
				equalName( std::wstring_view{module}.substr( 0U, systemRoot.size()), systemRoot) ;
			// 元INFの未展開指示か、同じ実ファイルを指す完全なSCM表記だけを受け入れます
			if( !equalName( value, L"%13%\\vwifibus.sys") && !equalName( value, module) &&
			   !(inSystem &&
				 equalName( value, L"\\SystemRoot\\" + module.substr( systemRoot.size())))) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			const auto error = verifySystemFile( module) ;	// 実体の保護とWindows署名を固定します
			return error != 0U ? error : verifyInboxServiceModule( *document, module) ;
		}

		// この選択は元宣言と現在のSCMの正規位置を同じSerenumだけへ解決する
		if( serialEnumeratorOnly && identity == msPortsInboxDocument_) {
			const auto module =
				windows_ + L"\\System32\\drivers\\serenum.sys" ;	// 実Windowsの正規配備先
			// 正規ドライバー位置の元DIRIDまたは完全な同等表記だけを認める
			if( !equalName( value, module) && !equalName( value, L"%12%\\serenum.sys") &&
			   !equalName( value, L"\\SystemRoot\\System32\\drivers\\serenum.sys") &&
			   !equalName( value, L"%SystemRoot%\\System32\\drivers\\serenum.sys")) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			const auto error = verifySystemFile( module) ;	// 実配置の保護とWindows署名
			return error != 0U ? error : verifyInboxServiceModule( *document, module) ;
		}

		std::wstring path{value} ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
		const std::array<std::pair<std::wstring_view, std::wstring>, 5U> prefixes{
			// 元field/型の全消費を確認する局所位置又は閉じた分類です
			{{L"%10%\\", windows_ + L"\\"},
			 {L"%11%\\", windows_ + L"\\System32\\"},
			 {L"%12%\\", windows_ + L"\\System32\\drivers\\"},
			 {L"%SystemRoot%\\", windows_ + L"\\"},
			 {L"\\SystemRoot\\", windows_ + L"\\"}}} ;
		// 指定したWindows起点以外の環境変数を展開しません
		for( const auto &[prefix, target] : prefixes) {
			// 元の不正/不一致又は不足を成功へ補完しません
			if( path.size() >= prefix.size() &&	// 不明/不一致の元値を成功や別scopeへ補完しません
			   equalName( std::wstring_view{path}.substr( 0U, prefix.size()), prefix)) {
				path = target + path.substr( prefix.size()) ;
				break ;
			}
		}

		// 単一basenameは同型のWindows標準提供位置だけへ結びます
		if( path.find( L'\\') == path.npos) {
			const auto dot =
				// 元field/型の全消費を確認する局所位置又は閉じた分類です
				path.find_last_of( L'.') ;
			path = windows_ +
				   (dot != path.npos && equalName( std::wstring_view{path}.substr( dot), L".sys")
						? L"\\System32\\drivers\\"
						: L"\\System32\\") +
				   path ;
		}

		const auto slash =
			// 元field/型の全消費を確認する局所位置又は閉じた分類です
			path.find_last_of( L'\\') ;
		const auto parent =	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
			slash == path.npos ? std::wstring_view{} : std::wstring_view{path}.substr( 0U, slash) ;
		// 引数/別dir/未展開tokenをWindows署名だけで許可しません
		if( !validInfDependencyPath( path, true) ||
		   (!equalName( parent, windows_ + L"\\System32") &&
			!equalName( parent, windows_ + L"\\System32\\drivers") &&
			!equalName( parent, windows_ + L"\\System32\\drivers\\UMDF"))) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		const auto dot =
			// 元field/型の全消費を確認する局所位置又は閉じた分類です
			path.find_last_of( L'.') ;
		const auto extension =	// 元field/型の全消費を確認する局所位置又は閉じた分類です
			dot == path.npos ? std::wstring_view{} : std::wstring_view{path}.substr( dot) ;
		// SYSとUMDF/通常DLLの役割を同名別directoryへ取り替えません
		if( (equalName( extension, L".sys") &&
			!equalName( parent, windows_ + L"\\System32\\drivers")) ||
		   (equalName( extension, L".dll") && !equalName( parent, windows_ + L"\\System32") &&
			!equalName( parent, windows_ + L"\\System32\\drivers\\UMDF")) ||
		   (!equalName( extension, L".sys") && !equalName( extension, L".dll"))) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		const auto error = verifySystemFile( path) ;	// 元System32モジュールの署名と保護を確認します
		// 元標準SYSには、一般のWindows署名に加えて同じ元INFのCATを要求します
		if( error == 0 &&
		   (identity == msPortsInboxDocument_ || identity == storNvmeInboxDocument_ ||
			identity == storAhciInboxDocument_ || identity == winUsbInboxDocument_) &&
		   equalName( extension, L".sys")) {
			return verifyInboxServiceModule( *document, path) ;
		}

		return error ;
	} ;
	api.legacyRegistry = [this, &rows]( const SystemInfEffect &effect, bool media) -> NativeError {
		const auto document =
			// 同原文/操作へ結ぶ検査又は結果の所有値です
			find( effect.source.document) ;
		// 元の不正/不一致又は不足を成功へ補完しません
		if( !document ||
		   effect.row.values.size() > 20U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			return E_INVALIDARG ;
		}

		InfHandle inf{SetupOpenInfFileW( files_[document->fileIndex]->path.c_str(),
										nullptr,	// この同期/fixtureが所有する資源又は原状態です
										INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)} ;
		// 元の不正/不一致又は不足を成功へ補完しません
		if( inf.get() == INVALID_HANDLE_VALUE) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			return winError( GetLastError()) ;
		}

		INFCONTEXT setting{} ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		// 元の不正/不一致又は不足を成功へ補完しません
		if( !SetupGetLineByIndexW(
			   inf.get(), effect.source.name.c_str(),
			   effect.row.ordinal,	// 不明/不一致の元値を成功や別scopeへ補完しません
			   &setting)) {
			return winError( GetLastError()) ;
		}

		std::array<std::wstring, 20U>
			values{} ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		std::ranges::copy( effect.row.values, values.begin()) ;
		const NeedsSystemContext system{
			files_[document->fileIndex]->path,	// 元権限/署名の照合中だけ使う証拠です
			[this]() { return verifyStreamingComponents() ; }} ;
		return media ? verifySystemMediaRow( inf.get(), setting, values,
											static_cast<DWORD>( effect.row.values.size()), system,
											rows, diagnostic_)
					 : verifyRelativeNeedsRow( setting, values,
											  static_cast<DWORD>( effect.row.values.size()),
											  diagnostic_) ;
	} ;
	api.service = [wifiBusInboxDocument]( std::wstring_view		name,
										 SystemServiceEvidence &evidence) -> NativeError {
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
		// 専用fixtureの不足操作は実SCMへfallbackしません
		if( testApi) {
			return testApi->systemService ? testApi->systemService( name, evidence) : E_NOTIMPL ;
		}
#endif
		// 所有完全表の不足操作も実SCMへfallbackしません
		if( const auto active = inf_dependency_native_detail::activeApi()) {
			return active->systemService ? active->systemService( name, evidence) : E_NOTIMPL ;
		}

		// 同じ署名文書の仮想Wi-Fiバスだけは表示文字列と元登録値も確認します
		if( wifiBusInboxDocument != 0U && equalName( name, L"vwifibus")) {
			return readWifiBusServiceEvidence( evidence) ;
		}

		return readSystemServiceEvidence( name, evidence) ;
	} ;
	std::uint32_t stage{} ;		// 同原文/操作へ結ぶ検査又は結果の所有値です
	std::uint32_t observed{} ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
	// 同じ元選択節から単一起動の電源作用を確認し、専用検査で全体を確認する
	if( storageFacts_ && !storageFacts_->auxiliary &&
	   equalName( storageFacts_->className, L"SCSIAdapter")) {
		const SystemInfSection	  selected{root,
										   storageFacts_->selectedInstallSection,
										   SystemInfContext::DEVICE,
										   SystemInfContext::DEVICE,
										   {}} ;			// 同じWindows互換ノードが解決した元基本節
		std::vector<SystemInfRow> original ;				// 元選択を限定する署名付きの全行
		const auto read = api.read( selected, original) ;	// 共同上限と元内容を使う同じ読取り
		// 読取りが不成立の場合は元作用を別経路で許可しない
		if( read != 0U) {
			return read ;
		}

		singleBootStorage = std::ranges::any_of(
			original, []( const auto &row) { return equalName( row.key, L"AddPowerSetting") ; }) ;
	}

	// 下位検査の最初の診断を後続へ返す一時値です
	NativeError error =
		typed.empty() ? 0 : inspectSystemInfEffects( typed, api, typedEffects_, stage, observed) ;
	// 同じ原CABから固定したINFとSYSでHDCの全作用を確認する
	if( error == 0U && collectorHdc_) {
		constexpr std::wstring_view decoration = L".ntamd64" ;	// 今回検査する元AMD64の導入節の修飾
		const bool					decorated  = selectedBase_.size() > decoration.size() &&
							   equalName( std::wstring_view{selectedBase_}.substr(
											 selectedBase_.size() - decoration.size()),
										 decoration) ;			// 原AMD64修飾の有無
		auto selected = collector_->closure.packages.front() ;	// 元CATと全ファイルを固定した基本INF
		selected.selectedInstallSection = selectedBase_ ;
		// 元グループで固定した修飾なし節は同じ原名をWindowsの再選択に渡す
		selected.selectedBasicSection =
			decorated ? selectedBase_.substr( 0U, selectedBase_.size() - decoration.size())
					  : selectedBase_ ;
		SelectedStorageServiceFacts service ;	// 署名済みの原SYSと選択されたサービスの結合
		error = readSelectedStorageServiceFacts( workspace_, collector_->closure.entries, selected,
												service) ;
		// 一意のサービスとSYSを確認してからその作用の元フィールドを読む
		if( error == 0U) {
			StorageInfEffects storage ;	// 端末の既存サービスを読み取らずに得る元作用
			error =
				inspectHdcInfContentEffects( reached, api, service, context_.build, storage, stage) ;
			// 全作用を評価した結果だけを終了時の同一性検査へ渡す
			if( error == 0U) {
				storageEffects_ = std::move( storage) ;
			}
		}
	}

	// PACKAGE storageは別validatorで元由来/全tuple/全原値のまま評価します
	if( error == 0U && storageFacts_) {
		// PACKAGE由来を保つ全storage作用の開始節です
		std::vector<SystemInfSection> packageSeeds ;
		// SYSTEM由来をstorage PACKAGEへ偽装しません
		for( const auto &section : reached) {
			// 元NativeLoaderだけが保持する由来/署名/全byteのdocumentです
			const auto document = find( section.document) ;
			// PACKAGEの到達節はstorage専用validatorへ由来を保って渡します
			if( document && document->value.origin == InfDependencyOrigin::PACKAGE) {
				packageSeeds.push_back( section) ;
			}
		}

		// 同元用途が端末storage専用であるという非権限分類です
		StorageInfEffects storage ;
		// HDCの元作用を評価し、端末の正確な既存サービスを別に観測する
		if( nativeHdc_) {
			error = inspectHdcInfContentEffects( packageSeeds, api, *storageFacts_, context_.build,
												storage, stage) ;
			// 署名された元INFの作用を確認してから現在サービスを調べる
			if( error == 0U) {
				SystemServiceEvidence existing ;	// 現在のサービス構成と保護
				error = readStorageService( storage.service.name, existing,
										   &storage.currentHdcBinarySha256) ;
				// サービスの正式不存在を導入前の観測として保持する
				if( error ==
				   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST))) {
					storage.services.push_back( {storage.service.name, std::nullopt}) ;
					error = 0U ;
				}
				// 現在サービスがある場合は元ドライバーの作用との対応を確かめる
				else if( error == 0U) {
					// 現在SYSの完全パスからファイル名を切り出す区切り
					const auto separator = existing.binary.rfind( L'\\') ;
					// 同梱SYSの相対位置からファイル名を切り出す区切り
					const auto sourceSeparator = storage.service.binarySource.rfind( L'\\') ;
					// 同梱SYSの展開階層を除いた元ファイル名
					const auto sourceName = std::wstring_view{storage.service.binarySource}.substr(
						sourceSeparator == std::wstring::npos ? 0U : sourceSeparator + 1U) ;
					// 名前以外にカーネル種別、開始方式、起動グループを照合する
					if( separator == std::wstring::npos || !storage.service.group ||
					   existing.type != SERVICE_KERNEL_DRIVER ||
					   existing.start != SERVICE_BOOT_START ||
					   !equalName( existing.group, *storage.service.group) ||
					   !equalName( std::wstring_view{existing.binary}.substr( separator + 1U),
								  sourceName)) {
						error = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
					} else {
						storage.services.push_back( {storage.service.name, std::move( existing)}) ;
					}
				}

				stage = error == 0U ? 0U : 14010U ;
			}
		}
		// 元基本節が電源作用を持つ単一起動は、全原作用を同じ署名付き元から検査する
		else if( singleBootStorage) {
			error = inspectSingleBootStorageInfContentEffects( packageSeeds, api, *storageFacts_,
															  storage, stage) ;
		} else {
			// 自動起動補助の元内容は、現在のサービスや共有設定を読む前に確認する
			if( autoStartStorage) {
				error = inspectAutoStartStorageInfContentEffects( packageSeeds, api, *storageFacts_,
																 storage, stage) ;
				// DLLを配置しない従来形では既存の現用・共有先照合を行う
				if( error == 0U && !eventMessageCopy) {
					error =
						verifyStorageAutomaticHost( storage, packageSeeds.front().document, stage) ;
				}
			} else {
				error = inspectStorageInfEffects(
					packageSeeds, api, *storageFacts_,
					[this]( std::wstring_view name, SystemServiceEvidence &evidence) {
						return readStorageService( name, evidence) ;
					},
					context_.build, storage, stage) ;
			}
		}

		// 起動時の関連サービスを現在のWindowsの順序に結び付ける
		if( error == 0U &&
		   (nativeHdc_ || singleBootStorage || (autoStartStorage && !eventMessageCopy) ||
			equalName( storage.service.className, L"MediumChanger"))) {
			error = readStorageBootLoadOrder( storage.loadOrder.emplace()) ;
			stage = error == 0U ? 0U : 14011U ;
		}

		// 検証済み補助サービスが変更する元の現在状態だけを読み取る
		if( error == 0U && storage.service.auxiliary && !autoStartStorage) {
			error =
				readStorageAuxiliaryHostSnapshot( storage.service, storage.auxiliaryHost.emplace()) ;
			stage = error == 0U ? 0U : 14017U ;
		}

		// 全原作用の成立時だけ同期結果へ保持します
		if( error == 0U) {
			storageEffects_ = std::move( storage) ;
		}
	}

	std::vector<SystemInfEffect> forwarders ;	// PACKAGE自身をSYSTEM許可へ昇格させない原tupleです
	// 元rootのframework転送宣言だけを同到達SYSTEM作用へ完全一致させます
	for( const auto &section : reached) {
		const auto document = find( section.document) ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		// 元の不正/不一致又は不足を成功へ補完しません
		if( error != 0U || !document ||
		   document->value.origin !=
			   InfDependencyOrigin::PACKAGE ||	// 不明/不一致の元値を成功や別scopeへ補完しません
		   section.context != SystemInfContext::FRAMEWORK) {
			continue ;
		}

		std::vector<SystemInfRow> rowsRead ;	// 実操作から得た観測値です。独立期待とは分けます
		error = api.read( section, rowsRead) ;
		// 同元文脈の全対象を有限な共同予算内で確認します
		for( const auto &row : rowsRead) {	// 同原文の全対象を共有上限内で消費します
			// 元の不正/不一致又は不足を成功へ補完しません
			if( error != 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				break ;
			}

			// 元の不正/不一致又は不足を成功へ補完しません
			if( equalName( row.key, L"Include") ||
			   equalName( row.key, L"Needs")) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				continue ;
			}

			// 元の不正/不一致又は不足を成功へ補完しません
			if( typedEffects_.references >=
			   4096U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				error = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				break ;
			}

			++typedEffects_.references ;
			const auto context =
				equalName( row.key, L"KmdfService")
					? SystemInfContext::KMDF	// 同原文/操作へ結ぶ検査又は結果の所有値です
				: equalName( row.key, L"UmdfService") ? SystemInfContext::UMDF
													 : SystemInfContext::COMPANION ;
			const SystemInfEffect *match = nullptr ;	// この同期/fixtureが所有する資源又は原状態です
			// 他documentの名前だけを借りず、全fieldが同じ一意宣言を必要とします
			for( const auto &effect : typedEffects_.effects) {
				// 元の不正/不一致又は不足を成功へ補完しません
				if( effect.source.context ==
					   SystemInfContext::
						   FRAMEWORK &&	// 不明/不一致の元値を成功や別scopeへ補完しません
				   equalName( effect.row.key, row.key) &&
				   effect.row.values == row.values) {
					// 元の不正/不一致又は不足を成功へ補完しません
					if( match) {	// 不明/不一致の元値を成功や別scopeへ補完しません
						error = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						break ;
					}

					match = &effect ;
				}
			}

			// 元の不正/不一致又は不足を成功へ補完しません
			if( !match ||
			   row.values.size() != 2U ||	// 不明/不一致の元値を成功や別scopeへ補完しません
			   (!equalName( row.key, L"KmdfService") && !equalName( row.key, L"UmdfService") &&
				!equalName( row.key, L"CompanionConfiguration"))) {
				error = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				break ;
			}

			SystemInfSection child{section.document, row.values[1], context,
								   context,	// この同期だけで保持する元値です。許可の代用にしません
								   row.values[0]} ;
			std::vector<SystemInfRow>
				childRows ;	// この同期だけで保持する元値です。許可の代用にしません
			error = api.read( child, childRows) ;
			std::vector<SystemInfRow> originalRows ;	// 元選択/原文へ結合した所有値です
			// 同元文脈の全対象を有限な共同予算内で確認します
			for( const auto &effect :
				typedEffects_.effects) {	// 同原文の全対象を共有上限内で消費します
				// 元の不正/不一致又は不足を成功へ補完しません
				if( effect.source.document ==
					   match->source.document &&	// 不明/不一致の元値を成功や別scopeへ補完しません
				   effect.source.context == context &&
				   effect.source.scope == context &&
				   equalName( effect.source.owner, row.values[0]) &&
				   equalName( effect.source.name, row.values[1])) {
					originalRows.push_back( effect.row) ;
				}
			}

			// 元の不正/不一致又は不足を成功へ補完しません
			if( error == 0U &&
			   (childRows.empty() ||
				childRows != originalRows)) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				error = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			// 元の不正/不一致又は不足を成功へ補完しません
			if( error == 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				// 元の不正/不一致又は不足を成功へ補完しません
				if( forwarders.size() >=
					   4096U - typedEffects_.effects
								   .size() ||	// 不明/不一致の元値を成功や別scopeへ補完しません
				   childRows.size() > 4095U - typedEffects_.effects.size() - forwarders.size()) {
					error = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
					break ;
				}

				forwarders.push_back( {section, row}) ;
				// 同元文脈の全対象を有限な共同予算内で確認します
				for( const auto &value : childRows) {	// 同原文の全対象を共有上限内で消費します
					forwarders.push_back( {child, value}) ;
				}
			}
		}

		// 元の不正/不一致又は不足を成功へ補完しません
		if( error != 0U && stage == 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			stage = static_cast<std::uint32_t>( SystemInfDiagnosticStage::FRAMEWORK) ;
		}
	}

	// 元の不正/不一致又は不足を成功へ補完しません
	if( error == 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
		typedEffects_.effects.insert( typedEffects_.effects.end(), forwarders.begin(),
									 forwarders.end()) ;
	}

	// first-errorだけを既binding診断へ投影します
	if( error != 0U && diagnostic_ && diagnostic_->rejection == InfBindingReject::NONE) {
		diagnostic_->stage =
			stage != 0U ? stage : static_cast<std::uint32_t>( SystemInfDiagnosticStage::READ) ;
		static_cast<void>( diagnostic_->reject( error, InfBindingReject::DEPENDENCY, observed)) ;
	}

	return error ;
}

/** @brief 公式USB Bluetoothの選択に必要な同梱文書二つの識別子 */
struct BluetoothUsbInboxDocuments {
	/// 元三節の依存先として解決したBluetoothの同梱文書
	std::uint64_t bluetooth{} ;
	/// 同梱BluetoothのHW節から解決したPCIの同梱文書
	std::uint64_t pci{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 公式USB Bluetoothの元三節と正規同梱INF間の全参照を照合する
 * @param[in] edges 同じ読み取りで解決した全参照辺
 * @param[in] seeds 認証した元基本節、HW節、Services節をこの順に保持する一覧
 * @param[in] root 元INFの元観測内識別子。非零
 * @return 両同梱INFと八参照が一意に一致した場合は両文書の識別子、それ以外は空
 * @note この照合だけでは参照先の作用や端末の導入資格を確認しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] static std::optional<BluetoothUsbInboxDocuments> matchScopedBluetoothUsbReferences(
	std::span<const InfDependencyEdge> edges, std::span<const std::wstring> seeds,
	std::uint64_t root)
{
	// 元文書の三対と同梱間の一対だけを照合する
	if( root == 0U || edges.size() != 8U || seeds.size() != 3U) {
		return std::nullopt ;
	}

	const auto resolve = [edges]( std::uint64_t source, std::wstring_view section,
								 InfDependencyDirective directive, std::wstring_view target) {
		const auto found = std::ranges::find_if( edges, [&]( const auto &edge) {
			return edge.sourceIdentity == source && equalName( edge.sourceSection, section) &&
				   edge.directive == directive && equalName( edge.target, target) &&
				   edge.state == InfDependencyState::RESOLVED_SYSTEM ;
		}) ; // 指定した文書と節から実際に解決した一辺
		return found == edges.end() ? 0U : found->targetIdentity ;
	} ; // 現観測中だけ同じ全辺を借用して照合する処理

	const auto bluetooth = resolve( root, seeds.front(), InfDependencyDirective::INCLUDE,
								   L"bth.inf") ;	// 元基本節が参照した同梱Bluetoothの識別子
	// 元パッケージや同梱文書に解決しなかった名前を採用しない
	if( bluetooth == 0U || bluetooth == root) {
		return std::nullopt ;
	}

	constexpr std::array targets{L"BthUsb.NT", L"BthUsb.NT.HW",
								 L"BthUsb.NT.Services"} ;	// 用途ごとの同梱節
	// 元三節ごとに同じ同梱文書と正確な参照先を確認する
	for( std::size_t index = 0U; index < seeds.size(); ++index) {
		// 同名INFの別文書や別の作用節を正規参照に読み替えない
		if( resolve( root, seeds[index], InfDependencyDirective::INCLUDE, L"bth.inf") != bluetooth ||
		   resolve( root, seeds[index], InfDependencyDirective::NEEDS, targets[index]) !=
			   bluetooth) {
			return std::nullopt ;
		}
	}

	const auto pci		= resolve( bluetooth, targets[1], InfDependencyDirective::INCLUDE,
								  L"pci.inf") ;	// 同梱BluetoothのHWが参照した別の同梱INF
	const bool pciBound = pci != 0U && pci != root && pci != bluetooth &&
						  resolve( bluetooth, targets[1], InfDependencyDirective::NEEDS,
								  L"PciD3ColdSupported.HW") == pci ;	// HWだけが参照する同梱PCI文書
	return pciBound ? std::optional{BluetoothUsbInboxDocuments{bluetooth, pci}} : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief Bluetooth機器設定の検査節に所定行数があり、ACLの付随宣言がないことを確認する
 * @param[in] inf 同期中だけ借用する元INF
 * @param[in] section 元参照先の正確な節名
 * @param[in] expected 完全な元行数
 * @return 正常に読み取った元節が期待に合う場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] static bool bluetoothSectionHasExpectedRows( HINF inf, const wchar_t *section,
														  LONG expected)
{
	const auto security = std::wstring{section} + L".Security" ;	// 同じ元節のACL宣言位置
	SetLastError( ERROR_SUCCESS) ;
	const auto securityRows = SetupGetLineCountW( inf, security.c_str()) ;	// ACLの付随宣言の有無
	const auto error		= GetLastError() ;								// 一般の読み取り失敗と節不在を分ける元診断
	return securityRows < 0L && (error == ERROR_SUCCESS || error == ERROR_SECTION_NOT_FOUND) &&
		   SetupGetLineCountW( inf, section) == expected ;
}

//------------------------------------------------------------------------------
/**
 * @brief 機器のHW節に一値の元参照が所定の順序で存在することを確認する
 * @param[in] inf 同じ署名済み元INF
 * @param[in] section 同じ選択から到達したHW節
 * @param[in] rows 各行のディレクティブと参照先の組を元順で保持する有限一覧
 * @return 全行と元参照が一致した場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] static bool verifyBluetoothHwDirectives(
	HINF inf, const wchar_t *section,
	std::span<const std::pair<const wchar_t *, const wchar_t *>> rows)
{
	// 追加の設定や不明な権限操作を既知の元参照から除外しない
	if( !bluetoothSectionHasExpectedRows( inf, section, static_cast<LONG>( rows.size()))) {
		return false ;
	}

	// 元の全行を読み、作用の種類と参照先を同じ順序で照合する
	for( DWORD index = 0U; index < rows.size(); ++index) {
		INFCONTEXT	 line{} ;	// 同じ元節の一行
		std::wstring value ;	// 元キーと展開済みの参照先
		// 別の参照や複数フィールドを一つの期待値に縮約しない
		if( !SetupGetLineByIndexW( inf, section, index, &line) || SetupGetFieldCount( &line) != 1U ||
		   field( line, 0U, value) != 0U || !equalName( value, rows[index].first) ||
		   field( line, 1U, value) != 0U || !equalName( value, rows[index].second)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 機器キー相対の値操作から名前、相対位置、型・操作フラグを厳密に確認する
 * @param[in,out] line 正確な元節と行から取得したSetupAPIコンテキスト
 * @param[in] fields 元行の全フィールド数
 * @param[in] subkey 機器キー相対の元位置。直下を要求する場合は空
 * @param[in] name 元の値名
 * @param[in] flags AddReg又はDelRegの元フラグ
 * @return 全フィールド構造と指定値が一致した場合true
 * @note 値データとAddReg・DelRegの種類は参照元を保持する呼出し側が検査する
 */
//------------------------------------------------------------------------------
[[nodiscard]] static bool verifyBluetoothDeviceValueHeader( INFCONTEXT &line, DWORD fields,
														   std::wstring_view subkey,
														   std::wstring_view name, int flags)
{
	std::wstring value ;			// SetupAPIから順に読む元のプリアンブル
	int			 observedFlags{} ;	// この行に記載された元の型と操作
	return SetupGetFieldCount( &line) == fields &&
		   field( line, 0U, value) == HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER) &&
		   field( line, 1U, value) == 0U && equalName( value, L"HKR") &&
		   field( line, 2U, value) == 0U &&
		   (subkey.empty() ? value.empty() : equalName( value, subkey)) &&
		   field( line, 3U, value) == 0U && equalName( value, name) && field( line, 4U, value) == 0U &&
		   !value.empty() && SetupGetIntField( &line, 4U, &observedFlags) && observedFlags == flags ;
}

//------------------------------------------------------------------------------
/**
 * @brief Bluetooth機器キーの追加と削除、同梱PCIの電源設定の元宣言を確認する
 * @param[in] bluetooth 公式対象から参照して署名と由来を確認済みの同梱Bluetooth INF
 * @param[in] pci 同じHW参照から解決し署名と由来を確認済みの同梱PCI INF
 * @return 両文書の機器相対作用が全件一致して0、読取・構造・型の不一致時はHRESULT
 * @note 元宣言の順序と型を検査する。OS処理順や対象機器での結果を推定しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] static NativeError verifyBluetoothUsbHardwareDeclarations( HINF bluetooth, HINF pci)
{
	static constexpr wchar_t ADD[]	  = L"BthPort.NT.HW.AddReg" ;	// 同梱Bluetoothの機器設定追加節
	static constexpr wchar_t REMOVE[] = L"BthPort.NT.HW.DelReg" ;	// 同じ選択の旧機器設定削除節
	static constexpr wchar_t PCI_REGISTRY[] =
		L"PciD3ColdSupported.RegHW" ;												// 同梱PCIの機器電源設定節
	constexpr NativeError UNSUPPORTED = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;	// 未確認の機器作用
	constexpr std::array  BLUETOOTH_REFS{
		 std::pair{L"AddReg", ADD}, std::pair{L"DelReg", REMOVE}, std::pair{L"Include", L"pci.inf"},
		 std::pair{L"Needs", L"PciD3ColdSupported.HW"}} ;				// HWの全参照
	constexpr std::array PCI_REFS{std::pair{L"AddReg", PCI_REGISTRY}} ;	// PCI電源節の全参照
	// 操作を宣言した側の文書と選択HW節を先に結び、同名の別節を参照しない
	if( !verifyBluetoothHwDirectives( bluetooth, L"BthUsb.NT.HW", BLUETOOTH_REFS) ||
	   !verifyBluetoothHwDirectives( pci, L"PciD3ColdSupported.HW", PCI_REFS) ||
	   !bluetoothSectionHasExpectedRows( bluetooth, ADD, 3L) ||
	   !bluetoothSectionHasExpectedRows( bluetooth, REMOVE, 4L) ||
	   !bluetoothSectionHasExpectedRows( pci, PCI_REGISTRY, 1L)) {
		return UNSUPPORTED ;
	}

	constexpr std::array VALUE_NAMES{L"Scans Before Out of Range", L"SCO Max Channels",
									 L"Store Link Key COD Masks",
									 L"SCO Support Level"} ;	// 機器相対の値名
	// 削除の全行を独立に読み、名前のないキー削除や他の削除フラグを認めない
	for( DWORD index = 0U; index < VALUE_NAMES.size(); ++index) {
		INFCONTEXT row{} ;	// この削除だけの元行
		// 値の追加行や別のサブキーを同じ削除作用へ読み替えない
		if( !SetupGetLineByIndexW( bluetooth, REMOVE, index, &row) ||
		   !verifyBluetoothDeviceValueHeader( row, 4U, {}, VALUE_NAMES[index], 0)) {
			return UNSUPPORTED ;
		}
	}

	constexpr std::array DWORD_FLAGS{FLG_ADDREG_TYPE_DWORD | FLG_ADDREG_NOCLOBBER,
									 FLG_ADDREG_TYPE_DWORD} ;	// 元のDWORDフラグ
	constexpr std::array DWORD_VALUES{8, 2} ;					// それぞれの元DWORD値
	// 値の追加は同名を削除する宣言とは独立に、型・上書き方針とデータを確認する
	for( DWORD index = 0U; index < DWORD_VALUES.size(); ++index) {
		INFCONTEXT row{} ;		// このDWORDの元追加行
		int		   value{} ;	// SetupAPIが展開した数値
		// 型やNOCLOBBERの違いを同じ値として受理しない
		if( !SetupGetLineByIndexW( bluetooth, ADD, index, &row) ||
		   !verifyBluetoothDeviceValueHeader( row, 5U, {}, VALUE_NAMES[index], DWORD_FLAGS[index]) ||
		   !SetupGetIntField( &row, 5U, &value) || value != DWORD_VALUES[index]) {
			return UNSUPPORTED ;
		}
	}

	constexpr std::array<BYTE, 16U>	   COD_MASKS{0x00U, 0x00U, 0x1fU, 0x43U, 0x00U, 0x00U,
												 0x05U, 0x40U, 0x00U, 0x00U, 0x1fU, 0x83U,
												 0x00U, 0x00U, 0x05U, 0x80U} ;	// 元REG_BINARY
	std::array<BYTE, COD_MASKS.size()> binary{} ;								// 元行から読んだ実バイト
	INFCONTEXT						   maskRow{} ;								// 機器のマスク値の元追加行
	DWORD							   required{} ;								// SetupAPIが返す実バイト数
	// 全16バイトを正しいREG_BINARY形式で一致させる
	if( !SetupGetLineByIndexW( bluetooth, ADD, 2U, &maskRow) ||
	   !verifyBluetoothDeviceValueHeader( maskRow, 4U + static_cast<DWORD>( COD_MASKS.size()), {},
										 VALUE_NAMES[2], FLG_ADDREG_TYPE_BINARY) ||
	   !SetupGetBinaryField( &maskRow, 5U, binary.data(), static_cast<DWORD>( binary.size()),
							&required) ||
	   required != binary.size() || binary != COD_MASKS) {
		return UNSUPPORTED ;
	}

	// 空の元フィールドを明示的なゼロバイトへ補完しない
	for( DWORD index = 5U; index < 5U + COD_MASKS.size(); ++index) {
		std::wstring octet ;	// 元REG_BINARYの一つの明示フィールド
		// データ長とは独立に各元フィールドが指定されていることを要求する
		if( field( maskRow, index, octet) != 0U || octet.empty()) {
			return UNSUPPORTED ;
		}
	}

	INFCONTEXT pciRow{} ;	// 署名済みPCI文書内の元電源設定
	int		   enabled{} ;	// 固定の電源設定値
	// PCI由来の固定位置、型、設定値を一組として保持する
	return SetupGetLineByIndexW( pci, PCI_REGISTRY, 0U, &pciRow) &&
				   verifyBluetoothDeviceValueHeader( pciRow, 5U,
													L"e5b3b5ac-9725-4f78-963f-03dfb1d828c7",
													L"D3ColdSupported", FLG_ADDREG_TYPE_DWORD) &&
				   SetupGetIntField( &pciRow, 5U, &enabled) && enabled == 1
			   ? 0U
			   : UNSUPPORTED ;
}

// BthUsbの基本節が順番に参照する二つの保護コピーリスト
constexpr std::array BLUETOOTH_USB_COPY_LISTS{L"BthUsb.NT.Copy", L"BthPort.NT.CopyFiles"} ;
// 各コピーリストが所有する同名の元ファイルと宛先ファイル
constexpr std::array BLUETOOTH_USB_COPY_FILES{L"bthusb.sys", L"bthport.sys"} ;

//------------------------------------------------------------------------------
/**
 * @brief 同梱Bluetoothの元コピー宣言とSetupAPIが展開した配備先を確認する
 * @param[in] inf 同期中だけ借用する同梱INFの読み取り用ハンドル
 * @param[in] driversDirectory 現在のWindowsから確定した標準driversの絶対位置
 * @return 二つのリストが標準driversへ期待する保護コピーを行う場合0、構造・読取・位置の失敗はHRESULT
 * @note ファイルの信頼と元CATへの所属は呼出し側で確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] static NativeError verifyBluetoothUsbCopyDeclaration(
	HINF inf, std::wstring_view driversDirectory)
{
	constexpr wchar_t	  INSTALL[]		 = L"BthUsb.NT" ;		// 選択内でコピーを所有する元基本節
	constexpr wchar_t	  DESTINATIONS[] = L"DestinationDirs" ;	// 同梱INFのリスト別の明示宛先
	constexpr NativeError UNSUPPORTED =
		// 元のコピー形式との不一致
		HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	INFCONTEXT	 copy{} ;		// 基本節の唯一のCopyFiles
	INFCONTEXT	 registry{} ;	// 同じ基本節が参照する登録一件
	std::wstring value ;		// SetupAPIが展開した現在の値
	// コピー以外のファイル操作や追加のコピーリストをこの元選択に含めない
	if( SetupGetLineCountW( inf, INSTALL) != 2L ||
	   !SetupFindFirstLineW( inf, INSTALL, L"CopyFiles", &copy) ||
	   SetupGetFieldCount( &copy) != BLUETOOTH_USB_COPY_LISTS.size() ||
	   !SetupFindFirstLineW( inf, INSTALL, L"AddReg", &registry) ||
	   SetupGetFieldCount( &registry) != 1U || field( registry, 1U, value) != 0U ||
	   !equalName( value, L"Fsquirt.NT.AddReg")) {
		return UNSUPPORTED ;
	}

	// 参照された両リストについて元順序、コピー行と宛先を確認する
	for( DWORD index = 0U; index < BLUETOOTH_USB_COPY_LISTS.size(); ++index) {
		const auto *list = BLUETOOTH_USB_COPY_LISTS[index] ;	// 元基本節と対応するコピーリスト
		INFCONTEXT	row{} ;										// リストの唯一の元コピー行
		int			flags{} ;									// 元コピー行の完全な保護フラグ
		// 同じ元ファイル名と保護フラグで、改名・一時名の指定がないことを要求する
		if( field( copy, index + 1U, value) != 0U || !equalName( value, list) ||
		   SetupGetLineCountW( inf, list) != 1L || !SetupGetLineByIndexW( inf, list, 0U, &row) ||
		   SetupGetFieldCount( &row) != 4U || field( row, 1U, value) != 0U ||
		   !equalName( value, BLUETOOTH_USB_COPY_FILES[index]) || field( row, 2U, value) != 0U ||
		   !value.empty() || field( row, 3U, value) != 0U || !value.empty() ||
		   !SetupGetIntField( &row, 4U, &flags) || flags != COPYFLG_PROTECTED_WINDOWS_DRIVER_FILE) {
			return UNSUPPORTED ;
		}

		const auto security = std::wstring{list} + L".Security" ;	// 同リストに付随し得る保護設定
		SetLastError( ERROR_SUCCESS) ;
		const auto securityCount = SetupGetLineCountW( inf, security.c_str()) ;	// 付随節の存在観測
		const auto securityError = GetLastError() ;								// 不在と読取失敗を分ける元診断
		// コピーから別のACLを適用する指定があれば、この形式では成立しない
		if( securityCount >= 0L ||
		   (securityError != ERROR_SUCCESS && securityError != ERROR_SECTION_NOT_FOUND)) {
			return securityCount >= 0L ? UNSUPPORTED : winError( securityError) ;
		}

		INFCONTEXT destination{} ;	// 同リストだけの明示宛先
		INFCONTEXT duplicate{} ;	// 同じリストの二つ目の宛先を検出する
		int		   dirId{} ;		// SetupAPIが展開した単独のDIRID
		// サブディレクトリや既定値への置換を許容せず、12を一意な明示値に要求する
		if( !SetupFindFirstLineW( inf, DESTINATIONS, list, &destination) ||
		   SetupGetFieldCount( &destination) != 1U || !SetupGetIntField( &destination, 1U, &dirId) ||
		   dirId != 12 || SetupFindNextMatchLineW( &destination, list, &duplicate)) {
			return UNSUPPORTED ;
		}

		std::array<wchar_t, MAX_PATH> path{} ;		// 実SetupAPIから得た現Windowsの配備ディレクトリ
		DWORD						  required{} ;	// NULを含むSetupAPI応答の必要文字数
		// 実際に展開される位置を照合し、DIRIDの数値だけで配備先を推測しない
		if( !SetupGetTargetPathW( inf, nullptr, list, path.data(), static_cast<DWORD>( path.size()),
								&required)) {
			return winError( GetLastError()) ;
		}

		// 過長や別の場所に展開される同名コピーを拒否する
		if( required == 0U || required > path.size() || path[required - 1U] != L'\0' ||
		   !equalName( std::wstring_view{path.data(), required - 1U}, driversDirectory)) {
			return UNSUPPORTED ;
		}
	}

	return 0U ;
}

/** @brief 署名済みBluetooth同梱文書内の一つの共有作用節 */
struct BluetoothSharedSectionRule {
	/// 元参照が指定した正確な節名
	const wchar_t	 *name ;
	/// 全元行数
	LONG			  rows ;
	/// SetupAPIが返した全行のキー・欄数・各フィールドを長さ付きUTF-16LEにしたハッシュ
	std::wstring_view fieldsSha256 ;
	/// サービス実体を宣言する節だけに指定する既知のSYS名
	std::wstring_view serviceModule{} ;
	/// 同じ文書で別に検査対象とした .Security 節を持つか
	bool			  hasSecurity{} ;
} ;

// 既知Windowsで確認したBTHUSB・BTHPORT、イベント、ACL、COMの到達節。非選択節の更新は対象外
constexpr BluetoothSharedSectionRule BLUETOOTH_SHARED_SECTIONS[]{
	{L"BthUsb.NT.Services", 2L,
	 L"4ae5df21ecede11d1b641272b0dc2df5bb9c37f448e69b747536553069d1a3dd"},
	{L"BthUsb_Service_Inst", 7L,
	 L"df55ac4fbea60c6b72935ac42be4c891ca52d94990d81cd1a7051b91665652b1", L"bthusb.sys"},
	{L"BthUsb_Service_Inst.AddReg", 1L,
	 L"37e3d8ad3e819b9da767c388821e55813dce7118f6d5ab1285c311cb76e77b65"},
	{L"BthUsb_EventLog_Inst", 1L,
	 L"eeeb535001cadb1dfb602b07eef4ac75a38c4adeacc3c7fb8940133d0cbeedf3"},
	{L"BthUsb_EventLog_Inst.AddReg", 2L,
	 L"0f3c6a989c07f642a1334fdbab031767c30a03ad047dfed26d832127f2d4e1fa"},
	{L"BthUsb_ETW.AddReg", 20L,
	 L"28bf5ccc287b7fcebcd4edf5d65ae6b3c784036789924d9685357cb089069665"},
	{L"BthPort_Service_Inst", 7L,
	 L"ace926907a59d3cec3cd4694abc0182ff08dc97128ffddd4a393a1adaa1cb7de", L"bthport.sys"},
	{L"BthPort_Service_Inst.AddReg", 98L,
	 L"fcb1cfa851f6ff742406e232e31ac4f1669f623aae87e38412c961ea0c647e31"},
	{L"BthPort_Service_Inst.Setup.AddReg",
	 3L,
	 L"849b92757dc326b8126fc01668a8fb7ef2303914e6b269444b755a527995530b",
	 {},
	 true},
	{L"BthPort_Service_Inst.Setup.AddReg.Security", 1L,
	 L"c674c73b5f414625f39e7c11925f9b7295133775f07090aa71f2cc605156901f"},
	{L"BthPort_Service_Inst.System.AddReg",
	 1L,
	 L"fbf23ddf64e1c4da21e036108033bbe0cf5268a5365d1dc461054a2c6e1f0bbb",
	 {},
	 true},
	{L"BthPort_Service_Inst.System.AddReg.Security", 1L,
	 L"9e7a32db369d8a9fdc73c0ab2047e2a2dce5be3fb650ade7d5ec81fda26e355c"},
	{L"BthPort_EventLog_Inst", 1L,
	 L"b6a7b098fec70c09c823a8b4b25a3fc0b814bf4637d44b32f63164989bf54c9c"},
	{L"BthPort_EventLog_Inst.AddReg", 2L,
	 L"6a77f51f5eff4a4560c0061fc63ca8a60befe02c493313792ec30eb1f016a582"},
	{L"BthPort_ETW.AddReg", 32L,
	 L"08d355963fd8297155029b432620cd7c5d41e4823aee4d98ab342c57633868e1"},
	{L"Fsquirt.NT.AddReg", 3L, L"38d3a401da67ce7b562ade70faf8d1d801879e4b1c88c8f5239bc88bf70aec83"},
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元サービス節の表示名と現在OSの展開に限って、共有作用の比較形式へ写す
 * @param[in] key 元行のキー
 * @param[in] count 元行のフィールド数
 * @param[in] module 元サービスの固定SYS名。別の作用節では空
 * @param[in] driversDirectory 正規のWindows drivers絶対ディレクトリ
 * @param[in,out] value SetupAPIが返した元フィールド。比較形式へ変換する場合だけ更新する
 * @return すべての比較前提を確認できた場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] static bool normalizeBluetoothSharedField( const std::wstring &key, DWORD count,
														std::wstring_view	module,
														const std::wstring &driversDirectory,
														std::wstring	   &value)
{
	// サービス節以外では空欄を含むすべての元フィールドをそのまま比較する
	if( module.empty() || key.empty()) {
		return true ;
	}

	// OS言語で変化する単独の表示名を確認し、他のサービス設定と区別する
	if( equalName( key, L"DisplayName")) {
		// 表示文字列だけを許容し、間接指定や制御文字は比較値に写さない
		if( count != 1U || value.empty() || value.front() == L'@' ||
		   std::ranges::any_of( value, []( wchar_t ch) { return ch < L' ' || ch == 0x7f ; })) {
			return false ;
		}

		value = L"<display>" ;
	}

	// SetupAPIが展開した実体は確認済みWindows driversの完全パスに結ぶ
	if( equalName( key, L"ServiceBinary")) {
		// 別パスや引数付きのサービス実体を同じ役割に変換しない
		if( count != 1U || !equalName( value, driversDirectory + L"\\" + std::wstring{module})) {
			return false ;
		}

		value = L"<drivers>\\" + std::wstring{module} ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共有作用の元節から全行・全フィールドを固定し、確認した署名付き文書の宣言と照合する
 * @param[in] inf 同期中に借用する署名と同梱由来を確認済みの元INF
 * @param[in] rule 対象となる一つの共有登録と全行の比較条件
 * @param[in] driversDirectory 正規のWindows drivers絶対ディレクトリ
 * @return 全フィールドが所定の節・順序・値で一致して0、読取失敗、追加登録、内容差はHRESULT
 * @note ここでは元宣言を照合する。共有キーを開かず、変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] static NativeError verifyBluetoothSharedSection(
	HINF inf, const BluetoothSharedSectionRule &rule, const std::wstring &driversDirectory)
{
	constexpr NativeError UNSUPPORTED = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;	// 未確認の共有宣言
	// 照合対象外のACLが付随した節や、欠落・追加された行を拒否する
	if( !(rule.hasSecurity ? SetupGetLineCountW( inf, rule.name) == rule.rows
						  : bluetoothSectionHasExpectedRows( inf, rule.name, rule.rows))) {
		return UNSUPPORTED ;
	}

	static_assert( sizeof( wchar_t) == 2U) ;
	std::wstring material ;	// 各フィールドを長さ付きUTF-16LEとして順に保持した比較入力
	const auto	 append = [&material]( std::wstring_view value) {
		  material.push_back( static_cast<wchar_t>( value.size())) ;
		  material.append( value) ;
	} ; // 有限なSetupAPI読取りの呼出し中だけ比較入力を借用する
	// 元行を順番に読み、キー・欄数・すべての元フィールドを結ぶ
	for( LONG index = 0; index < rule.rows; ++index) {
		INFCONTEXT row{} ;	// 現在の元行
		// 欠けた元行を空の設定とみなさない
		if( !SetupGetLineByIndexW( inf, rule.name, static_cast<DWORD>( index), &row)) {
			return winError( GetLastError()) ;
		}

		const auto count = SetupGetFieldCount( &row) ;	// 省略欄を含む元欄数
		// 元欄数を有界の比較入力に限定する
		if( count == 0U || count > 64U) {
			return UNSUPPORTED ;
		}

		std::wstring key ;							// 無名の元データ行だけ空
		auto		 error = field( row, 0U, key) ;	// 元ディレクティブ名の有無
		// 無名データ行と不正な名前付き行、別の読取り異常を区別する
		if( error == 0U ? key.empty() : error != HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER)) {
			return error != 0U ? error : UNSUPPORTED ;
		}

		append( key) ;
		material.push_back( static_cast<wchar_t>( count)) ;
		// 既知サービスの二つの表示・パス欄を除き、空欄を含む全元値を保持する
		for( DWORD position = 1U; position <= count; ++position) {
			std::wstring value ;	// 現在の元フィールド
			error = field( row, position, value) ;
			// 切り詰めや未知のパス・表示指定を元値として証明しない
			if( error != 0U || !normalizeBluetoothSharedField( key, count, rule.serviceModule,
															 driversDirectory, value)) {
				return error != 0U ? error : UNSUPPORTED ;
			}

			append( value) ;
		}
	}

	const auto	source = std::as_bytes( std::span{material}) ;	// Windows上のUTF-16LEコード単位
	std::string bytes( source.size(), '\0') ;					// 共通SHA-256入口が同期借用する同じバイト列
	std::memcpy( bytes.data(), source.data(), source.size()) ;
	std::wstring digest ;	// 元列挙の順序と全値に対するSHA-256
	// 元文書のハッシュを計算した際の診断値。成功まで出力を照合しない
	const auto	 error = computeBytesSha256( bytes, digest) ;
	// 既知の作用と異なる元節を個数だけで合格させない
	return error != 0U ? error : (digest == rule.fieldsSha256 ? 0U : UNSUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択した同梱Bluetoothが持つ共有設定の全到達先を検査する
 * @param[in] inf 同期中に借用する固定済み同梱Bluetooth INF
 * @param[in] driversDirectory Windowsが展開する正規driversディレクトリ
 * @return 既知の全作用と一致して0、別の付随節または元読取・値の不一致はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] static NativeError verifyBluetoothSharedDeclarations(
	HINF inf, const std::wstring &driversDirectory)
{
	constexpr std::wstring_view PREFIX = L"BthUsb.NT." ;	// 公式選択から到達する同梱の実節の接頭辞
	// 新しい付随作用の混入を検出し、上限に達した場合は遅れて現れる宣言を見落とさない
	for( UINT index = 0U; index < 4096U; ++index) {
		std::array<wchar_t, MAX_PATH> name{} ;	// 現在列挙した完全な節名
		// 正規の列挙終端まで確認する
		if( !SetupEnumInfSectionsW( inf, index, name.data(), static_cast<UINT>( name.size()),
								  nullptr)) {
			const auto error = GetLastError() ;	// 元の列挙診断
			// 上限、読み取り不能などを正常終端にしない
			if( error != ERROR_NO_MORE_ITEMS) {
				return winError( error) ;
			}

			// 列挙が正常に終わった元文書の全共有節を同じ署名・元バイトに結ぶ
			for( const auto &rule : BLUETOOTH_SHARED_SECTIONS) {
				const auto result =
					// 元節単位の結果
					verifyBluetoothSharedSection( inf, rule, driversDirectory) ;
				// 一つの不明な作用も他の成功で補わない
				if( result != 0U) {
					return result ;
				}
			}

			return 0U ;
		}

		const std::wstring_view section{name.data()} ;	// より長い別名を元節に短縮しない
		// 既知のコピー・HW・Services以外へ選択の作用を広げない
		if( equalName( section.substr( 0U, PREFIX.size()), PREFIX) &&
		   !equalName( section, L"BthUsb.NT.Copy") && !equalName( section, L"BthUsb.NT.HW") &&
		   !equalName( section, L"BthUsb.NT.Services")) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}
	}

	return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB Bluetoothの機器設定、共有登録、保護ファイルを同梱文書と現在のWindowsに結ぶ
 * @param[in] result 同期中に解決した同じ依存グラフ
 * @param[in] seeds 公式USB選択の元基本節、HW節、Services節をこの順に保持する一覧
 * @return 機器と共有設定の元宣言、資源の署名・バイトが一致して0、失敗時は元HRESULT
 * @note 読取り専用。機器および共有レジストリの現在値と導入資格は確定しない
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifyBluetoothUsbActions( const InfDependencyNativeResult &result,
													std::span<const std::wstring>	 seeds)
{
	// 署名と参照の元証拠が欠けた場合はファイル名から同梱元を補わない
	if( !result.dependency.plan.referencesResolved || !result.dependency.plan.rootEvidenceVerified) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const auto documents = matchScopedBluetoothUsbReferences( result.dependency.edges, seeds,
															 // 全辺から特定した同梱文書
															 documents_.front().value.identity) ;
	// 元参照の所有文書を一意に結べた場合だけ同梱の作用を読む
	if( !documents) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const auto findInbox = [this]( std::uint64_t identity, const wchar_t *leaf) -> NativeDocument * {
		auto *document = find( identity) ;	// 同じrunでバイトを固定した依存先
		// 他の由来・署名・位置の文書を同梱INFとして扱わない
		if( !document || document->value.origin != InfDependencyOrigin::SYSTEM ||
		   document->value.signature != InfDependencyEvidence::VERIFIED ||
		   document->value.provenance != InfDependencyEvidence::VERIFIED ||
		   document->signerScore != SIGNERSCORE_INBOX || document->storeIndex == MAX_FILES ||
		   document->catalogIndex == MAX_FILES ||
		   !equalName( files_[document->fileIndex]->path, windows_ + L"\\INF\\" + leaf)) {
			return nullptr ;
		}

		return document ;
	} ; // この同期だけ現在の固定文書集合を借用する
	const auto *document =
		// Bluetoothの全作用を所有するINF
		findInbox( documents->bluetooth, L"bth.inf") ;
	const auto *pci = findInbox( documents->pci, L"pci.inf") ;	// PCIの電源設定を所有するINF
	// 片方の正規性から他方の確認を省略しない
	if( !document || !pci) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const InfHandle inf{SetupOpenInfFileW( files_[document->fileIndex]->path.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_IGNORE,
										  nullptr)} ;	// 固定済みの同梱INF
	// 元文書を読み取れない場合は現在のモジュールの存在だけで成功にしない
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	const InfHandle pciInf{SetupOpenInfFileW( files_[pci->fileIndex]->path.c_str(), nullptr,
											 INF_STYLE_WIN4 | INF_STYLE_CACHE_IGNORE,
											 nullptr)} ;	// 固定済みPCI INF
	// 同梱Bluetoothの身元とは別にPCIの元読取り診断を保持する
	if( pciInf.get() == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	auto error =
		// 両文書の機器設定
		verifyBluetoothUsbHardwareDeclarations( inf.get(), pciInf.get()) ;
	// 設定の別作用や型の差があればコピー検査の成功を使わない
	if( error != 0U) {
		return error ;
	}

	const auto driversDirectory = windows_ + L"\\System32\\drivers" ;	// 同OSの標準の配備先
	error						= verifyBluetoothSharedDeclarations( inf.get(), driversDirectory) ;
	// 共有登録が不明な場合はファイルだけで作用全体を認定しない
	if( error != 0U) {
		return error ;
	}

	error =
		// 元宣言と実宛先の診断
		verifyBluetoothUsbCopyDeclaration( inf.get(), driversDirectory) ;
	// 元コピーに不一致があれば署名済みの同名バイトがあっても失敗する
	if( error != 0U) {
		return error ;
	}

	// 二つの実配置をWindows署名・保護と同じDriver Store原本へ結ぶ
	for( const auto *name : BLUETOOTH_USB_COPY_FILES) {
		const auto path = driversDirectory + L"\\" + name ;	// 直前に確認した同名ファイルの配備先
		error			= verifySystemFile( path) ;
		// 先行するWindows署名と保護の失敗を元CATが成功しても上書きしない
		if( error == 0U) {
			error = verifyInboxServiceModule( *document, path) ;
		}

		// 片方の検査成功で他方の不足を補わない
		if( error != 0U) {
			return error ;
		}
	}

	// COMとイベントが指定したWindowsの固定資源を非実行で保護・署名確認する
	for( const auto *name : {L"fsquirt.exe", L"IoLogMsg.dll"}) {
		error = verifySystemFile( windows_ + L"\\System32\\" + name) ;
		// 元の資源と実バイトの検査に失敗した場合は観測を保留する
		if( error != 0U) {
			return error ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 混在媒体の元基本節とServices節が同じ同梱文書だけを参照することを確認する
 * @param[in] edges 同じ署名確認済みの元選択に結ぶ全参照
 * @param[in] seeds 実DDInstall、HW、Servicesの元選択順
 * @param[in] root 元パッケージ文書の識別子。非零
 * @param[in] inbox 認証済みmsports.infの識別子。非零
 * @return 四つの参照全てが指定の元節と同梱先に一意に一致する場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] static bool matchesSerialEnumeratorReferences(
	std::span<const InfDependencyEdge> edges, std::span<const std::wstring> seeds,
	std::uint64_t root, std::uint64_t inbox)
{
	// 自前HW節から追加の同梱作用が来た場合も全参照数で拒否する
	if( edges.size() != 4U || seeds.size() != 3U || root == 0U || inbox == 0U || root == inbox) {
		return false ;
	}

	const auto one = [edges, root, inbox]( std::wstring_view		 section,
										  InfDependencyDirective directive,
										  std::wstring_view		 target) {
		return std::ranges::count_if( edges, [&]( const auto &edge) {
				   return edge.sourceIdentity == root && edge.targetIdentity == inbox &&
						  edge.state == InfDependencyState::RESOLVED_SYSTEM &&
						  edge.directive == directive && equalName( edge.sourceSection, section) &&
						  equalName( edge.target, target) ;
			   }) == 1 ;
	} ; // 同じ同期中だけ固定元の参照一覧と識別子を借用する
	return one( seeds[0], InfDependencyDirective::INCLUDE, L"msports.inf") &&
		   one( seeds[0], InfDependencyDirective::NEEDS, L"SerialEnumerator.NT") &&
		   one( seeds[2], InfDependencyDirective::INCLUDE, L"msports.inf") &&
		   one( seeds[2], InfDependencyDirective::NEEDS, L"SerialEnumerator.NT.Services") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正確なNeeds先の全作用を検証済み原documentと実copyへ結びます
 * @param[in] result 同runで解決した原graphです
 * @param[in] seeds 元選択DDInstallと実在付随節です
 * @return 全作用成立0、元API/未対応/byte差のHRESULTです
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::verifyNeedsEffects( const InfDependencyNativeResult	&result,
											 const std::span<const std::wstring> seeds)
{
	const bool scopedWifiBus =
		collector_ && collector_->scopedWifiBus ;	// 公式Netの元依存に限る検査です
	const bool serialEnumeratorOnly =
		collector_ && collector_->closure.packages.front()
						  .collectorSerialMedia.has_value() ;	// 自前媒体を保持する収集選択
	std::size_t			 registryRows{} ;						// 全Needsの元累積予算です
	constexpr std::array SD_BUS_COPY_NAMES{
		std::wstring_view{L"sdbus.sys"},
		std::wstring_view{L"dumpsd.sys"}} ;	// この収集型で選択されるWindows提供のSYSです
	std::array<bool, SD_BUS_COPY_NAMES.size()>
		 sdBusCopies{} ;			// 原媒体と配備先を同CATに結んだ位置です
	bool serialCopy{} ;				// 標準Portsの元選択が実際にコピーするSYSです
	bool portsPage{} ;				// 元基本節の単独AddRegが実System32 exportと一致したことを示します
	bool nvmeCopy{} ;				// NVMeの保護コピーが原CATと同一バイトに結び付いたかを記録します
	bool nvmeEmptyCopy{} ;			// 元基本節の空CopyFilesを再読したかを記録します
	bool nvmeEmptyRemove{} ;		// 元基本節の空DelFilesを再読したかを記録します
	bool ahciCopy{} ;				// AHCIの同CATに結ぶ保護コピーの成立を保持する
	bool ahciScore{} ;				// AHCIの元基本節から順位を再読した場合に立てる
	bool winUsbCopy{} ;				// 同梱WinUSBの元SYSと配備先を同じCATへ照合した場合true
	bool winUsbRegistry{} ;			// 同じ元INFで検査済みの機器相対登録先を再読した場合true
	bool auxiliaryCopySeen{} ;		// 補助サービスの一意の元EXEを同じCATへ照合した証拠
	bool eventMessageCopySeen{} ;	// 名前付きイベントの一意の元DLLを同じCATへ照合した証拠
	// 私有診断へ元graphの数値だけを写し、未解決と未検証rootを分離します
	if( diagnostic_) {
		diagnostic_->stage				  = 100U ;
		diagnostic_->referencesResolved	  = result.dependency.plan.referencesResolved ;
		diagnostic_->rootEvidenceVerified = result.dependency.plan.rootEvidenceVerified ;
		diagnostic_->rootSignatureError	  = documents_.front().finding.signatureError ;
		// 未解決辺をすべて数え、一件目の具体理由だけを保持します
		for( const auto &edge : result.dependency.edges) {
			// 成功した参照を未解決へ計上しません
			if( edge.state != InfDependencyState::RESOLVED_PACKAGE &&
			   edge.state != InfDependencyState::RESOLVED_SYSTEM) {
				++diagnostic_->unresolvedReferenceCount ;
				// 一件目の元reasonを後続の別診断で上書きしません
				if( diagnostic_->unresolvedReferenceCount == 1U) {
					diagnostic_->firstReferenceReason = static_cast<std::uint32_t>( edge.reason) ;
				}
			}
		}

		// 同同期で固定した依存証拠の最初の失敗だけを残します
		for( std::size_t index = 1U; index < documents_.size(); ++index) {
			const auto &finding = documents_[index].finding ;	// 元依存の独立診断です
			// 未観測0を成功へ読み替えず、元の非零値だけを保存します
			if( diagnostic_->firstDependencySignatureError == 0U) {
				diagnostic_->firstDependencySignatureError = finding.signatureError ;
			}

			// 署名と由来の失敗を一つの欄へまとめません
			if( diagnostic_->firstDependencyProvenanceError == 0U) {
				diagnostic_->firstDependencyProvenanceError = finding.provenanceError ;
			}
		}
	}

	// 未解決辺や未検査rootを空の効果集合へ変換しません
	if( !result.dependency.plan.referencesResolved || !result.dependency.plan.rootEvidenceVerified) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 元ブートSYSを持つHDCの内容検査は同じパッケージ内の作用に限定する
	if( nativeHdc_ && !result.dependency.edges.empty()) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// Windows同梱への委譲では各節が実際にWindows提供先の作用を必要とすることを確認する
	if( collector_ && !collectorHdc_ && !scopedWifiBus && !serialEnumeratorOnly) {
		// 一つの選択節の成功で他の節のpackage内参照やWindows側の不足を補いません
		for( const auto &seed : seeds) {
			bool systemNeeds{} ;	// この原節がWindowsの作用を一件以上参照する場合だけtrueです
			// 他のdocument・節からの参照を元選択に数えず、同節の全辺を確認します
			for( const auto &edge : result.dependency.edges) {
				// 他の選択節とWindows側の後続参照にはそれぞれの所有元を維持します
				if( edge.sourceIdentity != documents_.front().value.identity ||
				   !equalName( edge.sourceSection, seed)) {
					continue ;
				}

				// パッケージが一意に所有する参照もWindows同梱提供の代用にしません
				if( edge.state != InfDependencyState::RESOLVED_SYSTEM) {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				systemNeeds = systemNeeds || edge.directive == InfDependencyDirective::NEEDS ;
			}

			// Includeだけで実際の選択作用へ到達していない場合は空媒体を許可しません
			if( !systemNeeds) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}
		}
	}

	// 元選択からの設置文脈を全正確なNeeds辺へ結合します
	const auto registryContexts =
		needsRegistryContexts( result, seeds, documents_.front().value.identity) ;

	// SYSTEM全型を同原graphへ二相接続し、CopyFilesは後段の元実検査も必須にします
	const auto typedError = verifyTypedEffects( result, seeds, registryRows) ;
	// 元の不正/不一致又は不足を成功へ補完しません
	if( diagnostic_) {	// 不明/不一致の元値を成功や別scopeへ補完しません
		diagnostic_->verifiedRegistryRowCount = registryRows ;
	}

	// 元の不正/不一致又は不足を成功へ補完しません
	// 元SYSのHDCは型付き検査と元コピーの照合で全選択を検査済み
	if( typedError != 0U || nativeHdc_) {
		return typedError ;
	}

	// 混在媒体の元基本節とServices節だけが同じ同梱文書へ続くことを全辺で確認する
	if( serialEnumeratorOnly && !matchesSerialEnumeratorReferences( result.dependency.edges, seeds,
																  documents_.front().value.identity,
																  msPortsInboxDocument_)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 公式Netのこの接続は、同じ署名済みWindows文書へ実解決した元辺だけを検査します
	if( scopedWifiBus && (typedEffects_.wifiBusFilterDocument == 0U ||
						 std::ranges::any_of( result.dependency.edges, [this]( const auto &edge) {
							 return edge.targetIdentity != typedEffects_.wifiBusFilterDocument ||
									edge.state != InfDependencyState::RESOLVED_SYSTEM ;
						 }))) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 元同梱INFのコピーを元Storeの同名ファイルに結ぶまで他文書の作用へ進みません
	if( typedEffects_.wifiBusFilterDocument != 0U) {
		const auto document = find( typedEffects_.wifiBusFilterDocument) ;	// 同期中の同じ元文書です
		const auto copyError =
			document ? verifyWifiBusStoreCopy( *document)
					 : static_cast<NativeError>( E_UNEXPECTED) ;	// 実コピー境界の結果です
		// 元コピーが成立しない文書を、端末で照合可能な作用へ変換しません
		if( copyError != 0U) {
			// コピーの元診断を文書の検証段階として維持します
			if( diagnostic_) {
				diagnostic_->stage =
					static_cast<std::uint32_t>( SystemInfDiagnosticStage::COPY_REFERENCE) ;
			}

			return copyError ;
		}
	}

	std::vector<InfDependencyVisitedSection> effectSections =
		result.dependency.sections ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
	// 型付きservice/interface等から追加されたcopy節も同じ元copy検査へ送ります
	for( const auto &copy : typedEffects_.copySections) {
		// 元の不正/不一致又は不足を成功へ補完しません
		if( std::ranges::none_of(
			   effectSections,
			   [&]( const auto &old) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				   return old.identity == copy.document && equalName( old.section, copy.name) ;
			   })) {
			effectSections.push_back( {copy.document, copy.name, InfDependencyReadState::PRESENT}) ;
		}
	}

	// Needsで要求された正確な節だけを作用検査します
	for( std::size_t ordinal = 0U; ordinal < effectSections.size(); ++ordinal) {
		const auto &visited = effectSections[ordinal] ;	// 同元graphの正確な節です
		// 同じ仮想Wi-Fiバス文書の全節は専用の全作用検査と同Storeコピーで確認済みです
		if( typedEffects_.wifiBusFilterDocument != 0U &&
		   visited.identity == typedEffects_.wifiBusFilterDocument) {
			continue ;
		}

		const bool needed = std::ranges::any_of( result.dependency.edges, [&]( const auto &edge) {
			return edge.directive == InfDependencyDirective::NEEDS &&
				   edge.targetIdentity == visited.identity &&
				   equalName( edge.target, visited.section) ;
		}) ; // 非選択節を混入しません
		// 混在媒体の元選択側は同じ固定INFで全作用を検査済みで、ここでは同梱側を照合する
		const bool collectorSeed = collector_ && !scopedWifiBus && !serialEnumeratorOnly &&
								   visited.identity == documents_.front().value.identity &&
								   std::ranges::any_of( seeds, [&]( const auto &seed) {
									   return equalName( seed, visited.section) ;
								   }) ; // 収集rootで実選択した節です
		// 補助サービスを持つ元基本節は端末側でもコピーを独立に再照合する
		const bool auxiliarySeed =
			storageFacts_ && storageFacts_->auxiliary &&
			visited.identity == documents_.front().value.identity &&
			equalName( visited.section, storageFacts_->selectedInstallSection) ;
		// 通常の端末baseは元内容検査を使用し、そのほかの到達先は個別に確認する
		if( !collectorSeed && !auxiliarySeed && !needed &&
		   std::ranges::none_of( typedEffects_.copySections, [&]( const auto &copy) {
			   return copy.document == visited.identity && equalName( copy.name, visited.section) ;
		   })) {
			continue ;
		}

		const auto document = find( visited.identity) ;	// 同runの固定documentです
		// 存在・由来・署名を別々に必要とします
		if( document == nullptr || visited.state != InfDependencyReadState::PRESENT ||
		   document->value.signature != InfDependencyEvidence::VERIFIED ||
		   document->value.provenance != InfDependencyEvidence::VERIFIED) {
			// 参照解決後の対象証拠の不足を別段階へ保持します
			if( diagnostic_) {
				diagnostic_->stage = 110U ;
			}

			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		const auto documentIndex =
			// 同所有vectorの位置です
			static_cast<std::size_t>( document - documents_.data()) ;
		const auto fileIndex = document->fileIndex ;	// vector再配置から独立した位置です
		const bool sdBusCopySection =
			// 型付きSDHostの参照先だけです
			visited.identity == sdBusInboxDocument_ ;
		const bool portsCopySection =
			// 標準Portsの元選択です
			visited.identity == msPortsInboxDocument_ ;
		const bool nvmeCopySection =
			// 標準NVMeの選択だけが使う保護コピーです
			visited.identity == storNvmeInboxDocument_ ;
		const bool ahciCopySection =
			// AHCIの元選択の保護コピー
			visited.identity == storAhciInboxDocument_ ;
		const bool winUsbCopySection =
			// 同梱WinUSBの選択コピーだけ
			visited.identity == winUsbInboxDocument_ ;
		const bool protectedInboxCopy = sdBusCopySection || portsCopySection || nvmeCopySection ||
										ahciCopySection ||
										winUsbCopySection ;	// 型付き標準作用の元保護コピーだけです
		const HINF opened = SetupOpenInfFileW( files_[fileIndex]->path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr) ;	// 同固定INFだけです
		// 不正INFを無作用へ変換しません
		if( opened == INVALID_HANDLE_VALUE) {
			return winError( GetLastError()) ;
		}

		InfHandle  inf( opened) ;	// この節の読取handleです
		const LONG count =
			// 全効果行の有限数です
			SetupGetLineCountW( inf.get(), visited.section.c_str()) ;
		// 欠損と過大を切り詰めません
		if( count < 0 || count > 4096L) {
			return E_INVALIDARG ;
		}

		// 全行を既知の有限効果へ分離します
		for( LONG row = 0; row < count; ++row) {
			INFCONTEXT line{} ;	// 同じ明示節の一行です
			// 部分読取後の成功を許可しません
			if( !SetupGetLineByIndexW( inf.get(), visited.section.c_str(), static_cast<DWORD>( row),
									 &line)) {
				return winError( GetLastError()) ;
			}

			std::wstring key ;								// 元directiveです
			auto		 error = field( line, 0U, key) ;	// 同節の元読取診断です
			// 未読keyを空効果にしません
			if( error != 0) {
				return error ;
			}

			// 参照の充足は既存graphが独立に全検査しています
			if( equalName( key, L"Include") || equalName( key, L"Needs")) {
				continue ;
			}

			// NVMe元基本節は、元構造で確認した空リストの存在を署名済みINFから再読します
			if( collectorSeed && storNvmeInboxDocument_ != 0U) {
				const bool	isCopy = equalName( key, L"CopyFiles") ;	// 元のコピーと削除を区別します
				const auto &lists  = *collector_->closure.packages.front()
										 .collectorInboxNvmeLists ;	// 同じ元基本節のリストです
				auto &seen =
					isCopy ? nvmeEmptyCopy : nvmeEmptyRemove ;	// 同じ作用は一回だけ検査します
				std::wstring name ;								// 元署名付きINFから再読したリスト名です
				// 元の空リスト以外に同じ媒体例外を適用しません
				if( (!isCopy && !equalName( key, L"DelFiles")) || seen ||
				   !equalName( visited.section, selectedBase_) || SetupGetFieldCount( &line) != 1U ||
				   field( line, 1U, name) != 0 ||
				   !equalName( name, isCopy ? lists.copy : lists.remove) ||
				   SetupGetLineCountW( inf.get(), name.c_str()) != 0L) {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				seen = true ;
				continue ;
			}

			// AHCI元配布の基本節に属する正確な順位宣言のみを署名済み元文書から再読する
			if( collectorSeed && storAhciInboxDocument_ != 0U) {
				std::wstring score ;	// 先に構造検査した元順位
				// 採用したAHCI選択と異なる節や二重の順位判定を拒否する
				if( ahciScore || !equalName( visited.section, selectedBase_) ||
				   !equalName( key, L"FeatureScore") || SetupGetFieldCount( &line) != 1U ||
				   field( line, 1U, score) != 0 || score != L"80") {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				ahciScore = true ;
				continue ;
			}

			// 元CABの同一ハッシュとHW節に結び、検査済みの単一GUID登録先を再観測する
			if( collectorSeed && winUsbInboxDocument_ != 0U) {
				std::wstring registry ;	// 同じ署名付きHW節に明記された登録先
				// 追加の登録、名前差替え、HW以外の作用には同梱検査の成功を使わない
				if( winUsbRegistry ||
				   !equalName( visited.section, std::wstring( selectedBase_) + L".HW") ||
				   !equalName( key, L"AddReg") || SetupGetFieldCount( &line) != 1U ||
				   field( line, 1U, registry) != 0U ||
				   !equalName(
					   registry,
					   collector_->closure.packages.front().collectorInboxWinUsbRegistrySection)) {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				winUsbRegistry = true ;
				continue ;
			}

			// 元基本節が一意に所有する標準Portsページを独立して処理する
			if( collectorSeed) {
				std::wstring registry ;	// この元基本節の直接AddRegだけです
				// 別の節・複数行・別のスコープをページの成功へ変換しません
				if( msPortsInboxDocument_ == 0U || portsPage ||
				   !equalName( visited.section, selectedBase_) || !equalName( key, L"AddReg") ||
				   SetupGetFieldCount( &line) != 1U || field( line, 1U, registry) != 0 ||
				   !equalName(
					   registry,
					   collector_->closure.packages.front().collectorInboxPropertyPageSection)) {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				error = verifySerialPropertyPage() ;
				// 署名・同一バイト・名前付きexportの失敗を維持します
				if( error != 0) {
					return error ;
				}

				portsPage = true ;
				continue ;
			}

			// 同SYSTEM全作用は二相validatorが全field/関係を既に確認しました
			if( document->value.origin == InfDependencyOrigin::SYSTEM &&
			   std::ranges::any_of( typedEffects_.effects,
								   [&]( const auto &effect) {
									   return effect.source.document == visited.identity &&
											  equalName( effect.source.name, visited.section) ;
								   }) &&
			   !equalName( key, L"CopyFiles")) {
				continue ;
			}

			// 同PACKAGE全行validatorの成立した作用を旧SYSTEM policyへ通し直しません
			if( document->value.origin == InfDependencyOrigin::PACKAGE && storageEffects_ &&
			   !equalName( key, L"CopyFiles") &&
			   std::ranges::any_of( storageEffects_->effects, [&]( const auto &effect) {
				   return effect.original.source.document == visited.identity &&
						  equalName( effect.original.source.name, visited.section) &&
						  effect.original.row.ordinal == static_cast<std::uint32_t>( row) ;
			   })) {
				continue ;
			}

			// 元選択文脈のHKR設定だけを全行検査し、後続directiveも省略しません
			if( equalName( key, L"AddReg")) {
				// 読取・root・flag・型の拒否を元段階へ保持します
				if( diagnostic_) {
					diagnostic_->stage = 121U ;
				}

				const NeedsSystemContext system{
					files_[fileIndex]->path, [this]() {
						return verifyStreamingComponents() ;
					}} ; // 元SYSTEM documentと同NativeLoaderの固定helperだけを借用します
				const bool systemAllowed = document->value.origin == InfDependencyOrigin::SYSTEM &&
										   document->signerScore == SIGNERSCORE_INBOX &&
										   document->storeIndex != MAX_FILES &&
										   // 同正規DDInstall文脈だけです
										   registryContexts[ordinal] == 1U ;
				error = verifyNeedsAddReg( inf.get(), line, registryContexts[ordinal], registryRows,
										  diagnostic_, systemAllowed ? &system : nullptr) ;
				// 一部の正常行で未対応行や文脈不足を隠しません
				if( error != 0U) {
					return error ;
				}

				// 完了した全参照行の件数だけを診断へ保持します
				if( diagnostic_) {
					diagnostic_->verifiedRegistryRowCount = registryRows ;
				}

				continue ;
			}

			// 未解釈service等を無作用へ救済しません
			if( !equalName( key, L"CopyFiles")) {
				// 未対応効果の名称そのものをlogへ出しません
				if( diagnostic_) {
					diagnostic_->stage = equalName( key, L"AddReg")		 ? 121U
										 : equalName( key, L"AddService") ? 122U
																		 : 123U ;
				}

				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			const DWORD fields = SetupGetFieldCount( &line) ;	// 有限copy参照数です
			// AddReg成功の位置を後続copy失敗の起点へ持ち越しません
			if( diagnostic_) {
				diagnostic_->stage = 124U ;
			}

			// 空copyと過大を未検査のまま認定しません
			if( fields == 0U || fields > 64U) {
				return E_INVALIDARG ;
			}

			// 各copy listの全対象を元sourceとCATへ結合します
			for( DWORD item = 1U; item <= fields; ++item) {
				std::wstring list ;	// 元@fileまたは正確なcopy節です
				error = field( line, item, list) ;
				// 名前欠損を省略しません
				if( error != 0 || list.empty()) {
					return error != 0 ? error : static_cast<NativeError>( E_INVALIDARG) ;
				}

				// 同じ元選択のコピー情報に限定し、直接コピーと名前付き節を別々に照合する
				const auto *auxiliaryClaim =
					storageFacts_ && storageFacts_->auxiliary && documentIndex == 0U &&
							documents_[documentIndex].value.origin ==
								InfDependencyOrigin::PACKAGE &&
							equalName( visited.section, storageFacts_->selectedInstallSection)
						? &storageFacts_->auxiliary->copy
						: nullptr ;
				const bool directAuxiliary = auxiliaryClaim && list.front() == L'@' &&
											 auxiliaryClaim->dirid == 13 &&
											 equalName( visited.section, auxiliaryClaim->section) &&
											 auxiliaryClaim->fields.size() == 1U &&
											 // 元DDInstallの直接行
											 list == auxiliaryClaim->fields.front() ;
				const auto *auxiliaryCopy =
					(directAuxiliary ||
					 (auxiliaryClaim && list.front() != L'@' && auxiliaryClaim->dirid == 11 &&
					  equalName( list, auxiliaryClaim->section)))
						? auxiliaryClaim
						: nullptr ;	// 元閉包に照合する一つの補助コピー
				const auto *eventCopy =
					auxiliaryClaim && storageFacts_->auxiliary->eventMessageCopy &&
							equalName( list, storageFacts_->auxiliary->eventMessageCopy->section)
						? &*storageFacts_->auxiliary->eventMessageCopy
						: nullptr ;	// 同じ元基本節のメッセージDLL
				// DLLのコピー先を同元INFの明示宛先から再確認する
				if( eventCopy && (eventMessageCopySeen || eventCopy->dirid != 11 ||
								 !hasExplicitStorageEventCopyDestination( inf.get(), list))) {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				const auto *copyClaim =
					eventCopy ? eventCopy : auxiliaryCopy ;	// 元行と実バイトを照合する証拠
				std::vector<std::wstring> names ;			// 最大4096の全非rename copyです
				// 直接copyでは単一basenameだけを保持します
				if( list.front() == L'@') {
					// 標準コピーは各原行の保護フラグを確認できる名前付き節を使います
					if( protectedInboxCopy ||
					   (directAuxiliary &&
						(auxiliaryCopySeen || fields != 1U ||
						 auxiliaryCopy->ordinal != static_cast<std::uint32_t>( row)))) {
						return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
					}

					names.push_back( list.substr( 1U)) ;
				} else {
					const auto security = list + L".security" ;	// 未確認ACL作用を別に拒否します
					SetLastError( ERROR_SUCCESS) ;
					const LONG securityRows =
						// 空節も作用です
						SetupGetLineCountW( inf.get(), security.c_str()) ;
					const DWORD securityError = GetLastError() ;	// 元API直後だけを保持します
					// CopyFilesのsecurity作用を通常copyへ縮約しません
					if( securityRows >= 0L || (securityError != ERROR_SUCCESS &&
											  securityError != ERROR_SECTION_NOT_FOUND)) {
						return securityRows >= 0L ? HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)
												  : winError( securityError) ;
					}

					const LONG rows =
						// 正確な元copy節です
						SetupGetLineCountW( inf.get(), list.c_str()) ;
					// 欠損・空list・過大を成功へ変換しません
					if( rows <= 0 || rows > 4096L) {
						return E_INVALIDARG ;
					}

					// 補助EXEのコピーは同じ基本節から到達する一行を一度だけ照合する
					if( auxiliaryCopy &&
					   (auxiliaryCopySeen || rows != 1 || auxiliaryCopy->ordinal != 0U ||
						auxiliaryCopy->fields.size() != 4U)) {
						return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
					}

					// 元DLLコピーには改名や任意の追加欄を認めない
					if( eventCopy &&
					   (rows != 1 || eventCopy->ordinal != 0U || eventCopy->fields.size() != 1U)) {
						return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
					}

					// rename/tmp/flagsを全行で確認します
					for( LONG position = 0; position < rows; ++position) {
						INFCONTEXT copy{} ;	// 元copy data行です
						// 一行欠損でも部分成功を返しません
						if( !SetupGetLineByIndexW( inf.get(), list.c_str(),
												 static_cast<DWORD>( position), &copy)) {
							return winError( GetLastError()) ;
						}

						const DWORD values = SetupGetFieldCount( &copy) ;	// 最大四fieldです
						// 未採用の余分なcopy effectを切り捨てません
						if( values == 0U || values > 4U) {
							return E_INVALIDARG ;
						}

						int sdBusFlags{} ;	// 保護フラグを含む元の整数を完全に読みます
						// 元標準コピーの単独Windows保護フラグを確認します
						if( protectedInboxCopy &&
						   (values != 4U || !SetupGetIntField( &copy, 4U, &sdBusFlags) ||
							sdBusFlags != COPYFLG_PROTECTED_WINDOWS_DRIVER_FILE)) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						std::wstring name ;	// 宛先basenameです
						error = field( copy, 1U, name) ;
						// 読取失敗を空fileへ変換しません
						if( error != 0) {
							return error ;
						}

						// 型付き元行と現在読んだコピーのファイル名・欄数が一致することを要求する
						if( copyClaim && (values != copyClaim->fields.size() ||
										 name != copyClaim->fields.front())) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						const bool systemProtected =
							documents_[documentIndex].value.origin == InfDependencyOrigin::SYSTEM &&
							documents_[documentIndex].signerScore == SIGNERSCORE_INBOX &&
							documents_[documentIndex].storeIndex !=
								MAX_FILES ;	// 同原INBOX/Storeだけです

						// 全任意fieldも有限な原値へ固定します
						for( DWORD value = 2U; value <= values; ++value) {
							std::wstring option ;	// rename/tmp/flagsの原値です
							error = field( copy, value, option) ;
							int		   copyFlags{} ;	// 新たに解釈する単独のSDK保護flagです
							const bool protectedFlag =
								error == 0U && value == 4U && !option.empty() && option != L"0" &&
								systemProtected && SetupGetIntField( &copy, 4U, &copyFlags) &&
								copyFlags ==
									COPYFLG_PROTECTED_WINDOWS_DRIVER_FILE ;	// 他bit/comboへ広げません
							// 確認済みの補助EXEの元行だけ、使用中ファイルの置換をWindowsへ委ねる
							const bool deferredFlag = error == 0U && value == 4U && auxiliaryCopy &&
													  SetupGetIntField( &copy, 4U, &copyFlags) &&
													  copyFlags == COPYFLG_FORCE_FILE_IN_USE ;
							// 既存のコピー条件を維持し、補助サービスの全欄も元証拠に照合する
							if( error != 0 ||
							   (auxiliaryCopy && option != auxiliaryCopy->fields[value - 1U]) ||
							   (serialEnumeratorOnly && portsCopySection && value < 4U &&
								!option.empty()) ||
							   (!option.empty() &&
								!((value == 2U && equalName( option, name)) ||
								  (value == 4U &&
								   (option == L"0" || protectedFlag || deferredFlag))))) {
								return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
							}
						}

						names.push_back( std::move( name)) ;
					}
				}

				// 各payloadの同byteと同CATを確認します
				for( const auto &name : names) {
					// 相対pathや空名をbasenameへ正規化しません
					if( !validInfDependencyPath( name, false) ||
					   name.find( L'\\') != std::wstring::npos) {
						return E_INVALIDARG ;
					}

					std::wstring source ;	// 同HINF/source IDの完全file subdirです
					std::wstring media ;	// 同HINF/source IDの完全媒体位置です
					error = readOfficialInfSourceDirectories( inf.get(), name, source, media) ;
					// source欠損・曖昧・不安全をroot fallbackで補完しません
					if( error != 0 || (!source.empty() && !validInfDependencyPath( source, false)) ||
					   (!media.empty() && !validInfDependencyPath( media, false))) {
						return error != 0 ? error : static_cast<NativeError>( E_INVALIDARG) ;
					}

					const auto &fixed  = documents_[documentIndex] ;	// 安定した同documentです
					const bool	system = fixed.value.origin ==
										InfDependencyOrigin::SYSTEM ;	// 同観測で確認した由来です
					// SYSTEM由来には同byte対応Storeが必須です
					if( system && fixed.storeIndex == MAX_FILES) {
						return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
					}

					const auto original = files_[system ? fixed.storeIndex : fixed.fileIndex]
											  ->path ;	// 同元source起点です
					std::wstring path =
						// 元INF親だけです
						original.substr( 0U, original.find_last_of( L'\\') + 1U) ;
					// 完全取得した両directoryだけを結合します
					if( !media.empty()) {
						path += media + L"\\" ;
					}

					// 同じsource subdirを保持します
					if( !source.empty()) {
						path += source + L"\\" ;
					}

					path += name ;
					std::size_t payload{} ;	// 固定した実sourceです
					error = pin( path, MAX_TOTAL_BYTES, payload) ;
					// 実sourceがなければ導入効果を認定しません
					if( error != 0) {
						return error ;
					}

					std::vector<std::wstring> members{path} ;	// 同CATで検査する実memberです
					std::size_t				  sdBusCopyIndex =
						// SDHostの元コピー以外は記録しません
						sdBusCopies.size() ;
					// PACKAGEは元保護閉包の全byte検査へ結合します
					if( !system) {
						const auto relative = std::wstring_view( path).substr(
							// 同保護root相対位置です
							packageRoot_.size()) ;
						const auto expected = dependencyEntry(
							effectClosure_->entries, relative) ;	// 元閉包にないpayloadを足しません
						// 元size/hashの両方を一致させます
						if( expected == nullptr || expected->sha256 != files_[payload]->sha256 ||
						   expected->uncompressedSize != files_[payload]->bytes) {
							return TRUST_E_BAD_DIGEST ;
						}

						// 補助EXEまたはイベントDLLを元の相対位置と完全なファイル証拠に結ぶ
						if( copyClaim && (!equalName( relative, copyClaim->source) ||
										 copyClaim->sha256 != expected->sha256 ||
										 copyClaim->bytes != expected->uncompressedSize)) {
							return TRUST_E_BAD_DIGEST ;
						}
					} else {
						INFCONTEXT destination{} ;	// 同INFの元宛先定義です
						const auto destinationKey = list.front() == L'@'
														? L"DefaultDestDir"
														: list.c_str() ;	// 元copyの宛先keyです
						const bool explicitDestination =
							SetupFindFirstLineW( inf.get(), L"DestinationDirs", destinationKey,
												&destination) != FALSE ;	// 元リスト固有の宛先です
						// 明示list宛先、次に同INF既定だけを使います
						if( !explicitDestination &&
						   (protectedInboxCopy ||
							!SetupFindFirstLineW( inf.get(), L"DestinationDirs", L"DefaultDestDir",
												 &destination))) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						INFCONTEXT duplicate{} ;	// 元ファイルの設置先を別の同名行で上書きさせません
						// 元標準リストには一意の明示宛先が必要です
						if( protectedInboxCopy &&
						   SetupFindNextMatchLineW( &destination, destinationKey, &duplicate)) {
							return HRESULT_FROM_WIN32( ERROR_DUP_NAME) ;
						}

						int dirId{} ;	// Windowsの明示DIRIDです
						// 有限なWindows/System32とdrivers以外は未確認です
						if( !SetupGetIntField( &destination, 1U, &dirId) ||
						   (dirId != 11 && dirId != 12) || SetupGetFieldCount( &destination) > 2U) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						std::wstring subdir ;	// 任意の同INF宛先subdirです
						// subdirは安全な相対値だけを使用します
						if( SetupGetFieldCount( &destination) == 2U) {
							error = field( destination, 2U, subdir) ;
							// 取得失敗と境界外を止めます
							if( error != 0 ||
							   (!subdir.empty() && !validInfDependencyPath( subdir, false))) {
								return error != 0 ? error : static_cast<NativeError>( E_INVALIDARG) ;
							}
						}

						std::wstring installed =
							windows_ + (dirId == 12 ? L"\\System32\\drivers\\"
													: L"\\System32\\") ;	// 実提供先です
						// 同じ明示宛先を保持します
						if( !subdir.empty()) {
							installed += subdir + L"\\" ;
						}

						installed += name ;
						// 元選択で使う一件の保護コピーだけを、drivers直下の同一ファイルに結ぶ
						if( portsCopySection &&
						   (serialCopy ||
							!equalName( name,
									   serialEnumeratorOnly ? L"serenum.sys" : L"serial.sys") ||
							(serialEnumeratorOnly &&
							 !equalName( list, L"SerialEnumerator.NT.Copy")) ||
							dirId != 12 || !subdir.empty())) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						// NVMeの元選択ではstornvme.sysだけを正規drivers直下へ結びます
						if( nvmeCopySection && (nvmeCopy || !equalName( name, L"stornvme.sys") ||
											   dirId != 12 || !subdir.empty())) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						// AHCIは正規drivers直下への一つの標準SYSを同CATへ結ぶ
						if( ahciCopySection && (ahciCopy || !equalName( name, L"storahci.sys") ||
											   !equalName( list, L"storahci_copyfiles") ||
											   dirId != 12 || !subdir.empty())) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						// 同梱WinUSBの唯一の保護コピーを元リストとdrivers直下へ限定する
						if( winUsbCopySection && (winUsbCopy || !equalName( name, L"winusb.sys") ||
												 !equalName( list, L"WINUSB.CopyFiles") ||
												 dirId != 12 || !subdir.empty())) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						// SDHostでは同じ原INFの二つのSYSを正規のdrivers直下に限定する
						if( sdBusCopySection) {
							const auto expected =
								std::ranges::find_if( SD_BUS_COPY_NAMES, [&]( const auto target) {
									return equalName( target, name) ;
								}) ; // 同じ元名です
							// 追加のSYS、別ディレクトリ、重複行を完全な照合として扱いません
							if( expected == SD_BUS_COPY_NAMES.end() || dirId != 12 ||
							   !subdir.empty()) {
								return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
							}

							sdBusCopyIndex =
								static_cast<std::size_t>( expected - SD_BUS_COPY_NAMES.begin()) ;
							// 設置先が同じになる重複コピーも別の元行として拒否します
							if( sdBusCopies[sdBusCopyIndex]) {
								return HRESULT_FROM_WIN32( ERROR_DUP_NAME) ;
							}
						}

						std::size_t existing{} ;	// Windows既存fileです。コピーしません
						error = pin( installed, MAX_TOTAL_BYTES, existing) ;
						// 同byteの既提供が確認できなければSYSTEM効果未充足です
						if( error != 0 || files_[payload]->sha256 != files_[existing]->sha256 ||
						   files_[payload]->bytes != files_[existing]->bytes) {
							return error != 0 ? error
											  : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
						}

						members.push_back( installed) ;
					}

					error = nativeCatalogSignature(
						files_[documents_[documentIndex].catalogIndex]->path, members) ;
					// INF署名だけでpayload署名を合格にしません
					if( error != 0) {
						return error ;
					}

					auxiliaryCopySeen	 = auxiliaryCopySeen || auxiliaryCopy != nullptr ;
					eventMessageCopySeen = eventMessageCopySeen || eventCopy != nullptr ;

					// 元媒体と同じ配備済みバイトの両方が同CATに属した場合だけ記録します
					if( sdBusCopyIndex < sdBusCopies.size()) {
						sdBusCopies[sdBusCopyIndex] = true ;
					}

					serialCopy = serialCopy || portsCopySection ;
					nvmeCopy   = nvmeCopy || nvmeCopySection ;
					ahciCopy   = ahciCopy || ahciCopySection ;
					winUsbCopy = winUsbCopy || winUsbCopySection ;

					// 収集時に確認した実sourceと配備済み同byteも終了時に元CATへ再照合します
					if( collector_) {
						auto &checked =
							documents_[documentIndex].catalogMembers ;	// このdocumentの元CAT用です
						// 同じfileの複数用途で再確認集合を水増ししません
						for( const auto &member : members) {
							// 同じ元CATへ初めて照合した完全位置だけを保持します
							if( std::ranges::none_of( checked, [&]( const auto &prior) {
								   return equalName( prior, member) ;
							   })) {
								checked.push_back( member) ;
							}
						}
					}

					// 元の不正/不一致又は不足を成功へ補完しません
					if( list.front() != L'@') {	// 不明/不一致の元値を成功や別scopeへ補完しません
						// 元の不正/不一致又は不足を成功へ補完しません
						if( const auto observer = inf_dependency_native_detail::
							   // 不明/不一致の元値を成功や別scopeへ補完しません
						   activeApi() ;
						   observer && observer->observedSection) {
							observer->observedSection( files_[fileIndex]->path, list) ;
						}
					}
				}
			}
		}
	}

	// 二つの元コピーと同じ配備済みバイトを確認した場合だけ、SDHostの作用を成功とします
	if( sdBusInboxDocument_ != 0U &&
	   !std::ranges::all_of( sdBusCopies, []( bool checked) { return checked ; })) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 混在媒体ではSerenumの実コピーとSCM、従来の元選択ではページと実コピーを確かめる
	if( msPortsInboxDocument_ != 0U &&
	   (!serialCopy || (serialEnumeratorOnly ? typedEffects_.services.size() != 1U : !portsPage))) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// NVMeは二つの空リストと標準SYSの保護コピーがそろった場合だけ確定します
	if( storNvmeInboxDocument_ != 0U && (!nvmeEmptyCopy || !nvmeEmptyRemove || !nvmeCopy)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// AHCIの順位と同じ元CATの保護コピーを両方検査した場合だけ確定する
	if( storAhciInboxDocument_ != 0U && (!ahciScore || !ahciCopy)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 元HW登録とWindows側の唯一のコピーをともに確認した場合だけ成立する
	if( winUsbInboxDocument_ != 0U && (!winUsbRegistry || !winUsbCopy)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 補助サービス宣言は対応する原EXEの全照合と一緒に成立させる
	if( storageFacts_ && storageFacts_->auxiliary && !auxiliaryCopySeen) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// イベントDLLを使う場合は元CATを再確認してから同じ端末の共有先を読む
	if( storageFacts_ && storageFacts_->auxiliary && storageFacts_->auxiliary->eventMessageCopy) {
		// 元CATか元作用のいずれかが不成立なら現用照会を始めない
		if( !eventMessageCopySeen || !storageEffects_) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		std::uint32_t stage{} ;	// 元の現用・共有変更の判定を保持する固定番号
		// 選択した自動起動の作用と現在の共有先を確認した結果
		auto		  hostError =
			verifyStorageAutomaticHost( *storageEffects_, documents_.front().value.identity, stage) ;
		// 同じ現用と配置が成立した場合だけ、起動グループも同じ選択へ固定する
		if( hostError == 0U) {
			hostError = readStorageBootLoadOrder( storageEffects_->loadOrder.emplace()) ;
			stage	  = hostError == 0U ? 0U : 14011U ;
		}

		// 最初の読取りまたは所有の診断を終端の署名照合まで保持する
		if( diagnostic_ && hostError != 0U) {
			diagnostic_->stage = stage ;
		}

		return hostError ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief rootを固定し共通核と全根拠の再確認へ接続する
 * @param[in] rootIndex 開始member位置
 * @param[in] seeds 明示節群
 * @param[out] result 全成功時だけ保持する非実行結果
 * @return 完了0、最初のHRESULT
 */
//------------------------------------------------------------------------------
NativeError NativeLoader::run( std::size_t rootIndex, std::span<const std::wstring> seeds,
							  InfDependencyNativeResult &result)
{
	// 元全byte/metadata/CATの成功をenumだけから作りません
	if( content_ != nullptr) {
		const auto error = recheckCommonContent( *content_) ;	// 元内容の再検査結果です
		// 独立した元検査が失敗した場合はnative graphを作りません
		if( error != 0) {
			return error ;
		}
	}

	// 私有入口だけが供給する生存issuerと全固定集合を、native使用前に再確認する
	if( binding_ != nullptr) {
		const auto error =
			// 独立した公式由来確認
			binding_->verify( *session_, *archiveWorkspace_) ;
		// 署名や節の成功で失効した取得根拠を救済しない
		if( error != 0) {
			return error ;
		}
	}

	const auto directoryError = nativeWindowsDirectory( windows_) ;	// 実OS起点の独立診断
	// 環境変数から別のWindows領域を指定させない
	if( directoryError != 0) {
		return directoryError ;
	}

	const std::wstring first =
		// 初期化済み領域の確認
		workspace_.path( members_.front().relativePath) ;
	// 過短pathと不正なWindows起点を採用しない
	if( first.size() <= members_.front().relativePath.size() ||
	   !validInfDependencyPath( windows_, true)) {
		return E_INVALIDARG ;
	}

	packageRoot_ = first.substr( 0U, first.size() - members_.front().relativePath.size()) ;
	// 収集原閉包の全fileを元size/hashで固定し、CAT・graphと終了再確認までhandleを保持します
	if( collector_) {
		// 原INF、CAT、同原INFの参照sourceを既存の累積byte/file予算内で固定します
		for( const auto &entry : collector_->closure.entries) {
			std::size_t fixed{} ;	// 終了時の同一性・実hash再検査に使う位置です
			const auto	error = pin( workspace_.path( entry.relativePath), MAX_TOTAL_BYTES,
									fixed) ;	// 原fileの固定結果です
			// 署名済みの同名fileでも、元アーカイブから抽出したbyteと一致する必要があります
			if( error != 0U || files_[fixed]->bytes != entry.uncompressedSize ||
			   files_[fixed]->sha256 != entry.sha256) {
				return error != 0U ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}
		}
	}

	InfDependencyDocument root ;	// 固定済み開始snapshot
	// 最初の失敗を保持して終了まで上書きしない診断値
	NativeError			  error =
		observe( workspace_.path( members_[rootIndex].relativePath), &members_[rootIndex], root) ;
	// Root固定失敗ではcallbackを作成しない
	if( error != 0) {
		return error ;
	}

	// 収集原本は、選択rootの後にすべてのpackage所有INFと固有のCAT・memberを照合します
	if( collector_) {
		// 閉包の各importも独立に元署名を確認し、異なるCATの元成功を継承しません
		for( std::size_t index = 0U; index < members_.size(); ++index) {
			// rootの署名と元fileは直前に固定済みです
			if( index != rootIndex) {
				InfDependencyDocument
					imported ;	// graphで到達した場合は同じ固定documentを再利用します
				error = observe( workspace_.path( members_[index].relativePath), &members_[index],
								imported) ;
				// 未検査のimportを含む閉包を収集成功へ送らないよう元HRESULTを返します
				if( error != 0U) {
					return error ;
				}
			}
		}
	}

	InfDependencyOperations operations ;	// この同期loaderだけを借用するcallback
	operations.lookup = [this]( const auto &source, auto target, auto &lookupResult) {
		// Worker同期runだけでthisを借用する
		return lookup( source, target, lookupResult) ;
	} ;
	operations.readSection = [this]( const auto &document, auto name, auto &sectionResult) {
		// 同じ固定byteにだけ明示節を照会する
		return section( document, name, sectionResult) ;
	} ;
	operations.recheck = [this]( const auto &document) {
		// Snapshotの差替えとOS差は終了前に全体拒否する
		const auto stored = find( document.identity) ;	// 固定rootまたは発見候補
		// 未知identityと証拠差替えの再確認を拒否する
		if( stored == nullptr || stored->value.sha256 != document.sha256 ||
		   stored->value.byteCount != document.byteCount ||
		   !sameContext( stored->value.context, document.context) ||
		   stored->value.origin != document.origin ||
		   stored->value.signature != document.signature ||
		   stored->value.provenance != document.provenance ||
		   stored->value.byteBinding != document.byteBinding) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		return recheckFile( stored->fileIndex) ;
	} ;
	InfDependencyNativeResult	 observed ;	// 全native再確認後にだけ公開する結果
	InfDependencySelectedContext selectedContext{
		root, selectedBase_, {}} ;								// 観測済みrootの原証拠へ結合します
	const InfDependencySelectedContext *selected = nullptr ;	// 旧入口の共有範囲は拡張しません
	// 署名閉包と既確定基本がそろうときだけ、同じ実在seedを明示付属へ渡します
	if( effectClosure_ != nullptr && !selectedBase_.empty()) {
		// 順序や部分文字列から親を推定せず、明示された基本を除く実在seedだけです
		for( const auto &seed : seeds) {
			// 同じ基本を付属へ重複登録しません
			if( !equalName( seed, selectedBase_)) {
				selectedContext.companionSections.push_back( seed) ;
			}
		}

		selected = &selectedContext ;
	}

	error = resolveInfDependencies( root, seeds, operations, observed.dependency, selected) ;
	// 共通核の拒否・容量・例外の部分graphを返さない
	if( error != 0) {
		return error ;
	}

	error = observeFileUses( observed) ;
	// file用途の途中読取・容量失敗で部分graphを成功へ変換しない
	if( error != 0) {
		return error ;
	}

	const bool scopedBluetoothUsb =
		collector_ &&
		collector_->scopedBluetoothUsb ;	// 同梱の保護コピーと残りの作用を個別に検査する形
	// 収集内容と端末の元選択は到達作用を独立検査し、従来の観測入口は従来どおりの結果を返します
	if( effectClosure_ != nullptr) {
		error = scopedBluetoothUsb ? verifyBluetoothUsbActions( observed, seeds)
								   : verifyNeedsEffects( observed, seeds) ;
		// 辺解決だけで未検査の効果を成功にしません
		if( error != 0) {
			return error ;
		}
	}

	// INF以外の署名CAT・対応Storeも終了時に全て再確認する
	for( std::size_t index = 0U; index < files_.size(); ++index) {
		error = recheckFile( index) ;
		// 全根拠の一つでもbyte差があれば全体拒否する
		if( error != 0) {
			return error ;
		}
	}

	// 現在OSへの対応位置と完全scoreを再確認し、別根拠へ転用しない
	for( const auto &document : documents_) {
		error = recheckTrust( document) ;
		// 署名の失効とCAT／完全score差を元の成功値で隠さない
		if( error != 0) {
			return error ;
		}

		// 由来未検査に対応Store根拠を捏造しない
		if( document.storeIndex != MAX_FILES) {
			std::wstring current ;	// 対応位置の終了観測
			error = nativeDriverStore( files_[document.fileIndex]->path, current) ;
			// 対応変更・照会失敗を旧根拠で補完しない
			if( error != 0) {
				return error ;
			}

			// 対応位置の変更や不正終端を止める
			if( !validInfDependencyPath( current, true) ||
			   !equalName( current, files_[document.storeIndex]->path)) {
				return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
			}
		}

		observed.findings.push_back( document.finding) ;
	}

	InfDependencyContext current ;	// 終了時のOS文脈
	error = currentContext( context_.observationId, current) ;
	// 監視PCの別OS・別世代を旧文脈へ戻さない
	if( error != 0 || !sameContext( context_, current)) {
		return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
	}

	// OS・署名・参照の終了再確認後も同じ取得根拠を再確認する
	if( binding_ != nullptr) {
		error = binding_->verify( *session_, *archiveWorkspace_) ;
		// 途中でissuerが失効した場合は確認済みgraphを返さない
		if( error != 0) {
			return error ;
		}
	}

	observed.fixedFileCount = files_.size() ;
	// 全SYSTEM根拠の再確認後にも元保護閉包を再検査します
	if( content_ != nullptr) {
		error = recheckCommonContent( *content_) ;
		// 途中改変を開始時の成功で隠しません
		if( error != 0) {
			return error ;
		}
	}

	// helperの元権限/署名形式/同CATも終了時に独立再検証します
	for( std::size_t systemIndex = 0U; systemIndex < systemFiles_.size(); ++systemIndex) {
		const auto path =
			systemFiles_[systemIndex].filePath ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
		error = verifySystemFile( path, true) ;
		// 新しい成功tupleへのすり替えを許可しません
		if( error != 0U) {
			return error ;
		}
	}

	observed.fixedByteCount = totalBytes_ ;
	// 全元fileを私有計画の再検証へ結び、件数だけを充足証拠にしません
	for( const auto &file : files_) {
		observed.fixedFiles.push_back( {file->path, file->sha256, file->bytes}) ;
	}

	// 必要だった既存serviceも終了時に同config/SDを再観測します
	for( const auto &original : typedEffects_.services) {
		SystemServiceEvidence fresh ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		const auto			  read = [&]() -> NativeError {
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
			// 元の不正/不一致又は不足を成功へ補完しません
			if( testApi) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				return testApi->systemService ? testApi->systemService( original.name, fresh)
											  : E_NOTIMPL ;
			}
#endif
			// 元の不正/不一致又は不足を成功へ補完しません
			if( const auto api = inf_dependency_native_detail::
				   activeApi()) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				return api->systemService ? api->systemService( original.name, fresh) : E_NOTIMPL ;
			}

			// 元の仮想Wi-Fiバスに必要なSCM表示・説明と元登録値を同じ方式で再読します
			if( typedEffects_.wifiBusFilterDocument != 0U && equalName( original.name, L"vwifibus")) {
				return readWifiBusServiceEvidence( fresh) ;
			}

			return readSystemServiceEvidence( original.name, fresh) ;
		} ; // 同元serviceだけのreadonly再観測です
		error = read() ;
		// 元の不正/不一致又は不足を成功へ補完しません
		if( error != 0U || validateSystemServiceEvidence( fresh) != 0U ||
		   original != fresh) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	observed.systemFiles = systemFiles_ ;
	// 現serviceの明示不存在と全config/SDも終了時に再観測します
	if( storageEffects_) {
		// 署名・参照の終端照合後も、同じ端末の全作用とETW観測が変わっていないことを確認する
		if( storageEffects_->automaticHost) {
			StorageAutomaticHostSnapshot fresh ;	// 私有計画へ渡す直前の現在端末
			std::uint32_t				 stage{} ;	// 元読取りの固定診断
			error = readStorageAutomaticHost( *storageEffects_, root.identity, fresh, stage) ;
			// 途中変化や読取りの元失敗では古い端末観測を返さない
			if( error != 0U || fresh != *storageEffects_->automaticHost) {
				// 元診断があれば保持し、安定性の差は再観測の固定診断を使う
				if( diagnostic_) {
					diagnostic_->stage = stage != 0U ? stage : 14025U ;
				}

				return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
			}
		}

		// 同期中の設定または存在の変化を初回に観測した証拠へ上書きしない
		if( storageEffects_->auxiliaryHost) {
			StorageAuxiliaryHostSnapshot fresh ;	// 同じ端末構成の独立した再観測
			error = readStorageAuxiliaryHostSnapshot( storageEffects_->service, fresh) ;
			// 同じ元サービスとファイル・イベントの全状態を確認する
			if( error != 0U || fresh != *storageEffects_->auxiliaryHost) {
				return error != 0U ? error
								   : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
			}
		}

		// 初回に確認した起動グループが終端まで同じ位置にあることを確認する
		if( storageEffects_->loadOrder) {
			// 元の起動順との比較に使う終端の観測
			StorageLoadOrder observedOrder ;
			error = readStorageBootLoadOrder( observedOrder) ;
			// 順序が変わった場合は元観測を引き継がない
			if( error != 0U || observedOrder != *storageEffects_->loadOrder) {
				return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
			}
		}

		// 必要なexact serviceだけを同backendで終端再観測します
		for( const auto &original : storageEffects_->services) {
			// 自動起動型では保護付きのSYS・名前・SCMを上の全観測で照合済み
			if( storageEffects_->automaticHost) {
				break ;
			}

			// 同元入力から独立に再構築する比較値です
			SystemServiceEvidence fresh ;
			std::wstring		  binarySha256 ;	// 元HDCサービスの現在SYSとの比較値
			error = readStorageService( original.name, fresh, nativeHdc_ ? &binarySha256 : nullptr) ;
			// 正式不存在を照会失敗と分ける元HRESULTです
			const auto absent =
				static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST)) ;
			// 正式不存在/全現configの途中変化を元観測で補完しません
			if( original.evidence ? error != 0U || fresh != *original.evidence ||
									   binarySha256 != storageEffects_->currentHdcBinarySha256
								 : error != absent) {
				return error != 0U && error != absent
						   ? error
						   : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
			}
		}

		observed.storageEffects = storageEffects_ ;
	}

	observed.systemEffects				 = typedEffects_.effects ;
	observed.systemServices				 = typedEffects_.services ;
	observed.replacesWifiBusUpperFilters = typedEffects_.wifiBusFilterDocument != 0U ;
	observed.delayedRegistration = delayedRegistration_ || typedEffects_.delayedRegistration ;
	// 非公開fixtureの資格観測は全検査後だけで、許可入力や製品fallbackを持ちません
	if( const auto api = inf_dependency_native_detail::activeApi() ; api && api->observedResult) {
		api->observedResult( observed) ;
	}

	result = std::move( observed) ;
	return 0 ;
}

} // namespace

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 旧経路と封印私有経路で共用する有限native入口
 * @param[in] workspace 閉じたpackage所有領域
 * @param[in] members 全INFの固定一覧
 * @param[in] rootIndex 開始INF位置
 * @param[in] seeds 明示節群
 * @param[in] observationId 非零の観測世代
 * @param[out] result 全成功時だけのsnapshot
 * @param[in] binding 封印所有者。旧経路ではnullptr
 * @param[in] session 生存issuer。bindingと同時にだけ指定する
 * @param[in] archiveWorkspace 元領域。bindingと同時にだけ指定する
 * @param[in] collector 元収集の署名閉包と全一覧。収集専用入口以外ではnull
 * @return 観測完了0、不正入力・path・byte・OS・例外のHRESULT
 */
//------------------------------------------------------------------------------
NativeError inspectNativeInfDependenciesImpl(
	const OfficialDownloadWorkspace &workspace, std::span<const InfDependencyPackageMember> members,
	std::size_t rootIndex, std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result, const OfficialInfArchiveBinding *binding,
	const OfficialAcquisitionSession *session, const OfficialDownloadWorkspace *archiveWorkspace,
	const CollectorDependencySource *collector = nullptr)
{
	result = {} ;
	try {
		// 未初期化・過大・未知rootや観測IDから結果を作らない
		if( members.empty() || members.size() > 64U || rootIndex >= members.size() ||
		   observationId == 0U || (binding == nullptr) != (session == nullptr) ||
		   (binding == nullptr) != (archiveWorkspace == nullptr)) {
			return E_INVALIDARG ;
		}

		// 全memberの閉じた一覧と原hash／sizeを処理開始前に検査する
		for( std::size_t index = 0U; index < members.size(); ++index) {
			const auto &member = members[index] ;	// 固定一覧の一member
			// 安全相対INFだけを受理し、短い名称の末尾参照を避ける
			if( !validInfDependencyPath( member.relativePath, false) ||
			   member.relativePath.size() < 5U ||
			   !equalName(
				   std::wstring_view( member.relativePath).substr( member.relativePath.size() - 4U),
				   L".inf") ||
			   member.byteCount == 0U || member.byteCount > MAX_INF_BYTES ||
			   member.sha256.size() != 64U || std::ranges::any_of( member.sha256, []( wchar_t value) {
				   // 小文字hex以外を元hashへcanonical化しない
				   return !((value >= L'0' && value <= L'9') || (value >= L'a' && value <= L'f')) ;
			   })) {
				return E_INVALIDARG ;
			}

			// Case衝突を別memberとみなして候補を水増ししない
			for( std::size_t prior = 0U; prior < index; ++prior) {
				// Windowsの同位置を重複登録した一覧は閉じていない
				if( equalName( members[prior].relativePath, member.relativePath)) {
					return E_INVALIDARG ;
				}
			}
		}

		InfDependencyContext context ;											// 同期runの実OS snapshot
		const auto			 error = currentContext( observationId, context) ;	// 実OSの取得
		// 未知OSの起点を推測して解析しない
		if( error != 0) {
			return error ;
		}

		NativeLoader loader( workspace, members, context, binding, session, archiveWorkspace,
							nullptr, nullptr, {}, nullptr, collector) ;	// 全native根拠の単独所有者
		return loader.run( rootIndex, seeds, result) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 保護packageと現在WindowsのINFを共通核へ非実行接続する
 * @param[in] workspace 全package memberを呼出し終了まで所有する保護領域
 * @param[in] members 全抽出INFの閉じた固定一覧。1～64件、重複を禁止する
 * @param[in] rootIndex members内の開始INF位置
 * @param[in] seeds 同じroot内の明示節群。作用完全性を認定しない
 * @param[in] observationId 非零のworker内観測世代
 * @param[out] result 全再確認成功時だけ保持し、全体失敗では空
 * @return 観測完了0、不正入力・path・改変・OS差・容量・例外のHRESULT
 * @pre 入力と出力の所有storageはaliasしない。同期workerで呼び、再入しない
 * @note Packageの公式由来は未検査に固定する。署名成功を由来・導入許可へ流用しない。OS trustがrevocation照会する場合がある。scan・staging・device導入
 *       は行わない
 */
//------------------------------------------------------------------------------
NativeError inspectNativeInfDependencies( const OfficialDownloadWorkspace			&workspace,
										 std::span<const InfDependencyPackageMember> members,
										 std::size_t rootIndex, std::span<const std::wstring> seeds,
										 std::uint64_t				observationId,
										 InfDependencyNativeResult &result)
{
	return inspectNativeInfDependenciesImpl( workspace, members, rootIndex, seeds, observationId,
											result, nullptr, nullptr, nullptr) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現Windowsの正規System32にある標準シリアルページDLLを固定して検査する
 * @param[in] workspace 元配布物を所有する保護領域
 * @param[out] proof 固定DLLとWindows署名、バイト、保護の一致証拠。失敗時は空
 * @return キャッシュ内の署名と実AMD64 exportが成立した場合0、それ以外は元診断
 * @note DLLはロードしない。元選択と実端末の導入資格は別に照合する
 */
//------------------------------------------------------------------------------
NativeError inspectWindowsSerialPropertyPage( const OfficialDownloadWorkspace &workspace,
											 WindowsSystemFileTrust			 &proof)
{
	proof = {} ;
	try {
		NativeLoader loader( workspace, {}, {}, nullptr, nullptr,
							nullptr) ;	// 同じ固定ファイルと署名確認を使う
		return loader.inspectSerialPropertyPage( proof) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Windows正規の仮想無線バスINFの信用と内容を同じ固定文書に照会します
 * @param[in] workspace 同じ収集操作の保護workspaceを同期中だけ借用します
 * @param[in] inspect 同梱INFと対応Storeの絶対パス及び署名時と一致する全バイトを同期で借用します
 * @return 同梱由来と内容の前後確認が成立して0、失敗はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError inf_dependency_native_detail::inspectProtectedWifiBusInf(
	const OfficialDownloadWorkspace								 &workspace,
	const std::function<NativeError( const std::wstring &, std::wstring_view,
									std::span<const std::byte>)> &inspect)
{
	try {
		NativeLoader loader( workspace, {}, {}, nullptr, nullptr,
							nullptr) ;	// 既署名と元ファイルを固定します
		return loader.inspectProtectedWifiBusInf( inspect) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元基本INFと同梱Wi-Fiバスへの全参照を署名と作用を確認したgraphへ結ぶ
 * @param[in] selected 元選択の同一基本INFで読んだ参照台帳
 * @param[in] rootIdentity 元基本INFのgraph内の非零識別子
 * @param[in] edges 署名と型付き作用を照合済みの全解決辺
 * @return 双方向の対応と旧名転送が完全かつ一意な場合true
 * @pre graphの各参照先は同じ署名済みWindows同梱文書です
 */
//------------------------------------------------------------------------------
[[nodiscard]] static bool matchScopedWifiBusReferences( const OfficialInfInstallInventory &selected,
													   std::uint64_t rootIdentity,
													   std::span<const InfDependencyEdge> edges)
{
	constexpr std::wstring_view LEGACY = L"VWiFiBus.PnPFilterRegistration" ;	// 旧名の同梱節
	constexpr std::wstring_view LEGACY_HW =
		L"VWiFiBus.PnPFilterRegistration.HW" ;							// 元転送が指す同梱節
	const auto hardware = selected.selectedInstallSection + L".HW" ;	// 元の選択が所有するHW節
	const auto external = []( const auto &reference) {
		return reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF ||
			   (reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
				!reference.targetPresent) ;
	} ; // 元基本から出る外部参照だけを照合する
	const auto matches = [rootIdentity, &external]( const auto &reference, const auto &edge) {
		const bool include =
			// 元参照の種類
			reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF ;
		const auto target = include ? std::wstring_view{reference.target}.substr(
										  reference.target.find_last_of( L'\\') + 1U)
									: std::wstring_view{reference.target} ;	// 元の直接参照名
		return external( reference) &&
			   equalName( reference.directive, include ? L"Include" : L"Needs") &&
			   edge.sourceIdentity == rootIdentity &&
			   edge.state == InfDependencyState::RESOLVED_SYSTEM &&
			   edge.directive ==
				   (include ? InfDependencyDirective::INCLUDE : InfDependencyDirective::NEEDS) &&
			   equalName( edge.sourceSection, reference.section) && equalName( edge.target, target) ;
	} ; // 元選択の節と種類まで一致した一辺に結ぶ
	// 外部へ出る元参照の全件を一つずつ実解決の辺へ結ぶ
	for( const auto &reference : selected.references) {
		// 複数候補や元graphで不在の参照を先頭の解決済み辺へ縮約しない
		if( external( reference) &&
		   ((equalName( reference.directive, L"Needs") && equalName( reference.target, LEGACY) &&
			 !equalName( reference.section, hardware)) ||
			std::ranges::count_if(
				edges, [&]( const auto &edge) { return matches( reference, edge) ; }) != 1)) {
			return false ;
		}
	}

	const auto legacyOrigin = [&]( const auto &edge) {
		return edge.sourceIdentity == rootIdentity && edge.targetIdentity != 0U &&
			   edge.targetIdentity != rootIdentity &&
			   edge.state == InfDependencyState::RESOLVED_SYSTEM &&
			   edge.directive == InfDependencyDirective::NEEDS &&
			   equalName( edge.sourceSection, hardware) && equalName( edge.target, LEGACY) ;
	} ; // 元のHW節が同梱旧名を要求した辺
	const auto origin = std::ranges::find_if( edges, legacyOrigin) ;	// 同じ同梱文書への元Needsです
	bool	   forwarded{} ;											// 元文書内の正規旧名転送を一度確認したこと
	// 実解決した逆向き照合も全件行い、同梱文書内の旧名転送を区別する
	for( const auto &edge : edges) {
		// 同じ署名済み文書内の規定一辺だけを元基本INFの照合対象から区別する
		if( origin != edges.end() && edge.sourceIdentity == origin->targetIdentity &&
		   edge.targetIdentity == edge.sourceIdentity &&
		   edge.state == InfDependencyState::RESOLVED_SYSTEM &&
		   edge.directive == InfDependencyDirective::NEEDS &&
		   equalName( edge.sourceSection, LEGACY) && equalName( edge.target, LEGACY_HW) &&
		   !std::exchange( forwarded, true)) {
			continue ;
		}

		// 元照合の一意性を緩めず、他の文書内の辺や重複した転送も拒否する
		if( std::ranges::count_if( selected.references, [&]( const auto &reference) {
			   return matches( reference, edge) ;
		   }) != 1) {
			return false ;
		}
	}

	return std::ranges::count_if( edges, legacyOrigin) == (forwarded ? 1 : 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集原本の選択節からWindows同梱の依存またはHDCの元SYSと全作用を検査する
 * @param[in] workspace 収集した原閉包の実ファイルを同期呼出し中所有する領域
 * @param[in] closure 元アーカイブから抽出し、各INFと宣言CATの内容検査を終えた閉包
 * @param[in] archiveEntries 抽出前に確認した同じアーカイブ階層の全通常ファイル一覧
 * @param[in] seeds AMD64 Modelsで選択した実基本節と実在する同名のHW・Services節
 * @param[in] selectedBase 元選択の実基本節名。seedsの先頭と一致する
 * @param[in] observationId 原収集の非零scan session ID
 * @param[in] scopedSelection 公式NetまたはUSB Bluetoothの元Modelsから選んだ棚卸し。従来型はnull
 * @param[out] evidence 公式Netの比較用証拠です。非nullの場合に全確認後だけ返します
 * @param[in] bluetoothSelection 同じ元INFのUSB Bluetooth棚卸しを検査する場合true
 * @param[out] serialObserved 混在シリアルの比較用証拠。両選択を検査する入口からだけ指定する
 * @return 全参照の所有元、署名、作用と同OSでの終了再検査が成立すれば0、失敗はHRESULT
 * @note 元アーカイブと現在状態の読取りです。端末の選択や導入許可を発行しません
 */
//------------------------------------------------------------------------------
static NativeError inspectArchiveInfDependencies(
	const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
	std::span<const OfficialZipEntry> archiveEntries, std::span<const std::wstring> seeds,
	std::wstring_view selectedBase, std::uint64_t observationId,
	const OfficialInfInstallInventory *scopedSelection, ScopedWifiBusDependencyEvidence *evidence,
	bool bluetoothSelection = false, InfDependencyNativeResult *serialObserved = nullptr)
{
	const bool scopedWifiBus =
		scopedSelection != nullptr && !bluetoothSelection ;	// 公式Netの同梱依存
	// 原INFの選択、全一覧、有限の閉包を持たない引数から収集成功を発行しません
	if( archiveEntries.empty() || closure.entries.empty() || closure.entries.size() > MAX_FILES ||
	   closure.packages.empty() || closure.packages.size() > 64U || observationId == 0U ||
	   seeds.empty() || seeds.size() > (scopedWifiBus ? 10U : 3U) ||
	   !equalName( seeds.front(), selectedBase) ||
	   (bluetoothSelection && (!scopedSelection || evidence))) {
		return E_INVALIDARG ;
	}

	try {
		const auto &source = closure.packages.front() ;	// 同じ収集rootの構造検査結果です
		const auto &groups = source.collectorSerialMedia ? source.collectorSerialMedia->groups
							 : source.nativeHdcInstallGroups.empty()
								 ? source.collectorInboxInstallGroups
								 : source.nativeHdcInstallGroups ;	// 原基本INFから解決した全選択節
		const bool	scopedBluetoothUsb =
			source.scopedModels && equalName( source.className, L"Bluetooth") &&
			!source.collectorInboxInstallGroups.empty() ;	// 空媒体として検査した元選択
		// 元WinUSBの作用は、公式Modelsが結ぶ同じ二ファイルだけの保護閉包に限る
		if( !source.collectorInboxWinUsbRegistrySection.empty()) {
			const auto *inf =
				// 実署名した同じ元INF
				dependencyEntry( closure.entries, source.infRelativePath) ;
			// 他のCAB構造や機器の元ハッシュでWinUSBの検査を有効にしない
			if( scopedSelection || !source.scopedModels || closure.packages.size() != 1U ||
			   archiveEntries.size() != 2U || closure.entries.size() != 2U ||
			   !source.sourceFiles.empty() || groups.size() != 1U || seeds.size() != 3U || !inf ||
			   inf->sha256 != source.scopedModels->infSha256 ||
			   workspace.protectionMode() != OfficialWorkspaceMode::CURRENT_USER_INSPECTION) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}
		}

		// 混在媒体は二つの元選択を比較する入口だけで扱う
		if( source.collectorSerialMedia.has_value() != (serialObserved != nullptr)) {
			return E_INVALIDARG ;
		}

		// 混在媒体には同じ公式ZIPから得たINF・CAT・SYS・DLLの確定済み閉包を必須とする
		if( source.collectorSerialMedia &&
		   (scopedSelection != nullptr || closure.packages.size() != 1U ||
			closure.entries.size() != 4U || archiveEntries.size() != 4U ||
			source.sourceFiles.size() != 2U || groups.size() != 2U ||
			!source.collectorPropertyPage || !equalName( source.className, L"Ports") ||
			!equalName( source.classGuid, L"{4d36e978-e325-11ce-bfc1-08002be10318}") ||
			!source.collectorInboxInstallGroups.empty() || source.nativePortsPage ||
			workspace.protectionMode() != OfficialWorkspaceMode::CURRENT_USER_INSPECTION ||
			std::ranges::any_of( closure.entries, [&]( const auto &entry) {
				const auto *original =
					// 取得済み同元項目
					dependencyEntry( archiveEntries, entry.relativePath) ;
				return original == nullptr || original->relativePath != entry.relativePath ||
					   original->uncompressedSize != entry.uncompressedSize ||
					   original->sha256.size() != 64U || original->sha256 != entry.sha256 ;
			}))) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		// 指定した公式選択がなく、または別のCAB形である場合はBluetoothの検査を完了させない
		if( scopedBluetoothUsb != bluetoothSelection ||
		   (scopedBluetoothUsb &&
			(archiveEntries.size() != 2U || closure.entries.size() != 2U ||
			 closure.packages.size() != 1U || !source.sourceFiles.empty() ||
			 !equalName( source.classGuid, L"{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}")))) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		// 公式範囲の元Modelsから選択したNet基本だけに専用の同梱依存検査を使います
		const bool selectedScopedRoot =
			scopedWifiBus && closure.packages.size() == 1U && source.scopedModels &&
			equalName( scopedSelection->infRelativePath, source.infRelativePath) &&
			scopedSelection->infSha256 == source.scopedModels->infSha256 &&
			equalName( scopedSelection->selectedInstallSection, selectedBase) &&
			scopedSelection->references.size() <= 4096U && equalName( source.className, L"Net") &&
			equalName( source.classGuid, L"{4d36e972-e325-11ce-bfc1-08002be10318}") &&
			std::ranges::any_of( source.scopedModels->sections, [&]( const auto &section) {
				return std::ranges::any_of( section.matches, [&]( const auto &match) {
					return equalName( match.installBase, scopedSelection->baseInstallSection) ;
				}) ;
			}) ;
		// 異なる用途や別のModels選択の節を同じrootの署名で検査しません
		if( source.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
		   (scopedWifiBus ? !selectedScopedRoot
						  : std::ranges::none_of( groups, [&]( const auto &group) {
								return std::ranges::equal( group, seeds) ;
							}))) {
			return E_INVALIDARG ;
		}

		std::vector<InfDependencyPackageMember>
			members ;	// 元CATと一組で検査する実package INFだけです
		// source fileとして含まれただけのINFを検査済みの所有元に変換しません
		for( const auto &package : closure.packages) {
			const auto *inf =
				// 元閉包のINFです
				dependencyEntry( closure.entries, package.infRelativePath) ;
			const auto *catalog = dependencyEntry(
				closure.entries, package.catalogRelativePath) ;	// 宣言された同CATです
			// 同じ容器に元からあるINFとCATの双方を抽出結果に結びます
			for( const auto *entry : {inf, catalog}) {
				// 元閉包に存在しない署名資料をパスだけから生成しません
				if( !entry) {
					return HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ;
				}

				const auto *original =
					// 抽出前の同原位置です
					dependencyEntry( archiveEntries, entry->relativePath) ;
				// 元一覧の実sizeと既知の原hashを維持し、署名済み別原本への切替えを拒否します
				if( !original || original->uncompressedSize != entry->uncompressedSize ||
				   (!original->sha256.empty() && original->sha256 != entry->sha256)) {
					return TRUST_E_BAD_DIGEST ;
				}
			}

			members.push_back( {inf->relativePath, inf->sha256, inf->uncompressedSize}) ;
		}

		const CollectorDependencySource collector{closure, archiveEntries, selectedBase,
												  scopedWifiBus,
												  scopedBluetoothUsb} ;	// 同期呼出し中だけ借用します
		InfDependencyNativeResult		observed ;						// graph・原file・作用は外部に引き渡しません
		const auto						error = inspectNativeInfDependenciesImpl(
			 workspace, members, 0U, seeds, observationId, observed, nullptr, nullptr, nullptr,
			 &collector) ;	// 同梱文書と参照の再観測結果です
		// 比較用証拠は一選択の終端再確認まで成功した場合だけ取り出す
		if( error == 0U && serialObserved != nullptr) {
			*serialObserved = std::move( observed) ;
		}

		// 従来の収集型と元診断はそのまま呼出し元へ返します
		if( error != 0U || !scopedWifiBus) {
			return error ;
		}

		const auto &plan = observed.dependency.plan.entries ;	// 元基本INFを指す項目です
		const auto	root = std::ranges::find_if(
			 plan, &InfDependencyPlanEntry::baseDriver) ;	// 検査済み元基本INFのgraph内位置です
		// 実選択の元基本と同梱フィルター作用を証明できなければ充足させません
		if( root == plan.end() || !observed.replacesWifiBusUpperFilters ||
		   observed.delayedRegistration) {
			return E_UNEXPECTED ;
		}

		// 型付きの同梱作用まで通過したgraphだけを元選択と双方向照合する
		if( !matchScopedWifiBusReferences( *scopedSelection, root->identity,
										 observed.dependency.edges)) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		// 同じ元選択の全照合と現在状態を確認した場合だけ比較資料を返します
		if( evidence) {
			*evidence = {std::move( observed.fixedFiles), std::move( observed.systemFiles),
						 std::move( observed.systemEffects), std::move( observed.systemServices)} ;
		}

		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 収集原本の選択節からWindows同梱の依存またはHDCの元SYSと全作用を検査する
 * @param[in] workspace 収集した原閉包の実ファイルを同期呼出し中所有する領域
 * @param[in] closure 元アーカイブから抽出し、各INFと宣言CATの内容検査を終えた閉包
 * @param[in] archiveEntries 抽出前に確認した同じアーカイブ階層の全通常ファイル一覧
 * @param[in] seeds AMD64 Modelsで選択した実基本節と実在する同名のHW・Services節
 * @param[in] selectedBase 元選択の実基本節名。seedsの先頭と一致する
 * @param[in] observationId 原収集の非零scan session ID
 * @return 全参照の所有元、署名、作用と同OSでの終了再検査が成立すれば0、失敗はHRESULT
 * @note 同期結果は収集内容だけに適用し、端末の選択や導入許可を発行しない
 */
//------------------------------------------------------------------------------
NativeError inspectCollectorInfDependencies( const OfficialDownloadWorkspace	 &workspace,
											const OfficialDriverClosure		 &closure,
											std::span<const OfficialZipEntry> archiveEntries,
											std::span<const std::wstring>	  seeds,
											std::wstring_view				  selectedBase,
											std::uint64_t					  observationId)
{
	return inspectArchiveInfDependencies( workspace, closure, archiveEntries, seeds, selectedBase,
										 observationId, nullptr, nullptr) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 混在シリアルの両選択で同じ元同梱ファイルとサービスが成立することを照合する
 * @param[in] workspace 取得済み元四ファイルを保持する私有保護領域
 * @param[in] closure 構造・署名・元DLLのexportを確認した一基本INFの閉包
 * @param[in] archiveEntries 同じ元ZIPの審査済み全項目とハッシュ
 * @param[in] observationId 同じ収集取得を示す非零の観測ID
 * @return 両方の元参照、Windows実ファイルとSCMが一致すれば0、失敗・途中変化はHRESULT
 * @note 読取り専用で同梱証拠を比較する。デバイス選択や導入は行わない
 */
//------------------------------------------------------------------------------
NativeError inspectCollectorSerialEnumeratorDependencies(
	const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
	std::span<const OfficialZipEntry> archiveEntries, std::uint64_t observationId)
{
	// 検査済みの混在媒体に属する異なる二つの選択をそろえる
	if( closure.packages.size() != 1U || !closure.packages.front().collectorSerialMedia) {
		return E_INVALIDARG ;
	}

	const auto &groups =
		// 元INFから解決した両選択
		closure.packages.front().collectorSerialMedia->groups ;
	// 基本、HW、Servicesの組が欠けた場合や同一選択の重複は受理しない
	if( groups.size() != 2U || groups[0].size() != 3U || groups[1].size() != 3U ||
	   equalName( groups[0].front(), groups[1].front())) {
		return E_INVALIDARG ;
	}

	std::array<InfDependencyNativeResult, 2U>
		observed ;	// それぞれの終端で同じ元参照を再確認した証拠
	// 両選択を個別に調べ、一方の失敗も元診断値を返す
	for( std::size_t index = 0U; index < observed.size(); ++index) {
		const auto &group = groups[index] ;	// 検査する一つの原選択
		const auto	error = inspectArchiveInfDependencies(
			 workspace, closure, archiveEntries, group, group.front(), observationId, nullptr,
			 nullptr, false, &observed[index]) ;	// 同梱依存の元診断
		// 片方でも根拠を確認できない場合は同梱の成功を返さない
		if( error != 0U) {
			return error ;
		}
	}

	// 二つの観測間でWindowsの元INF、CAT、配備ファイルやSCM設定が変わった場合は保留する
	return sameContext( observed[0].dependency.context, observed[1].dependency.context) &&
				   std::ranges::is_permutation( observed[0].fixedFiles, observed[1].fixedFiles) &&
				   observed[0].systemServices == observed[1].systemServices
			   ? 0U
			   : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ元CABで確認した公式USB Bluetoothの選択を全参照と終端再検査へ結ぶ
 * @param[in] workspace 同期中に元CABの展開データを所有する領域
 * @param[in] closure 元INFとCATを検査済みの一つのBluetooth閉包
 * @param[in] archiveEntries 同じ元CABの全通常ファイル
 * @param[in] selected 元INFから同じ公式Models範囲を読んだ一つの選択棚卸し
 * @param[in] observationId 収集処理の非零の観測世代
 * @return 元選択とすべての参照・作用が終端まで一致して0、読取や不一致はHRESULT
 * @note 同じCABから得た署名証拠を前提に、収集内容だけを検査する
 */
//------------------------------------------------------------------------------
NativeError inspectScopedBluetoothUsbDependencies( const OfficialDownloadWorkspace	&workspace,
												  const OfficialDriverClosure		&closure,
												  std::span<const OfficialZipEntry>	 archiveEntries,
												  const OfficialInfInstallInventory &selected,
												  std::uint64_t						 observationId)
{
	constexpr NativeError UNSUPPORTED = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;	// 未証明の収集作用
	// 公式選択の根を他の元パッケージから補わない
	if( closure.packages.size() != 1U) {
		return UNSUPPORTED ;
	}

	const auto &source = closure.packages.front() ;				// 先に元署名と公式Modelsを確認した基本INF
	const auto &groups = source.collectorInboxInstallGroups ;	// 同じ元バイトから確認した三つの選択節
	// 元のINF、ハッシュ、公式範囲の実選択、参照と節の全集合を結ぶ
	if( !source.scopedModels || !equalName( source.className, L"Bluetooth") ||
	   !equalName( source.infRelativePath, selected.infRelativePath) ||
	   selected.infSha256 != source.scopedModels->infSha256 || groups.size() != 1U ||
	   groups.front().size() != 3U ||
	   !equalName( groups.front().front(), selected.selectedInstallSection) ||
	   selected.references.size() != 7U || selected.visitedSections.size() != 4U ||
	   selected.coverageGaps.size() != 1U || selected.scannedLines != 9U) {
		return UNSUPPORTED ;
	}

	const auto &seeds	 = groups.front() ;					// 検査済みの元三節
	const auto &sections = source.scopedModels->sections ;	// 元署名と結んだ公式Models
	// 異なる元Modelsの導入名を同じ署名済みINFの別選択として取り込まない
	if( sections.size() != 1U || sections.front().matches.empty() ||
	   !equalName( sections.front().matches.front().installBase, selected.baseInstallSection)) {
		return UNSUPPORTED ;
	}

	constexpr std::array TARGETS{L"BthUsb.NT", L"BthUsb.NT.HW",
								 L"BthUsb.NT.Services"} ;	// 元節別の同梱Needs
	const auto			 count = [&]( std::wstring_view section, std::wstring_view directive,
							 std::wstring_view target, OfficialInfInstallReferenceKind kind) {
		  return std::ranges::count_if( selected.references, [&]( const auto &reference) {
			  return equalName( reference.section, section) &&
					 equalName( reference.directive, directive) &&
					 equalName( reference.target, target) && reference.kind == kind &&
					 !reference.targetPresent ;
		  }) ;
	} ; // 同じ元棚卸しから指定した外部辺だけを数える
	// 同じ元三節の外部参照が先行した署名付き元形と一対一に一致することを確認する
	for( std::size_t index = 0U; index < seeds.size(); ++index) {
		// IncludeとNeedsを別文書や別用途の参照で補わない
		if( count( seeds[index], L"Include", L"bth.inf",
				 OfficialInfInstallReferenceKind::INCLUDE_INF) != 1 ||
		   count( seeds[index], L"Needs", TARGETS[index],
				 OfficialInfInstallReferenceKind::LOCAL_SECTION) != 1) {
			return UNSUPPORTED ;
		}
	}

	const auto &gap =
		// 一般棚卸しが値まで判断しない唯一の局所機器設定
		selected.coverageGaps.front() ;
	const auto registry = std::ranges::find_if( selected.references, [&]( const auto &reference) {
		return equalName( reference.section, seeds[1]) &&
			   equalName( reference.directive, L"AddReg") &&
			   equalName( reference.target, gap.section) &&
			   reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
			   reference.targetPresent ;
	}) ; // 同じ署名と元節の検査で確認された機器DWORDの参照
	// 解釈されていない範囲は元署名で値まで確認済みの当該機器設定一件だけ
	if( registry == selected.references.end() ||
	   gap.kind != OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED ||
	   !gap.directive.empty()) {
		return UNSUPPORTED ;
	}

	return inspectArchiveInfDependencies( workspace, closure, archiveEntries, seeds,
										 selected.selectedInstallSection, observationId, &selected,
										 nullptr, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの公式Net選択から実解決した全仮想Wi-Fiバス参照と現状態を確認する
 * @param[in] workspace 同じ原アーカイブから展開した保護閉包の領域
 * @param[in] closure 原CATと全参照を確認した一つの公式Net基本INF
 * @param[in] archiveEntries 元CABの同じ容器内の全通常ファイル。部分展開一覧は不可
 * @param[in] selected 同じ元INFバイトから読んだ実導入節と付随節の棚卸し
 * @param[in] observationId 現workerの非零の観測世代
 * @param[out] evidence 非nullの場合、全確認後だけ元観測を返す。失敗時は空
 * @return 全元参照、同梱署名・Storeと現サービスが一致すれば0、失敗はHRESULT
 * @pre 端末側では呼出し側が公式レコードと現在の実選択を確定する
 * @note 読取り専用。元端末と導入資格は発行しない
 */
//------------------------------------------------------------------------------
NativeError inspectScopedWifiBusDependencies( const OfficialDownloadWorkspace   &workspace,
											 const OfficialDriverClosure	   &closure,
											 std::span<const OfficialZipEntry>	archiveEntries,
											 const OfficialInfInstallInventory &selected,
											 std::uint64_t						observationId,
											 ScopedWifiBusDependencyEvidence   *evidence)
{
	// 先行観測を不成立の元アーカイブへ流用しません
	if( evidence) {
		*evidence = {} ;
	}

	// 一つの元アーカイブの全通常ファイルを有限な一覧で受け取ります
	if( archiveEntries.empty() || archiveEntries.size() > 32'768U) {
		return E_INVALIDARG ;
	}

	try {
		std::vector<std::wstring> seeds{selected.selectedInstallSection} ;	// 同じ実基本節です
		// 元棚卸しで実在した同じ基本節の付随節だけを追加します
		for( const auto suffix :
			{L".HW", L".Services", L".CoInstallers", L".Interfaces", L".Components", L".Software",
			 L".Wdf", L".Events", L".LogConfigOverride"}) {
			auto section = selected.selectedInstallSection + suffix ;	// 同じ元起点の付随節です
			// 別起点や元にない付随節から依存を取得しません
			if( std::ranges::find( selected.visitedSections, section) !=
			   selected.visitedSections.end()) {
				seeds.push_back( std::move( section)) ;
			}
		}

		return inspectArchiveInfDependencies( workspace, closure, archiveEntries, seeds,
											 selected.selectedInstallSection, observationId,
											 &selected, evidence) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 使用中固定した封印集合を同じnative loaderへ渡す
 * @param[in] binding 同期使用中固定を所有する封印結果
 * @param[in] session 元証拠の生存issuer
 * @param[in] archiveWorkspace 元取得領域
 * @param[in] rootIndex 全INF内の開始位置
 * @param[in] seeds 明示節群
 * @param[in] observationId 非零の観測世代
 * @param[out] result 全成功時だけの非実行結果
 * @return 完了0、最初の検証／API／例外のHRESULT
 * @pre 呼出し元が元／派生全fileを呼出し終了まで固定する
 */
//------------------------------------------------------------------------------
NativeError AcquiredInfNativeAccess::inspect( const OfficialInfArchiveBinding  &binding,
											 const OfficialAcquisitionSession &session,
											 const OfficialDownloadWorkspace  &archiveWorkspace,
											 std::size_t					   rootIndex,
											 std::span<const std::wstring>	   seeds,
											 std::uint64_t					   observationId,
											 InfDependencyNativeResult		  &result)
{
	result = {} ;
	// 空結果をworkspace参照へ変換せず、成功boolから入口を作らない
	if( binding.workspace() == nullptr) {
		return E_INVALIDARG ;
	}

	return inspectNativeInfDependenciesImpl( *binding.workspace(), binding.members(), rootIndex,
											seeds, observationId, result, &binding, &session,
											&archiveWorkspace) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元内容を前後確認し、選択節の全Needs効果を検査します
 * @param[in] inspected 元保護byteと全署名を所有する内容です
 * @param[in] selected 同元packageの私有node選択copyです
 * @param[out] result 非実行graphです。効果は独立に検査します
 * @param[out] diagnostic 任意の非機密数値です。合否を変更する入力ではありません
 * @param[in] registeredDeviceRead 同じ選択機器の現用登録を読取する同期操作。指定しない場合はnull
 * @return 全依存と有限効果の充足0、未観測・未知・不合格のHRESULTです
 */
//------------------------------------------------------------------------------
NativeError CommonInfNativeAccess::inspect( const CommonInfInspection		 &inspected,
										   const OfficialInfPackage			 &selected,
										   InfDependencyNativeResult		 &result,
										   RequiredInfBindingDiagnostic		 *diagnostic,
										   const StorageRegisteredDeviceRead *registeredDeviceRead)
{
	result					= {} ;
	const auto contentError = recheckCommonContent( inspected) ;	// 全元byteと署名です
	// 私有元所有者なしで由来を作りません
	if( contentError != 0 || inspected.workspace == nullptr ||
	   selected.selectedBasicSection.empty()) {
		return contentError != 0 ? contentError : static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto original =
			selected.infRelativePath == inspected.closure.packages.front().infRelativePath
				? &inspected.closure.packages.front()
				: nullptr ;	// 元baseまたは元importを照合します
		const auto imported =
			std::ranges::find_if( inspected.requiredInfPackages, [&]( const auto &package) {
				return package.infRelativePath == selected.infRelativePath ;
			}) ; // 同元内容だけです
		// 元基本INFまたは元署名importだけを選択情報の再解析対象へ借用します
		const auto source =
			original != nullptr
				? original
				: (imported != inspected.requiredInfPackages.end() ? &*imported : nullptr) ;
		// 任意のINFへ選択節を転用しません
		if( source == nullptr) {
			return E_INVALIDARG ;
		}

		OfficialInfPackage current ;	// 同OS選択を元byteから再解析します
		// 同元inventoryを維持するWindows選択関係の再解析診断です
		auto			   error =
			inspectSelectedOfficialInfRelations( *inspected.workspace, inspected.closure.entries,
												*source, selected.selectedBasicSection, current) ;
		// 別OS節や選択機能の差を旧成功で補完しません
		if( error != 0 || current.selectedInstallSection != selected.selectedInstallSection ||
		   current.activeRequiredInfPaths != selected.activeRequiredInfPaths) {
			return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		std::vector<InfDependencyPackageMember> members ;	// 元保護閉包の全INFです
		std::size_t								root = 0U ;	// 正確な開始位置です
		// 全固定INFを元size/hashから構築します
		for( const auto &entry : inspected.closure.entries) {
			// データfileをINFへ読み替えません
			if( entry.relativePath.size() < 5U ||
			   !equalName(
				   std::wstring_view( entry.relativePath).substr( entry.relativePath.size() - 4U),
				   L".inf")) {
				continue ;
			}

			// Rootは元相対pathの完全一致だけです
			if( entry.relativePath == selected.infRelativePath) {
				root = members.size() ;
			}

			members.push_back( {entry.relativePath, entry.sha256, entry.uncompressedSize}) ;
		}

		// 不在rootを先頭INFへ救済しません
		if( members.empty() || root >= members.size() ||
		   members[root].relativePath != selected.infRelativePath) {
			return E_INVALIDARG ;
		}

		const HINF opened = SetupOpenInfFileW(
			inspected.workspace->path( selected.infRelativePath).c_str(), nullptr,
			INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;	// 非実行の選択seed確認です
		// 解析不能のまま任意seedを作りません
		if( opened == INVALID_HANDLE_VALUE) {
			return winError( GetLastError()) ;
		}

		InfHandle				  inf( opened) ;							// 同同期呼出しで解析handleを閉じる所有者です
		std::vector<std::wstring> seeds{selected.selectedInstallSection} ;	// exact同OS選択節です
		// 同じ選択節に付属し実在する節だけをseedへ追加します
		for( const auto suffix :
			{L".HW", L".Services", L".CoInstallers", L".Interfaces", L".Components", L".Software",
			 L".Wdf", L".Events", L".LogConfigOverride"}) {
			const auto name = selected.selectedInstallSection + suffix ;	// 同選択節です
			SetLastError( ERROR_SUCCESS) ;
			const LONG lines =
				// 同exact節の実在観測です
				SetupGetLineCountW( inf.get(), name.c_str()) ;
			// 空節と不存在を区別して保持します
			if( lines >= 0) {
				seeds.push_back( name) ;
			}
			// 不存在以外の読取失敗を付属節なしへ補完しません
			else if( GetLastError() != ERROR_SUCCESS && GetLastError() != ERROR_SECTION_NOT_FOUND) {
				return winError( GetLastError()) ;
			}
		}

		InfDependencyContext context ;	// 同scan観測と実OSです
		error = currentContext( inspected.scanSessionId, context) ;
		// 未観測文脈を固定値へ補完しません
		if( error != 0) {
			return error ;
		}

		SelectedStorageServiceFacts storageFacts ;	// 同原byteから独立に読み直す非権限factsです
		// 同元用途が端末storage専用であるという非権限分類です
		const bool					storage =
			selected.inspectionPurpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
		// storageはInclude/Needs flagの有無に関係なく全serviceとSYSを固定します
		if( storage) {
			error = readSelectedStorageServiceFacts( *inspected.workspace, inspected.closure.entries,
													current, storageFacts) ;
			// 原storage factsを独立読取できない場合はnative資格へ進めません
			if( error != 0U) {
				return error ;
			}
		}

		// 元の検査済み閉包と現在構成を借用し、指定したNeedsの選択節を照合する読込み器
		NativeLoader loader( *inspected.workspace, members, context, nullptr, nullptr, nullptr,
							&inspected, diagnostic, selected.selectedInstallSection,
							storage ? &storageFacts : nullptr, nullptr, registeredDeviceRead) ;
		return loader.run( root, seeds, result) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
namespace test {
//------------------------------------------------------------------------------
/**
 * @brief 架空の元選択と解決済み依存辺で旧名転送の双方向照合を検証する
 * @param[in] selected 架空の元基本INFの選択と参照
 * @param[in] rootIdentity 架空の元基本INFの識別子
 * @param[in] edges 事前に解決済みの状態を試験入力とした架空graph
 * @return 元参照と旧名転送を一意に照合できた場合true
 * @note 署名とWindows由来はこの架空graph検査では認定しない
 */
//------------------------------------------------------------------------------
bool matchScopedWifiBusReferencesForTest( const OfficialInfInstallInventory &selected,
										 std::uint64_t						rootIdentity,
										 std::span<const InfDependencyEdge> edges)
{
	return matchScopedWifiBusReferences( selected, rootIdentity, edges) ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB Bluetoothの同梱INF間の参照を試験用の依存グラフで照合する
 * @param[in] edges 解決状態を与えた架空の全参照辺
 * @param[in] seeds 架空の元基本節、HW節、Services節をこの順に保持する一覧
 * @param[in] rootIdentity 架空の元INF識別子
 * @return 両同梱INFと用途ごとの八参照が一意に一致した場合true
 * @note 署名、Windows由来、参照先の作用はこの試験の対象外
 */
//------------------------------------------------------------------------------
bool matchScopedBluetoothUsbReferencesForTest( std::span<const InfDependencyEdge> edges,
											  std::span<const std::wstring>		 seeds,
											  std::uint64_t						 rootIdentity)
{
	return matchScopedBluetoothUsbReferences( edges, seeds, rootIdentity).has_value() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空のUSB Bluetooth INFから保護コピーとSetupAPIの配備先を読み取る
 * @param[in] path 試験用領域内に作成済みの元INF
 * @param[in] driversDirectory SetupAPIの読み取り結果に要求する絶対ディレクトリ
 * @return コピー行と配備先が期待に一致して0、読取または構造不一致はHRESULT
 * @note INFを書き換えず、読み取ったコピーも実行しない
 */
//------------------------------------------------------------------------------
NativeError verifyBluetoothUsbCopyDeclarationForTest( const std::wstring &path,
													 std::wstring_view	 driversDirectory)
{
	const InfHandle inf{SetupOpenInfFileW(
		// 架空元INF
		path.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)} ;
	return inf.get() == INVALID_HANDLE_VALUE
			   ? winError( GetLastError())
			   : verifyBluetoothUsbCopyDeclaration( inf.get(), driversDirectory) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空のBluetoothとPCI INFから機器設定の元宣言を読み取る
 * @param[in] bluetoothPath 試験用領域内のBluetooth INF
 * @param[in] pciPath 試験用領域内のPCI INF
 * @return 両文書の機器相対作用が一致して0、読取・構造・型の不一致はHRESULT
 * @note 架空宣言だけを読む。署名、端末の現在値と導入時の処理順は検査しない
 */
//------------------------------------------------------------------------------
NativeError verifyBluetoothUsbHardwareDeclarationsForTest( const std::wstring &bluetoothPath,
														  const std::wstring &pciPath)
{
	constexpr DWORD STYLE = INF_STYLE_WIN4 | INF_STYLE_CACHE_IGNORE ;	// 元バイトを直接読む設定
	const InfHandle bluetooth{											// 架空Bluetooth文書
							  SetupOpenInfFileW( bluetoothPath.c_str(), nullptr, STYLE, nullptr)} ;
	// 先に開く元文書の読取失敗を後続APIで上書きしない
	if( bluetooth.get() == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	const InfHandle pci{SetupOpenInfFileW( pciPath.c_str(), nullptr, STYLE, nullptr)} ;	// 架空PCI文書
	return pci.get() == INVALID_HANDLE_VALUE
			   ? winError( GetLastError())
			   : verifyBluetoothUsbHardwareDeclarations( bluetooth.get(), pci.get()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定した試験用INFを同梱Bluetoothの共有作用比較に通す
 * @param[in] path 呼出し元が選んだ読取り専用の試験用INF
 * @return 元宣言の全件が一致して0、読取りや既知作用との不一致はHRESULT
 * @note これだけでは署名を確認しない。INFの内容やWindowsの設定を書き換えない
 */
//------------------------------------------------------------------------------
NativeError verifyBluetoothUsbSharedDeclarationsForTest( const std::wstring &path)
{
	std::array<wchar_t, MAX_PATH> windows{} ;	// SetupAPIと同じ現在OSのルート
	// 試験で照合するWindowsディレクトリの取得結果。単位は文字
	const auto length = GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
	// OSの位置が読み取れないときは試験用の代替ルートを推定しない
	if( length == 0U || length >= windows.size()) {
		return HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND) ;
	}

	const InfHandle inf{SetupOpenInfFileW(
		// 試験用INF
		path.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_IGNORE, nullptr)} ;
	// 元のファイルを読めなかったケースを不一致と区別する
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	return verifyBluetoothSharedDeclarations( inf.get(), std::wstring{windows.data(), length} +
															L"\\System32\\drivers") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元選択からの正確なNeeds文脈伝播を架空graphで確認します
 * @param[in] result 架空の元graphです。導入能力を持ちません
 * @param[in] seeds 元rootの基本節と付随節です
 * @param[in] rootIdentity 架空の元document identityです
 * @return 元sectionsと同順の文脈bit集合です
 */
//------------------------------------------------------------------------------
std::vector<unsigned char> inspectNeedsRegistryContextsForTest(
	const InfDependencyNativeResult &result, const std::span<const std::wstring> seeds,
	const std::uint64_t rootIdentity)
{
	return needsRegistryContexts( result, seeds, rootIdentity) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 専用compileだけで実AddReg parserの全行と文脈拒否を検査します
 * @param[in] path 架空保護workspace内の実INFです
 * @param[in] contexts DDInstall/HW/未対応の既定bit集合です
 * @param[in,out] registryRows 元累積予算です
 * @param[in,out] diagnostic 任意の元pair診断です。合否の入力に使いません
 * @return 実parserの元HRESULTです。署名・由来・device適合の認定ではありません
 */
//------------------------------------------------------------------------------
NativeError inspectNeedsAddRegForTest( const std::wstring &path, const unsigned char contexts,
									  std::size_t				   &registryRows,
									  RequiredInfBindingDiagnostic *diagnostic)
{
	const HINF opened =
		// 架空入力だけです
		SetupOpenInfFileW( path.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
	// 有効な実読取handleがないfixtureを成功へ補完しません
	if( opened == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	InfHandle  inf( opened) ;	// 同同期で閉じる読取専用所有者です
	INFCONTEXT line{} ;			// 架空Installの元AddReg行です
	// 別節や欠損したAddRegを先頭行へ補完しません
	if( !SetupFindFirstLineW( inf.get(), L"Install", L"AddReg", &line)) {
		return winError( GetLastError()) ;
	}

	return verifyNeedsAddReg( inf.get(), line, contexts, registryRows, diagnostic) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 専用compileの架空APIで実Common私有入口を一同期検査します
 * @param[in] api 既存の必須五callbackです
 * @param[in] inspected このfixtureだけの原内容です
 * @param[in] selected 実readerが再解析する元選択です
 * @param[out] result 成功時だけの元graphです
 * @param[out] diagnostic 元数値の任意出力です
 * @return Common入口の未変更HRESULTです
 * @note 通常製品にはこの宣言/入口を含めません
 */
//------------------------------------------------------------------------------
NativeError inspectCommonInfDependenciesWithTestApi( const InfDependencyNativeTestApi &api,
													const CommonInfInspection		 &inspected,
													const OfficialInfPackage		 &selected,
													InfDependencyNativeResult		 &result,
													RequiredInfBindingDiagnostic	 *diagnostic)
{
	result = {} ;
	// 専用fixtureも欠損/再入時は実trust APIへfallbackしません
	if( !api.version || !api.windowsDirectory || !api.infSignature || !api.catalogSignature ||
	   !api.driverStore || testApi != nullptr) {
		return E_INVALIDARG ;
	}

	/** @brief 専用compileの同期API借用を全returnで解除します */
	struct CommonApiScope {
		/**
		 * @brief 所有しないthread-local借用だけを終了します
		 */
		~CommonApiScope()
		{
			testApi = nullptr ;
		}
	} ;
	testApi = &api ;
	const CommonApiScope scope ;	// 実Common呼出しと全再検証の間だけ生存します
	return CommonInfNativeAccess::inspect( inspected, selected, result, diagnostic) ;
}

//------------------------------------------------------------------------------
/**
 * @brief このthreadの一同期呼出しにだけ架空APIを結合する
 * @param[in] api 必須五callbackと任意属性callback。呼出し終了まで生存し再入しない
 * @param[in] workspace 架空fileの所有領域
 * @param[in] members 閉じたINF一覧
 * @param[in] rootIndex 開始member
 * @param[in] seeds 明示節群
 * @param[in] observationId 非零の架空run
 * @param[out] result 全再確認成功時だけ保持し、失敗時は空
 * @return 内部観測0、不完全API・再入・例外またはadapterの失敗HRESULT
 * @note 製品buildにはこの関数もthread-local slotも含めない
 */
//------------------------------------------------------------------------------
NativeError inspectInfDependenciesWithTestApi( const InfDependencyNativeTestApi			 &api,
											  const OfficialDownloadWorkspace			 &workspace,
											  std::span<const InfDependencyPackageMember> members,
											  std::size_t								  rootIndex,
											  std::span<const std::wstring>				  seeds,
											  std::uint64_t				 observationId,
											  InfDependencyNativeResult &result)
{
	result = {} ;
	// 必須callback不在で実OS trustへfallbackせず、再入slotも借用しない
	if( !api.version || !api.windowsDirectory || !api.infSignature || !api.catalogSignature ||
	   !api.driverStore || testApi != nullptr) {
		return E_INVALIDARG ;
	}

	/** @brief 全return／例外経路でthread-local借用を解除する */
	struct TestApiScope {
		/**
		 * @brief 同期借用を解除する。callbackの所有権を持たない
		 */
		~TestApiScope()
		{
			testApi = nullptr ;
		}
	} ;
	testApi = &api ;
	const TestApiScope scope ;	// この同期runだけの解除責任
	return inspectNativeInfDependencies( workspace, members, rootIndex, seeds, observationId,
										result) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 封印所有者の同期入口へ専用APIを借用する。実取得・署名を認定しない
 * @param[in] api 必須五callbackと任意属性callback。同期呼出し中だけ生存する
 * @param[in] binding 架空取得から作った封印所有者
 * @param[in] session 架空取得の生存issuer
 * @param[in] archiveWorkspace 架空原取得領域
 * @param[in] rootIndex 開始INF位置
 * @param[in] seeds 明示節群
 * @param[in] observationId 非零の架空run世代
 * @param[out] result 全成功時だけのsnapshot。失敗時は空
 * @return 完了0、不完全API・再入・境界・例外のHRESULT
 */
//------------------------------------------------------------------------------
NativeError inspectAcquiredInfDependenciesWithTestApi(
	const InfDependencyNativeTestApi &api, const OfficialInfArchiveBinding &binding,
	const OfficialAcquisitionSession &session, const OfficialDownloadWorkspace &archiveWorkspace,
	std::size_t rootIndex, std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result)
{
	result = {} ;
	// 架空APIの欠損と再入を、実OS署名へのfallbackで補わない
	if( !api.version || !api.windowsDirectory || !api.infSignature || !api.catalogSignature ||
	   !api.driverStore || testApi != nullptr) {
		return E_INVALIDARG ;
	}

	/** @brief 全失敗／例外でもこの同期呼出しのAPI借用を解除する */
	struct AcquiredApiScope {
		/**
		 * @brief 非所有のthread-local slotを空にする
		 */
		~AcquiredApiScope()
		{
			testApi = nullptr ;
		}
	} ;
	testApi = &api ;
	const AcquiredApiScope scope ;	// 成功・拒否・例外すべてのslot回収責任
	return binding.inspectDependencies( session, archiveWorkspace, rootIndex, seeds, observationId,
									   result) ;
}
} // namespace test
#endif
} // namespace drivercrate
