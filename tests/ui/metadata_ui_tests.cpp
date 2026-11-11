//------------------------------------------------------------------------------
/**
 * @file metadata_ui_tests.cpp
 * @brief 製品と同じWin32画面の情報検索専用内部試験。
 * @version 01.54.02
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  非通信画面の選択・取消し・終端・描画を検証。
 * Ver.01.01.00 Shunji Ogawa  2026/09/14  種類別三階層・件数・選択・sort・結果保持を検証。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  観測・八軸詳細の表示とread-only操作を検証。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  共通packageの構成役割表示を検証。
 * Ver.01.03.01 Shunji Ogawa  2026/09/15  Provider行検証をregistryの件数と能力へ追従。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  通常scanの協調取消しbuttonと終端を検証。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  隠した索引画面で元承認・確定結果・遅延拒否を検証。
 * Ver.01.06.00 Shunji Ogawa  2026/10/12  実署名索引workerから通常選択・指定導入・部分失敗を検証。
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  複数INF・一回共有取得・native初回・登録先の25条件を検証。
 * Ver.01.08.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.08.01 Shunji Ogawa  2026/10/12  規約GETの必須安全headerと全handle解放を個別確認。
 * Ver.01.09.00 Shunji Ogawa  2026/10/12  元T06/T07/T09/C03と同意拒否subcaseを固定入力で確認。
 * Ver.01.09.01 Shunji Ogawa  2026/10/12  関数内Case十fieldの説明を採用前置形式へ統一。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  Class未確定初回の24条件と三回帰を実worker/Treeで確認。
 * Ver.01.11.00 Shunji Ogawa  2026/10/13  通常画面と元workerで必要構成の固定28条件を検査。
 * Ver.01.12.00 Shunji Ogawa  2026/10/13  元31と新19選択節/import条件を本物UI/workerで確認。
 * Ver.01.13.00 Shunji Ogawa  2026/10/13  元50条件を維持し必要Win32 service38条件を通常UI/workerへ追加。
 * Ver.01.13.01 Shunji Ogawa  2026/10/13  元88期待を維持し同leafの不正binary三条件を確認。
 * Ver.01.14.00 Shunji Ogawa  2026/10/13  元91と必要Win32形式24条件を通常worker・指定導入・結果で確認。
 * Ver.01.15.00 Shunji Ogawa  2026/10/13  元117と事前固定した媒体24条件を通常画面へ通す。
 * Ver.01.16.00 Shunji Ogawa  2026/10/13  元141にroot-only媒体と選択節依存の有限回帰を追加。
 * Ver.01.17.00 Shunji Ogawa  2026/10/13  固定157条件で選択依存とSYSTEM効果を通常workerへ接続。
 * Ver.01.17.01 Shunji Ogawa  2026/10/13  components入口の説明を現固定161条件へ整合。
 * Ver.01.18.00 Shunji Ogawa  2026/10/14  通常取得commandと原HTML全文の固定11正負を連結。
 * Ver.01.19.00 Shunji Ogawa  2026/10/15  R04の正常結果保持と旧候補再利用拒否を同画面/workerで直接確認。
 * Ver.01.20.00 Shunji Ogawa  2026/10/15  元固定条件の同意task結合・引継ぎ拒否・混合結果を直接確認。
 * Ver.01.21.00 Shunji Ogawa  2026/10/15  必要Extensionの登録byte保持と指定base作用の八条件を追加。
 * Ver.01.21.01 Shunji Ogawa  2026/10/15  到達済みHKR AddRegの採用に正常期待を整合。
 * Ver.01.22.00 Shunji Ogawa  2026/10/15  追加INFなしの必要条件の正負四件を通常準備へ追加。
 * Ver.01.23.00 Shunji Ogawa  2026/10/15  33INF正常公開とarchive128受理・129全拒否を実入力で確認。
 * Ver.01.24.00 Shunji Ogawa  2026/10/15  最終確認と実worker終端の有限観測を追加。
 * Ver.01.24.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.25.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * Ver.01.26.00 Shunji Ogawa  2026/10/16  索引通信結果の可視導線と同版publicationの画面受入を追加。
 * Ver.01.27.00 Shunji Ogawa  2026/10/16  索引通信詳細の全文と数値末尾の実control観測を追加。
 * Ver.01.28.00 Shunji Ogawa  2026/10/16  fixture撮影の再入観測とdialog生存境界を補強。
 * Ver.01.29.00 Shunji Ogawa  2026/10/17  限定入口で独立control描画とGDI/WIC/PNG原pixelを比較。
 * Ver.01.30.00 Shunji Ogawa  2026/10/18  UI試験を専用非入力desktopで自己監督し所有終端を検査。
 * Ver.01.30.01 Shunji Ogawa  2026/10/18  子環境keyとmodal所有判定を限定し実観測契約を正確化。
 * Ver.01.30.02 Shunji Ogawa  2026/10/19  部分内容結果と候補発行を併記し未導入を保持する表示を検証。
 * Ver.01.30.03 Shunji Ogawa  2026/10/24  時刻拒否のformatter理由と他診断保持の正負例を追加。
 * Ver.01.30.04 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * Ver.01.31.00 Shunji Ogawa  2026/10/27  通常準備画面で同ID/未知Class二機能と他node不足を確認。
 * Ver.01.32.00 Shunji Ogawa  2026/10/27  一device一行・詳細での明示候補選択と結果保持を検証。
 * Ver.01.33.00 Shunji Ogawa  2026/10/27  二初回候補の部分終端後に実詳細の履歴と再選択拒否を検証。
 * Ver.01.34.00 Shunji Ogawa  2026/10/28  通常検索前の再検出と取得前案内の境界を追加。
 * Ver.01.34.01 Shunji Ogawa  2026/10/28  取得待ちと他候補の混在案内を有限回帰。
 * Ver.01.35.00 Shunji Ogawa  2026/10/28  選択対象の導入後実観測と現在行の自動更新を接続。
 * Ver.01.36.00 Shunji Ogawa  2026/10/28  通常検索から同意付き検査・行checkboxまでを完全fakeで検証。
 * Ver.01.37.00 Shunji Ogawa  2026/10/28  三列・control不在・最下段配置と詳細閲覧の選択保持を確認。
 * Ver.01.38.00 Shunji Ogawa  2026/10/28  元選択に結合した取得・検査と導入の二段階操作へ接続。
 * Ver.01.39.00 Shunji Ogawa  2026/11/02  公式規約の画面内案内と明示Install・任意全文閲覧を接続。
 * Ver.01.39.01 Shunji Ogawa  2026/11/02  導入済み同版・不明参照・Code28初回のfilterと件数を検証。
 * Ver.01.39.02 Shunji Ogawa  2026/11/02  現行の単一導入操作と追加同意の試験を整合。
 * Ver.01.40.00 Shunji Ogawa  2026/11/03  新版の取得前確認と非推奨Store混在を固定。
 * Ver.01.40.01 Shunji Ogawa  2026/11/07  同原packageの共同保持と現非実行policyを整合。
 * Ver.01.41.00 Shunji Ogawa  2026/11/07  旧版詳細の実dialogとtable/filter不整合を再現。
 * Ver.01.41.01 Shunji Ogawa  2026/11/07  参照版分類の既core宣言を非配布TUへ明示。
 * Ver.01.42.00 Shunji Ogawa  2026/11/07  実候補tableの行結合・不正通知・geometryを検証。
 * Ver.01.43.00 Shunji Ogawa  2026/11/08  通常/狭幅画像と明示keyboard・旧版停止/取消しを確認。
 * Ver.01.43.01 Shunji Ogawa  2026/11/08  画像専用modeで初回描画の一巡後だけ撮影。
 * Ver.01.44.00 Shunji Ogawa  2026/11/08  表とbutton・実hoverセル短文のfocused回帰へ整合。
 * Ver.01.45.00 Shunji Ogawa  2026/11/08  同内容候補の表示集約と元一件選択を保持。
 * Ver.01.46.00 Shunji Ogawa  2026/11/08  明示指定を保持して比較可能な最新候補を初期表示。
 * Ver.01.47.00 Shunji Ogawa  2026/11/08  匿名導入診断と保存状態・元数値の有限確認を追加。
 * Ver.01.48.00 Shunji Ogawa  2026/11/08  同一索引再利用後の通常workerと候補表示の継続を確認。
 * Ver.01.49.00 Shunji Ogawa  2026/11/08  準備不成立後の元表示保持と段階別匿名診断を追加。
 * Ver.01.50.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続。
 * Ver.01.50.01 Shunji Ogawa  2026/11/09  導入完了後の元行・filter・表示位置を有限確認。
 * Ver.01.50.02 Shunji Ogawa  2026/11/09  詳細短文の旧二期待と不明機器fixtureの全件表示を整合。
 * Ver.01.50.03 Shunji Ogawa  2026/11/09  同scopeのWindow/event ownerだけheapへ移し全条件を保持。
 * Ver.01.51.00 Shunji Ogawa  2026/11/09  導入後の一回fresh候補継続と元意図の正負回帰を追加。
 * Ver.01.52.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続。
 * Ver.01.53.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続。
 * Ver.01.53.01 Shunji Ogawa  2026/11/11  復元失敗の選択保持とnative tooltip退場の試験観測を整合。
 * Ver.01.53.02 Shunji Ogawa  2026/11/11  README画像専用入口を新版候補の通常選択状態へ限定。
 * Ver.01.53.03 Shunji Ogawa  2026/11/11  README用検索結果を実filter操作で更新して撮影。
 * Ver.01.53.04 Shunji Ogawa  2026/11/11  README撮影だけをDWMの可視枠でPNGへ保存。
 * Ver.01.53.05 Shunji Ogawa  2026/11/11  README撮影の残る外周をclient左右下端に合わせる。
 * Ver.01.54.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新とInno引継ぎを接続。
 * Ver.01.54.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * Ver.01.54.02 Shunji Ogawa  2026/11/11  U21部分導入後の元scan保持期待をADR0474へ整合。
 * </pre>
 *
 * @note 明示optionでのみ起動し、実device・network・取得・復旧・導入へ接続しない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "app/main_window.h"
#include "app/resource.h"
#include "core/pending_reference_version.h"
#include "platform/signed_index_manifest.h"
#include "platform/local_scan_diagnostics.h"
#include "core/candidate_audit.h"
#include "core/local_coverage.h"
#include "core/device_observation.h"
#include "core/metadata_search.h"
#include "core/official_preparation.h"
#include "core/provider_registry.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/official_acquisition.h"
#include "platform/official_file_verifier.h"
#include "platform/signed_index_scan.h"
#include "platform/signed_index_task_observer_internal.h"
#include "platform/official_download_grant.h"
#include "support/metadata_ui_fixture.h"
#include "test_framework.h"
#include "app_update_ui_tests.h"
#include "signed_index_candidate_binding_tests.h"

#include <dwmapi.h>
#include <wincodec.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <iomanip>
#include <sstream>
#include <memory>
#include <optional>
#include <span>
#include <semaphore>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <thread>
#include <stdexcept>
#include <cwchar>
#include <type_traits>

namespace drivercrate {
namespace test {

// 再帰起動を防ぐ子process専用の環境名です。親の環境へは書き戻しません。
constexpr wchar_t	  PRIVATE_DESKTOP_MARKER[] = L"DRIVERCRATE_UI_PRIVATE_DESKTOP" ;
// 子processが保存する撮影成果物の新規所有rootです。
std::filesystem::path privateCaptureRoot ;
// 既owned dialogの二画像だけを再取得する内部modeです。通常の機能試験ではfalseです。
bool				  historyImagesOnly{} ;
// Startup照合後にだけ設定し、worker終了まで不変の実desktop名です。
std::wstring		  privateDesktopName ;
// 実factory callbackと実HWNDの照合数を元のUI期待と別に集計します。
std::atomic_uint32_t  privateWorkerObservations{} ;
// 一致しない所属や後始末を元のUI成功へ吸収しないための失敗状態です。
std::atomic_bool	  privateLifecycleFailed{} ;
// 実HWND観測の本文は一process一回とし、pumpの反復をlogへ増幅しません。
std::atomic_bool	  privateUiObserved{} ;

//------------------------------------------------------------------------------
/**
 * @brief 所有process handleから再利用されない作成時刻を読みます。
 * @param[in] process 本呼出し中に有効なprocess handleです。
 * @return 成功時のFILETIME値、失敗時は0です。
 */
//------------------------------------------------------------------------------
std::uint64_t		  nativeCreationTime( const HANDLE process) noexcept
{
	FILETIME creation{} ;	// 同handleに属する作成時刻です。
	FILETIME exit{} ;		// 未終端時もAPIへ渡す出力領域です。
	FILETIME kernel{} ;		// 本検査では利用しないkernel時間です。
	FILETIME user{} ;		// 本検査では利用しないuser時間です。
	// PIDだけで別processを同一とみなさないため作成時刻を要求します。
	if( !GetProcessTimes( process, &creation, &exit, &kernel, &user)) {
		return 0U ;
	}

	return (static_cast<std::uint64_t>( creation.dwHighDateTime) << 32U) | creation.dwLowDateTime ;
}

//------------------------------------------------------------------------------
/**
 * @brief 借用desktopの名前を有限領域へ読み取ります。
 * @param[in] desktop 自作または同threadの借用desktopです。解放しません。
 * @return 実名、取得失敗時は空です。
 */
//------------------------------------------------------------------------------
std::wstring nativeDesktopName( const HDESK desktop)
{
	wchar_t name[256]{} ;	// 自作名を上回る有限bufferです。
	DWORD	needed{} ;		// APIが要求するbyte数です。
	// 不完全な名前を照合へ渡しません。
	if( !desktop || !GetUserObjectInformationW( desktop, UOI_NAME, name, sizeof( name), &needed)) {
		return {} ;
	}

	return name ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定した自作desktopが非入力であることを標本確認します。
 * @param[in] desktop 自作または起動時に照合済みのdesktopです。
 * @return UOI_IOの取得が成功しfalseの場合trueです。名前は検査しません。
 */
//------------------------------------------------------------------------------
bool nativeNonInput( const HDESK desktop)
{
	BOOL  input = TRUE ;	// 取得失敗を非入力へ変換しない初期値です。
	DWORD needed{} ;		// UOI_IOの出力byte数です。
	return GetUserObjectInformationW( desktop, UOI_IO, &input, sizeof( input), &needed) != FALSE &&
		   input == FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実際のcallback threadを起動時desktopへ照合します。
 * @param[in] role 非機密な観測点名です。
 * @return 非入力の同desktopに所属する場合trueです。
 */
//------------------------------------------------------------------------------
bool observePrivateThread( const char *role)
{
	const HDESK desktop = GetThreadDesktop( GetCurrentThreadId()) ;	// 借用handleです。
	const bool	matched = !privateDesktopName.empty() &&
						 nativeDesktopName( desktop) == privateDesktopName &&
						 // 実所属です。
						 nativeNonInput( desktop) ;
	// 不一致を独立のprocess終了失敗へ保持します。
	if( !matched) {
		privateLifecycleFailed = true ;
	}

	// HWNDの反復照合は維持し、同一観測点の出力だけを一回へ制限します。
	if( std::string_view{role} != "MainWindow-HWND" || !privateUiObserved.exchange( true)) {
		std::cout << "PRIVATE_THREAD role=" << role << " pid=" << GetCurrentProcessId()
				  << " tid=" << GetCurrentThreadId() << " matched=" << matched << '\n' ;
	}

	return matched ;
}

/** @brief 一回の自己起動に必要なkernel handleとdesktopだけを所有します。
 * @note 明示finishで失敗を伝播し、例外時も所有子をjobで終端させます。
 */
struct NativeUiResources {
	/// 作成したdesktopです。borrowed originalを閉じません。
	HDESK				   desktop{} ;
	/// 作成前のthread所属です。非所有です。
	HDESK				   original{GetThreadDesktop( GetCurrentThreadId())} ;
	/// Kill-on-closeを設定した所有jobです。
	HANDLE				   job{} ;
	/// 実Assign成功後だけtrueとし、job handleの存在から推測しません。
	bool				   jobAssigned{} ;
	/// CreateProcessが返した同一process handleです。
	HANDLE				   process{} ;
	/// ResumeThread後に閉じる所有primary threadです。
	HANDLE				   thread{} ;
	/// 明示handle listにだけ載せる複製stdioです。
	std::array<HANDLE, 3U> streams{} ;
	/// Held-childが待機到達を通知する所有eventです。
	HANDLE				   ready{} ;
	/**
	 * @brief 例外時も所有資源を回収し、失敗をprocess状態へ残します。
	 */
	~NativeUiResources()
	{
		static_cast<void>( finish()) ;
	}
	/**
	 * @brief 所有process終端後に所属復帰・handle解放を確認します。
	 * @return 全後始末が成功した場合trueです。二度目は空の所有状態を確認します。
	 */
	bool finish() noexcept
	{
		bool ok = true ;	// 全APIの失敗を累積します。
		// 異常終了経路の子だけを所有jobまたは同作成handleで停止します。
		if( process && WaitForSingleObject( process, 0U) != WAIT_OBJECT_0) {
			ok = (jobAssigned ? TerminateJobObject( job, 75U) : TerminateProcess( process, 75U)) !=
				 FALSE ;
			const bool terminal =
				// 同作成handleの終端です。
				WaitForSingleObject( process, 5000U) == WAIT_OBJECT_0 ;
			std::cout << "PRIVATE_ABORT assigned=" << jobAssigned << " terminated=" << ok
					  << " sameHandleTerminal=" << terminal
					  << " creation=" << nativeCreationTime( process) << '\n' ;
			ok = terminal && ok ;
		}

		// 当該scopeが取得したkernel handleだけを閉じます。
		for( HANDLE *handle :
			{&thread, &process, &ready, &job, &streams[0], &streams[1], &streams[2]}) {
			// 取得済みの資源を一度だけ閉じ、失敗も結果へ残します。
			if( *handle) {
				ok		= CloseHandle( *handle) != FALSE && ok ;
				*handle = nullptr ;
			}
		}

		// Windowless親の所属を戻してから自作desktopを閉じます。
		if( desktop) {
			ok		= SetThreadDesktop( original) != FALSE && ok ;
			ok		= CloseDesktop( desktop) != FALSE && ok ;
			desktop = nullptr ;
		}

		// Cleanup失敗を元のassertion数とは別に終了codeへ反映します。
		if( !ok) {
			privateLifecycleFailed = true ;
		}

		return ok ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元環境blockを例外経路でも回収し、解放失敗を終了状態へ残します。
 * @param[in] block GetEnvironmentStringsWで取得した所有pointerです。
 */
//------------------------------------------------------------------------------
void nativeFreeEnvironment( wchar_t *block) noexcept
{
	// 一時環境を解放できない場合も黙って成功にしません。
	if( !FreeEnvironmentStringsW( block)) {
		privateLifecycleFailed = true ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 環境entryのkeyが内部markerと完全一致するかを判定します。
 * @param[in] entry 呼出し中だけ借用するkey=valueです。drive entryも許可します。
 * @return 区切り前のkeyが大文字小文字非依存で完全一致する場合trueです。
 * @note 値と非一致entryを変更せず、外部I/Oや環境内容の出力は行いません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool nativePrivateMarkerEntry( const std::wstring_view entry) noexcept
{
	const auto separator = entry.find( L'=') ;					// 値や類似prefixを比較へ混入させない境界です。
	constexpr std::wstring_view KEY{PRIVATE_DESKTOP_MARKER} ;	// 置換できる唯一のkeyです。
	// 区切り欠落、drive entryと長さ違いは内部markerとして除去しません。
	if( separator != KEY.size()) {
		return false ;
	}

	return CompareStringOrdinal( entry.data(), static_cast<int>( separator), KEY.data(),
								static_cast<int>( KEY.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief Child専用markerを追加した環境blockを所有copyで作ります。
 * @param[in] marker 起動先desktopの完全名です。
 * @return 二重NUL終端の環境blockです。
 */
//------------------------------------------------------------------------------
std::vector<wchar_t> nativeChildEnvironment( const std::wstring &marker)
{
	// 文字列/vectorの確保例外でも元blockを解放する専用deleterです。
	std::unique_ptr<wchar_t, decltype( &nativeFreeEnvironment)> block( GetEnvironmentStringsW(),
																	 &nativeFreeEnvironment) ;
	// 環境の取得失敗時は不完全な子を起動しません。
	if( !block) {
		throw std::runtime_error( "private environment unavailable") ;
	}

	std::vector<std::wstring> entries ;	// 既存環境の所有copyです。
	// 元環境を一回走査し、内部markerだけを置き換えます。
	for( const wchar_t *entry = block.get(); *entry; entry += std::wcslen( entry) + 1U) {
		// 同名の外部markerを子へ重複伝播しません。
		if( nativePrivateMarkerEntry( entry)) {
			continue ;
		}

		entries.emplace_back( entry) ;
	}

	block.reset() ;
	// 後始末失敗を起動成功へ吸収しません。
	if( privateLifecycleFailed) {
		throw std::runtime_error( "private environment cleanup failed") ;
	}

	entries.emplace_back( std::wstring{PRIVATE_DESKTOP_MARKER} + L"=" + marker) ;
	// Windows環境blockの大文字小文字非依存順へ揃えます。
	std::ranges::sort( entries, []( const auto &left, const auto &right) {
		return _wcsicmp( left.c_str(), right.c_str()) < 0 ;
	}) ;
	std::vector<wchar_t> result ;	// 起動API終了まで所有するblockです。
	// 全環境entryをNUL終端で連結し、末尾へもう一つNULを追加します。
	for( const auto &entry : entries) {
		result.insert( result.end(), entry.begin(), entry.end()) ;
		result.push_back( L'\0') ;
	}

	result.push_back( L'\0') ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実UI起動前のmarker指定owner epoch・desktop所属・成果物rootを照合します。
 * @param[in] marker 取得済みの有限な内部markerです。
 * @return 起動を許可できる場合trueです。
 * @note 指定ownerの生存を確認しますが、OSの実親子系譜は独立に検証しません。
 */
//------------------------------------------------------------------------------
bool validatePrivateStartup( const std::wstring &marker)
{
	const HDESK desktop = GetThreadDesktop( GetCurrentThreadId()) ;	// 起動時の借用所属です。
	const auto	first	= marker.find( L'_', 14U) ;					// 親PIDと作成時刻の境界です。
	// 形式と実desktopが一致しなければCOM/control生成前に停止します。
	if( !marker.starts_with( L"DriverCrateUi_") || marker.size() > 120U ||
	   first == std::wstring::npos || nativeDesktopName( desktop) != marker ||
	   !nativeNonInput( desktop)) {
		std::cout << "PRIVATE_STARTUP rejected=1 beforeCOM=1 beforeHWND=1\n" ;
		return false ;
	}

	const auto split =
		// PID境界です。
		marker.find( L'_', std::wstring_view{L"DriverCrateUi_"}.size()) ;
	std::size_t parsedPid{} ;														// 全桁消費を要求する変換位置です。
	std::size_t parsedTime{} ;														// 作成時刻の全桁消費位置です。
	const auto	pid = std::stoul( marker.substr( 14U, split - 14U), &parsedPid) ;	// 親の固定PIDです。
	const auto	creation =
		// 親の固定作成時刻です。
		std::stoull( marker.substr( split + 1U), &parsedTime) ;
	HANDLE	   parent  = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
									 // 本scopeだけで照合し解放します。
									 static_cast<DWORD>( pid)) ;
	const bool matched = parent && parsedPid == split - 14U &&
						 parsedTime == marker.size() - split - 1U &&
						 nativeCreationTime( parent) == creation &&
						 // markerが指定したownerの生存です。
						 WaitForSingleObject( parent, 0U) == WAIT_TIMEOUT ;
	const bool closed = !parent || CloseHandle( parent) != FALSE ;	// 取得済みhandleだけ回収します。
	// 異なるepochや死んだ親からの内部markerを受理しません。
	if( !matched || !closed) {
		return false ;
	}

	privateDesktopName = marker ;
	privateCaptureRoot = std::filesystem::current_path() / L"metadata-ui-private" / marker ;
	const DWORD attributes =
		// 親が新規作成したrootです。
		GetFileAttributesW( privateCaptureRoot.c_str()) ;
	// Reparse pointや既存の別rootへ撮影を転送しません。
	if( attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
	   (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		return false ;
	}

	std::wcout << L"PRIVATE_STARTUP desktop=" << marker << L" pid=" << GetCurrentProcessId()
			   << L" creation=" << nativeCreationTime( GetCurrentProcess())
			   << L" nonInput=1 beforeCOM=1\n" ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じPE・元raw command・元CWDで専用desktopの子を有限監督します。
 * @param[in] mode 明示されたUI/control modeです。元argvは変更しません。
 * @return 子の終了code、marker拒否73、期限切れ74、監督失敗75です。
 */
//------------------------------------------------------------------------------
int supervisePrivateUi( const std::string_view mode)
{
	NativeUiResources owned ;												// 異常経路でも所有子とdesktopを回収します。
	const auto		  creation = nativeCreationTime( GetCurrentProcess()) ;	// 親epochです。
	std::wstring	  name	   = L"DriverCrateUi_" + std::to_wstring( GetCurrentProcessId()) + L"_" +
						// PID再利用に依存しない自作名です。
						std::to_wstring( creation) ;
	owned.desktop = CreateDesktopW( name.c_str(), nullptr, nullptr, 0U,
								   DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
									   DESKTOP_WRITEOBJECTS,
								   nullptr) ;
	// 自動所属を仮定せず、windowless親の明示所属と復帰を要求します。
	if( !creation || !owned.desktop || nativeDesktopName( owned.desktop) != name ||
	   !nativeNonInput( owned.desktop) || !SetThreadDesktop( owned.desktop) ||
	   nativeDesktopName( GetThreadDesktop( GetCurrentThreadId())) != name ||
	   !SetThreadDesktop( owned.original)) {
		return 75 ;
	}

	const auto base =
		// 新しい共通親です。
		std::filesystem::current_path() / L"metadata-ui-private" ;
	std::filesystem::create_directories( base) ;
	const DWORD baseAttributes = GetFileAttributesW( base.c_str()) ;	// No-follow属性です。
	// 成果物の既存rootを置き換えず、自作名の新規directoryだけを許可します。
	if( baseAttributes == INVALID_FILE_ATTRIBUTES ||
	   (baseAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
	   !std::filesystem::create_directory( base / name)) {
		return 75 ;
	}

	owned.job = CreateJobObjectW( nullptr, nullptr) ;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{} ;	// 他の制限を変更しない所有job設定です。
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ;
	// Nested jobが使えない環境も無保護で継続しません。
	if( !owned.job || !SetInformationJobObject( owned.job, JobObjectExtendedLimitInformation, &limits,
											  sizeof( limits))) {
		return 75 ;
	}

	const std::wstring readyName = L"Local\\" + name + L"_ready" ;	// 所有待機到達eventです。
	// 期限切れcontrolだけが同期eventを作ります。
	if( mode == "lifecycle-expiry") {
		owned.ready = CreateEventW( nullptr, TRUE, FALSE, readyName.c_str()) ;
		// 既存eventの流用を成功へ変換しません。
		if( !owned.ready || GetLastError() == ERROR_ALREADY_EXISTS) {
			return 75 ;
		}
	}

	const std::array<DWORD, 3U> standardIds{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
											STD_ERROR_HANDLE} ;	// 明示三本です。
	// Stdio以外のhandleを継承せず、一時複製だけを許可listへ入れます。
	for( std::size_t index = 0U; index < standardIds.size(); ++index) {
		// CTestの既存pipeまたはconsole handleをそのまま同用途へ複製します。
		if( !DuplicateHandle( GetCurrentProcess(), GetStdHandle( standardIds[index]),
							GetCurrentProcess(), &owned.streams[index], 0U, TRUE,
							DUPLICATE_SAME_ACCESS)) {
			return 75 ;
		}
	}

	SIZE_T bytes{} ;	// Attribute listに必要なbyte数です。
	static_cast<void>( InitializeProcThreadAttributeList( nullptr, 1U, 0U, &bytes)) ;
	std::vector<std::byte> storage( bytes) ;	// 起動API終了までlistを所有します。
	// Win32のopaque listはAPIが指定するbyte領域へ配置します。
	auto *attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>( storage.data()) ;
	// Handle継承の限定に失敗した場合は通常継承へfallbackしません。
	if( !InitializeProcThreadAttributeList( attributes, 1U, 0U, &bytes)) {
		return 75 ;
	}

	// 以後の環境/string構築例外でもlist内部だけを解放し、byte領域はstorageへ残します。
	std::unique_ptr<std::remove_pointer_t<LPPROC_THREAD_ATTRIBUTE_LIST>,
					decltype( &DeleteProcThreadAttributeList)>
			   attributesOwner( attributes, &DeleteProcThreadAttributeList) ;

	const bool listed = UpdateProcThreadAttribute( attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
												  owned.streams.data(), sizeof( owned.streams),
												  nullptr, nullptr) != FALSE ;	// 限定listです。
	STARTUPINFOEXW startup{} ;													// Desktopとstdio以外の表示設定を変えません。
	startup.StartupInfo.cb		   = sizeof( startup) ;
	startup.StartupInfo.lpDesktop  = name.data() ;
	startup.StartupInfo.dwFlags	   = STARTF_USESTDHANDLES ;
	startup.StartupInfo.hStdInput  = owned.streams[0] ;
	startup.StartupInfo.hStdOutput = owned.streams[1] ;
	startup.StartupInfo.hStdError  = owned.streams[2] ;
	startup.lpAttributeList		   = attributes ;
	std::vector<wchar_t> executable( 32768U) ;											// 同一PEの絶対pathを読みます。
	const DWORD	 length	 = GetModuleFileNameW( nullptr, executable.data(), 32768U) ;	// 有効長です。
	std::wstring command = GetCommandLineW() ;											// 外部raw commandを変更しない所有copyです。
	auto		 environment = nativeChildEnvironment(
		// 内部markerだけです。
		mode == "lifecycle-marker" ? name + L"_wrong" : name) ;
	PROCESS_INFORMATION child{} ;	// APIの作成handleを直ちにownerへ移します。
	const bool			launched =
		listed && length > 0U && length < 32768U &&
		CreateProcessW( executable.data(), command.data(), nullptr, nullptr, TRUE,
					   CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
					   environment.data(), nullptr, &startup.StartupInfo,
					   &child) != FALSE ;									// 元CWDを継承します。
	const DWORD launchError = launched ? ERROR_SUCCESS : GetLastError() ;	// Cleanup前に保持します。
	attributesOwner.reset() ;
	owned.process = child.hProcess ;
	owned.thread  = child.hThread ;
	// Launch失敗を子成功へ変換しません。
	if( !launched) {
		std::cout << "PRIVATE_LAUNCH failed=1 error=" << launchError << '\n' ;
		return 75 ;
	}

	const auto childCreation = nativeCreationTime( owned.process) ;	// 同作成handleのepochです。
	// 負例だけ実無効job handleへAssignし、未再開の自作子を同作成handleで回収します。
	if( mode == "lifecycle-assignment-error") {
		const bool assigned =
			// 実API拒否を要求します。
			AssignProcessToJobObject( nullptr, owned.process) != FALSE ;
		const DWORD error  = GetLastError() ;	// Cleanupで失われる前の実errorです。
		owned.jobAssigned  = assigned ;
		const bool cleanup = owned.finish() ;	// 未所属なら同process handleをTerminateProcessします。
		std::cout << "PRIVATE_ASSIGNMENT_NEGATIVE pid=" << child.dwProcessId
				  << " creation=" << childCreation << " assigned=" << assigned << " error=" << error
				  << " neverResumed=1 cleanup=" << cleanup << '\n' ;
		return !assigned && error != ERROR_SUCCESS && cleanup ? 75 : 76 ;
	}

	owned.jobAssigned = AssignProcessToJobObject( owned.job, owned.process) != FALSE ;
	// 実所属が成立しない通常子を再開するfallbackは設けません。
	if( !childCreation || !owned.jobAssigned ||
	   ResumeThread( owned.thread) == static_cast<DWORD>( -1)) {
		return 75 ;
	}

	std::cout << "PRIVATE_CHILD pid=" << child.dwProcessId << " creation=" << childCreation
			  << " handle=" << owned.process << " job=1 originalRawCommand=1 originalCwd=1\n"
			  << std::flush ;
	DWORD waited{} ;	// 同process handleの有限待機結果です。
	// Held-childの待機到達をeventで確認してから短い期限を測ります。
	if( owned.ready) {
		// 起動不能を期限切れcontrolの成功へ数えません。
		if( WaitForSingleObject( owned.ready, 5000U) != WAIT_OBJECT_0) {
			return 75 ;
		}

		waited = WaitForSingleObject( owned.process, 100U) ;
	} else {
		waited = WaitForSingleObject( owned.process, 590000U) ;
	}

	int result = 75 ;	// 未確認終端は失敗です。
	// 期限切れは失敗として所有jobを終端し、同じhandleで終了を確認します。
	if( waited == WAIT_TIMEOUT) {
		const bool killed =
			// 所有子以外を操作しません。
			TerminateJobObject( owned.job, 74U) != FALSE ;
		const bool terminal =
			// 同handleです。
			WaitForSingleObject( owned.process, 5000U) == WAIT_OBJECT_0 ;
		std::cout << "PRIVATE_EXPIRY ready=" << (owned.ready != nullptr) << " killed=" << killed
				  << " terminal=" << terminal << '\n' ;
		result = killed && terminal ? 74 : 75 ;
	}
	// 自然終端時だけ子の実exit codeを転送します。
	else if( waited == WAIT_OBJECT_0) {
		DWORD code{} ;	// 同作成handleから取得する実終了値です。
		// Exit取得失敗やhandleのepoch不一致は成功にしません。
		if( GetExitCodeProcess( owned.process, &code) && code <= 255U &&
		   nativeCreationTime( owned.process) == childCreation) {
			result = static_cast<int>( code) ;
		}
	}

	const bool cleanup = owned.finish() ;	// 子終端後に全資源を回収します。
	std::cout << "PRIVATE_TERMINAL pid=" << child.dwProcessId << " creation=" << childCreation
			  << " sameHandle=1 cleanup=" << cleanup << " exit=" << result << '\n' ;
	return cleanup && !privateLifecycleFailed ? result : 75 ;
}

} // namespace test

/** @brief 内部targetだけが使用する、非通信factory設定と既存UI状態の観測。 */
struct MainWindowMetadataTestAccess {
	/**
	 * @brief 取得前の一参照を普通の選択意図として指定します。
	 * @param[in,out] window 元scanです。
	 * @param[in,out] context 原assertionです。
	 * @param[in] expectedVersion 空は旧metadata負例、正例は原INF由来の明示版です。
	 * @return 明示した元identityです。
	 */
	static std::vector<std::wstring> selectTargetOnlyReference(
		MainWindow &window, test::TestContext &context,
		const std::wstring_view expectedVersion = {})
	{
		window.showRecommendedOnly_ = false ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
		window.populateCandidates( window.candidates_) ;
		window.clearCandidateSelection() ;
		return selectInstallIntents( window, context, true, false, expectedVersion) ;
	}
	/**
	 * @brief 同workerの実DS候補二件を選び一件だけを最初に送ります。
	 * @param[in,out] window 元scanの本物Windowです。
	 * @param[in,out] context 有限assertion集計先です。
	 * @return 最初に実行した元candidate identityです。
	 */
	static std::wstring startTargetOnlyLocal( MainWindow &window, test::TestContext &context)
	{
		window.showRecommendedOnly_ = false ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
		window.populateCandidates( window.candidates_) ;
		window.clearCandidateSelection() ;
		std::vector<std::size_t> indexes ;	// 元DSだけの新版候補です。
		// Currentや索引の取得前参照を直接Installへ混ぜません。
		for( std::size_t index{}; index < window.candidates_.size(); ++index) {
			const auto &candidate = window.candidates_[index] ;	// 原候補です。
			// 実低位fakeから返ったDS新版だけを選びます。
			if( candidate.providerId == DRIVER_STORE_PROVIDER_ID && candidate.installable &&
			   !candidate.current && candidate.action == DriverAction::UPDATE) {
				indexes.push_back( index) ;
				DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( index)) ;
				TreeView_SetCheckState( window.updateTree_, window.candidateItems_[index], TRUE) ;
			}
		}

		DRIVERCRATE_EXPECT( context,
						   indexes.size() == 2U && window.checkedCandidateIndexes().size() == 2U) ;
		// 原二候補がなければ合成selectionで補完しません。
		if( indexes.size() != 2U) {
			return {} ;
		}

		const std::array selected{
			window.candidates_[indexes.front()].identity} ;	// 一件のみの原selectionです。
		const auto begin = window.controller_.beginInstall(
			window.controller_.scanSessionId(), selected,
			InstallConfirmation::CONFIRMED) ;	// 残checkは未処理です。
		DRIVERCRATE_EXPECT( context,
						   begin.accepted &&
							   window.worker_->requestInstall(
								   begin.operationId, window.controller_.scanSessionId(), selected,
								   window.window_, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		return selected.front() ;
	}
	/**
	 * @brief 最新解消だけ枠を隠し、次filterと未処理選択を確認します。
	 * @param[in,out] window 元のnative Windowです。
	 * @param[in,out] context 原assertionです。
	 * @param[in] consumed 実際に導入した元候補です。
	 */
	static void verifyLatestResolved( MainWindow &window, test::TestContext &context,
									 const std::wstring &consumed)
	{
		const auto found = std::ranges::find( window.candidates_, consumed,
											 &UpdateCandidate::identity) ;	// 元選択です。
		DRIVERCRATE_EXPECT( context, found != window.candidates_.end()) ;
		// 元導入対象がなければ別行で期待を補いません。
		if( found == window.candidates_.end()) {
			return ;
		}

		const auto index =
			// 元行です。
			static_cast<std::size_t>( found - window.candidates_.begin()) ;
		const auto item = window.candidateItems_[index] ;	// まだ元itemを保持しています。
		DRIVERCRATE_EXPECT(
			context, item && window.resolvedInstallDevices_.contains( found->deviceIdentity) &&
						 (TreeView_GetItemState( window.updateTree_, item, TVIS_STATEIMAGEMASK) >>
						  12U) == 0U &&
						 window.checkedCandidateIndexes().size() == 1U) ;
		window.showRecommendedOnly_ = true ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_CHECKED, 0) ;
		window.populateCandidates( window.candidates_) ;
		std::cout << "LATEST_FILTER filter=" << window.showRecommendedOnly_
				  << " checks=" << window.checkedCandidateIndexes().size()
				  << " raw=" << std::ranges::count( window.candidateSelected_, true)
				  << " resolved=" << window.resolvedInstallDevices_.size()
				  << " item=" << (window.candidateItems_[index] != nullptr) << "\n" ;

		DRIVERCRATE_EXPECT( context, !window.candidateItems_[index] &&
										window.checkedCandidateIndexes().empty() &&
										std::ranges::count( window.candidateSelected_, true) == 1) ;
		// 元Bが非推奨で非表示でも、未失効の選択そのものを保持します。
		for( std::size_t pending = 0; pending < window.candidateSelected_.size(); ++pending) {
			// 非表示でも元の未失効選択を保持することを確認します。
			if( window.candidateSelected_[pending]) {
				DRIVERCRATE_EXPECT(
					context, !window.visibleInRecommendedFilter( window.candidates_[pending]) &&
								 !window.candidateItems_[pending] &&
								 window.controller_.isInstallCandidateAllowed(
									 window.candidates_[pending].identity)) ;
			}
		}

		window.showRecommendedOnly_ = false ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
		window.populateCandidates( window.candidates_) ;
		std::cout << "LATEST_FILTER filter=" << window.showRecommendedOnly_
				  << " checks=" << window.checkedCandidateIndexes().size()
				  << " raw=" << std::ranges::count( window.candidateSelected_, true)
				  << " resolved=" << window.resolvedInstallDevices_.size()
				  << " item=" << (window.candidateItems_[index] != nullptr) << "\n" ;

		DRIVERCRATE_EXPECT(
			context, window.candidateItems_[index] &&
						 (TreeView_GetItemState( window.updateTree_, window.candidateItems_[index],
												TVIS_STATEIMAGEMASK) >>
						  12U) == 0U &&
						 window.checkedCandidateIndexes().size() == 1U) ;
	}
	/**
	 * @brief 元scan・残check・通常入口を確認して二番目だけを開始します。
	 * @param[in,out] window 最初の終端を受理した本物Windowです。
	 * @param[in,out] context 有限assertion集計先です。
	 * @param[in] session 元scanです。
	 * @param[in] consumed 消費した候補です。
	 * @return 元一候補から次の明示Installを開始できた場合trueです。
	 */
	static bool startTargetOnlyRemaining( MainWindow &window, test::TestContext &context,
										 const ScanSessionId session, const std::wstring &consumed)
	{
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::SCAN_READY &&
										window.controller_.scanSessionId() == session &&
										window.controller_.lastInstallSucceeded()) ;
		const std::array old{consumed} ;	// 同scanでも消費したcandidateは拒否します。
		DRIVERCRATE_EXPECT(
			context, !window.controller_.beginInstall( session, old, InstallConfirmation::CONFIRMED)
						  .accepted) ;
		DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().size() == 1U &&
										IsWindowEnabled( window.installButton_)) ;
		std::size_t selected{} ;	// 元raw選択です。
		std::size_t allowed{} ;		// controllerが保持する元permitだけです。
		std::size_t references{} ;	// 残metadataです。
		std::size_t readonly{} ;	// 表示gateです。
		// 元集合の各要素を同じscopeへ一度ずつ照合します。
		for( std::size_t index{}; index < window.candidates_.size(); ++index) {
			selected += index < window.candidateSelected_.size() && window.candidateSelected_[index]
							? 1U
							: 0U ;
			allowed +=
				window.controller_.isInstallCandidateAllowed( window.candidates_[index].identity)
					? 1U
					: 0U ;
			references += !window.candidates_[index].preparationTargetIdentity.empty() ? 1U : 0U ;
		}

		// 元集合の各要素を同じscopeへ一度ずつ照合します。
		for( const auto &row : window.treeRows_) {
			readonly += row.readonlyCheckbox ? 1U : 0U ;
		}

		std::cout << "TARGET_GATE selected=" << selected << " allowed=" << allowed
				  << " references=" << references << " readonly=" << readonly
				  << " checked=" << window.checkedCandidateIndexes().size()
				  << " button=" << IsWindowEnabled( window.installButton_) << '\n'
				  << std::flush ;
		// 期待を減らさず、不成立を合成したclickや未駆動modalで隠しません。
		if( window.checkedCandidateIndexes().size() == 1U &&
		   IsWindowEnabled( window.installButton_)) {
			window.beginInstall() ;
		}

		DRIVERCRATE_EXPECT( context,
						   window.controller_.state() == ApplicationState::CREATING_RESTORE_POINT) ;
		return window.controller_.state() == ApplicationState::CREATING_RESTORE_POINT ;
	}
	/** @brief 実queueから取り出した最大64eventの非機密な順序観測です。 */
	struct IndexTerminalTrace {
		/// 受信順の実event種類です。count未満の要素だけが有効です。
		std::array<WorkerEventKind, 64U> kinds{} ;
		/// 同eventの実operation IDです。候補や端末の識別子を含みません。
		std::array<OperationId, 64U>	 operations{} ;
		/// 配列へ保存済みの要素数です。
		std::size_t						 count{} ;
		/// 64eventを超えた場合trueです。観測欠落を成功へ補完しません。
		bool							 overflow{} ;
	} ;
	/**
	 * @brief 実workerのstop/joinを待ち、以後の非atomic観測を同期します。
	 * @param[in,out] window 対象workerを単独所有する同UI threadのWindowです。
	 */
	static void stopIndexWorker( MainWindow &window)
	{
		window.worker_->stop() ;
	}
	/**
	 * @brief 待機せず同workerの現在queueを所有付きで取り出します。
	 * @param[in,out] window 同workerを所有するUI threadのWindowです。
	 * @return 実queueの有限event集合です。成功eventを生成しません。
	 */
	static std::vector<WorkerEvent> takeReadyIndexEvents( MainWindow &window)
	{
		return window.worker_->takeEvents() ;
	}
	/**
	 * @brief 完全低位fixture workerを本物Windowへ私有結合します。
	 * @param[in,out] window 既存fakeで生成済みの隠したWindowです。
	 * @param[in] worker 実queueと元署名storeを保持するworkerの単独所有です。
	 */
	static void attachIndexWorker( MainWindow &window, std::unique_ptr<ProviderWorker> worker)
	{
		window.worker_->stop() ;
		window.worker_								= std::move( worker) ;
		window.enabledProviderIds_					= {std::wstring{DRIVER_STORE_PROVIDER_ID},
													   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		window.testSuppressPreparationResultDialog_ = true ;
	}
	/**
	 * @brief 通常scan buttonと同じ製品処理を開始します。
	 * @param[in,out] window 完全低位fixture workerを所有するWindowです。
	 */
	static void beginIndexScan( MainWindow &window)
	{
		window.beginScan() ;
	}
	/**
	 * @brief 利用者の通常検索と同じcommandを送ります。取得準備commandは送りません。
	 * @param[in,out] window 完全低位fake workerを結合した内部Windowです。
	 */
	static void beginSearchCommand( MainWindow &window)
	{
		SendMessageW( window.window_, WM_COMMAND, MAKEWPARAM( IDC_SCAN, BN_CLICKED), 0) ;
	}
	/**
	 * @brief 本体がpostした同Windowの一通知を、実dispatch前に所有します。
	 * @param[in] window 同じUI threadの所有Windowです。
	 * @return 元通知、または未発行の場合nulloptです。成功通知を生成しません。
	 */
	static std::optional<MSG> takeSearchContinuation( const MainWindow &window)
	{
		MSG message{} ;	// 当該private通知だけを有限に取り出します。
		return PeekMessageW( &message, window.window_, WM_APP + 2, WM_APP + 2, PM_REMOVE)
				   ? std::optional<MSG>{message}
				   : std::nullopt ;
	}
	/**
	 * @brief 元候補が複数あるdeviceを勝手に一候補へ指定していないことを確認します。
	 * @param[in] window 元検索を受理した本物Windowです。
	 * @param[in,out] context 原assertionの集計先です。
	 * @return 詳細閲覧へ使用する元参照位置です。欠落時は候補数です。
	 */
	static std::size_t inspectPendingAmbiguity( const MainWindow &window, test::TestContext &context)
	{
		const auto reference = std::ranges::find_if( window.candidates_, []( const auto &candidate) {
			return !candidate.preparationTargetIdentity.empty() ;
		}) ; // 元recordへ結合済みの最初の参照です。
		DRIVERCRATE_EXPECT( context, reference != window.candidates_.end()) ;
		// 元参照なしを別の候補で補完しません。
		if( reference == window.candidates_.end()) {
			return window.candidates_.size() ;
		}

		const auto index = static_cast<std::size_t>(
			reference - window.candidates_.begin()) ;	// 同scanの元位置です。
		const auto &row =
			window.treeRows_[window.candidateRowIndexes_[index]] ;	// 同deviceの唯一の行です。
		DRIVERCRATE_EXPECT( context,
						   !row.hasCandidateChoice &&
							   std::ranges::count_if( row.candidateIndexes,
													 [&]( const auto ordinal) {
														 return window.isSelectableCandidate(
															 window.candidates_[ordinal]) ;
													 }) > 1 &&
							   window.checkedCandidateIndexes().empty() &&
							   !IsWindowEnabled( window.installButton_)) ;
		return index ;
	}
	/**
	 * @brief 初回結果後の実fake新scanを、そのまま確認します。
	 * @param[in,out] window 実fake新scanの所有Windowです。
	 * @param[in,out] context Assertion集計先です。
	 */
	static void verifyFreshAfterInitial( MainWindow &window, test::TestContext &context)
	{
		const auto references = std::ranges::count_if( window.candidates_, []( const auto &item) {
			return !item.preparationTargetIdentity.empty() ;
		}) ; // 新scan自身が返した取得前参照数です。
		DRIVERCRATE_EXPECT( context, references == 0 && window.checkedCandidateIndexes().empty()) ;
		// 新scanの全deviceで旧代表が消えたことを確認します。
		for( const auto &row : window.treeRows_) {
			// 種類行は候補指定を持ちません。
			if( row.kind == MainWindow::TreeRowKind::DEVICE) {
				DRIVERCRATE_EXPECT( context,
								   !row.hasCandidateChoice && !row.explicitCandidateChoice) ;
			}
		}
	}
	/**
	 * @brief 元workerに完全fakeのWUA slotを追加します。
	 * @param[in,out] window 元workerを結合済みの内部Windowです。
	 */
	static void enableManagedFixture( MainWindow &window)
	{
		window.enabledProviderIds_.push_back( std::wstring{WINDOWS_UPDATE_PROVIDER_ID}) ;
	}
	/**
	 * @brief 元pending参照を同deviceの実checkboxから明示選択します。
	 * @param[in,out] window 元検索を受理した本物Windowです。
	 * @param[in,out] context 正負の原assertion集計先です。
	 * @param[in] one 一件だけを選択する場合trueです。
	 * @param[in] mixed 別deviceの既存Driver Store候補を一件併せて選ぶ場合trueです。
	 * @param[in] expectedVersion 空は元metadata、指定時は原版への等値を要求します。
	 * @return 実行意思を与えた元opaque candidate identity集合です。
	 */
	static std::vector<std::wstring> selectInstallIntents(
		MainWindow &window, test::TestContext &context, const bool one, const bool mixed,
		const std::wstring_view expectedVersion = {})
	{
		std::vector<std::wstring> result ;	// 元check集合を独立期待へ固定します。
		// 混在条件だけは既存の同版候補も表示して明示選択します。
		if( mixed) {
			window.showRecommendedOnly_ = false ;
			window.populateCandidates( window.candidates_) ;
		}

		// 元workerが発行した未検査参照だけを元順に選択します。
		for( std::size_t index{}; index < window.candidates_.size(); ++index) {
			const auto &candidate = window.candidates_[index] ;	// 同scanの元候補です。
			// 未取得参照以外や、明示一件条件の後続を無断追加しません。
			if( candidate.preparationTargetIdentity.empty() || ((one || mixed) && !result.empty())) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context, !candidate.installable && !candidate.current &&
											candidate.action == DriverAction::NONE &&
											candidate.version == expectedVersion &&
											!candidate.recommended &&
											window.isSelectableCandidate( candidate)) ;
			// 明示指定が必要な候補は詳細と同じAPIで一件へ結合します。
			if( mixed || !window.treeRows_[window.candidateRowIndexes_[index]].hasCandidateChoice) {
				DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( index)) ;
			}

			const auto item = window.candidateItems_[index] ;	// 通常device行の実handleです。
			DRIVERCRATE_EXPECT(
				context,
				item != nullptr &&
					window.treeRows_[window.candidateRowIndexes_[index]].hasCandidateChoice) ;
			TreeView_SetCheckState( window.updateTree_, item, TRUE) ;
			window.handleTreeCheckChange( item, true) ;
			DRIVERCRATE_EXPECT( context, window.candidateSelected_[index]) ;
			result.push_back( candidate.identity) ;
		}

		// 既検証候補の混在は同scanの実Driver Store候補へだけ結びます。
		if( mixed && !result.empty()) {
			const auto pending = std::ranges::find( window.candidates_, result.front(),
												   &UpdateCandidate::identity) ;	// 元参照です。
			const auto ready = std::ranges::find_if( window.candidates_, [&]( const auto &candidate) {
				return candidate.installable && !candidate.current &&
					   candidate.deviceIdentity != pending->deviceIdentity ;
			}) ; // 別deviceの元Provider候補です。
			DRIVERCRATE_EXPECT( context, ready != window.candidates_.end()) ;
			// 元候補が存在しない場合に合成ready行で成功を補いません。
			if( ready != window.candidates_.end()) {
				const auto index = static_cast<std::size_t>(
					ready - window.candidates_.begin()) ;	// 同scanの元位置です。
				DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( index)) ;
				TreeView_SetCheckState( window.updateTree_, window.candidateItems_[index], TRUE) ;
				window.handleTreeCheckChange( window.candidateItems_[index], true) ;
				result.push_back( ready->identity) ;
			}
		}

		// 独立期待も元表示位置へ揃え、WUAと末尾追加参照の選択順を取り違えません。
		std::ranges::sort( result, [&window]( const auto &left, const auto &right) {
			return std::ranges::find( window.candidates_, left, &UpdateCandidate::identity) <
				   std::ranges::find( window.candidates_, right, &UpdateCandidate::identity) ;
		}) ;

		window.updateCommandState() ;
		DRIVERCRATE_EXPECT( context, !result.empty() &&
										window.checkedCandidateIndexes().size() == result.size() &&
										IsWindowEnabled( window.installButton_)) ;
		return result ;
	}
	/**
	 * @brief 主画面の規約案内と、旧選択・差替えsnapshotの非実行を確認します。
	 * @param[in,out] window 同scanの元planと実checkboxを保持する完全fake画面です。
	 * @param[in,out] context 原assertionの集計先です。
	 * @note 正常二件の選択だけに適用し、実workerへ取得・導入を要求しません。
	 */
	static void verifyInlineInstallTerms( MainWindow &window, test::TestContext &context)
	{
		wchar_t caption[128]{} ;	// 主画面の実Install文言です。
		wchar_t note[1024]{} ;		// 選択中の規約案内だけを読みます。
		GetWindowTextW( window.installButton_, caption, 128) ;
		GetWindowTextW( window.installTermsNote_, note, 1024) ;
		DRIVERCRATE_EXPECT( context, std::wstring_view{caption} == L"同意してインストール(&I)" &&
										std::wstring_view{note}.find( L"選択中 2 件。") == 0U &&
										std::wstring_view{note}.find( L"メーカー規約に同意") !=
											std::wstring_view::npos &&
										IsWindowEnabled( window.installTermsButton_) != FALSE &&
										window.presentedInstallTerms_) ;
		// 案内が欠けた場合に試験側の合成値から承認を補いません。
		if( !window.presentedInstallTerms_) {
			return ;
		}

		const auto original = *window.presentedInstallTerms_ ;	// 未承認の元案内値です。
		DRIVERCRATE_EXPECT(
			context, window.matchesPresentedInstallTerms( original) &&
						 std::ranges::none_of( original.decisions, []( const auto &decision) {
							 return decision.eulaAccepted || decision.prerequisitesConfirmed ||
									decision.restrictedNetworkApproved ;
						 })) ;
		// 原全文・revision・出典・token・対象・選択・session・予算の差を個別に拒否します。
		for( unsigned mode{}; mode < 12U; ++mode) {
			auto  changed = original ;							// 一つの差だけを与える有限な比較値です。
			auto &target  = changed.decisions.front().target ;	// 元の共有配布物です。
			// 公開fieldを省かず、異なるsnapshotへのInstall同意を一つずつ拒否します。
			switch( mode) {
				// 同revisionの本文差替えです。
				case 0:
					target.eulaText += L"Changed." ;
					break ;

				// 本文未取得です。
				case 1:
					target.eulaText.clear() ;
					break ;

				// 改訂差替えです。
				case 2:
					target.eulaRevision += L"Changed" ;
					break ;

				// 出典主体差替えです。
				case 3:
					target.eulaSourceSubject += L"Changed" ;
					break ;

				// 共有group差替えです。
				case 4:
					++target.sharedEulaToken ;
					break ;

				// 未解決条件への差替えです。
				case 5:
					target.terms = OfficialPreparationTerms::UNRESOLVED ;
					break ;

				// 未選択対象への取得許可変更です。
				case 6:
					changed.decisions.front().acquire = false ;
					break ;

				// 別scanの値です。
				case 7:
					++changed.scanSessionId ;
					break ;

				// 別計画の値です。
				case 8:
					++changed.planId ;
					break ;

				// 選択集合の欠落です。
				case 9:
					changed.installIntentIdentities.pop_back() ;
					break ;

				// 元予算の差替えです。
				case 10:
					--changed.limits.maximumFileBytes ;
					break ;

				// 新たな具体的前提です。
				default:
					target.requiresPrerequisiteConfirmation =
						!target.requiresPrerequisiteConfirmation ;
					break ;
			}

			DRIVERCRATE_EXPECT( context, !window.matchesPresentedInstallTerms( changed)) ;
		}

		const auto indexes = window.checkedCandidateIndexes() ;			// 元二件の実check位置です。
		const auto item	   = window.candidateItems_[indexes.back()] ;	// 同deviceの実checkboxです。
		TreeView_SetCheckState( window.updateTree_, item, FALSE) ;
		window.handleTreeCheckChange( item, false) ;
		DRIVERCRATE_EXPECT( context,
						   !window.matchesPresentedInstallTerms( original) &&
							   window.presentedInstallTerms_ &&
							   window.presentedInstallTerms_->installIntentIdentities.size() == 1U) ;
		window.presentedInstallTerms_ = original ;
		window.beginInstall() ;
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::SCAN_READY &&
										!window.presentedInstallTerms_ &&
										window.preparationApproval_.operationId == 0U) ;
		TreeView_SetCheckState( window.updateTree_, item, TRUE) ;
		window.handleTreeCheckChange( item, true) ;
		DRIVERCRATE_EXPECT( context, window.presentedInstallTerms_ &&
										window.matchesPresentedInstallTerms( original) &&
										IsWindowEnabled( window.installButton_) != FALSE) ;
		window.presentedInstallTerms_->decisions.front().target.eulaText += L"Changed." ;
		window.beginInstall() ;
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::SCAN_READY &&
										!window.presentedInstallTerms_ &&
										window.preparationApproval_.operationId == 0U) ;
		window.updateCommandState() ;
	}
	/**
	 * @brief 取消しとして選択を解除し、画面内案内と未承認値を破棄します。
	 * @param[in,out] window 元選択と実controlを保持する完全fake画面です。
	 * @param[in,out] context 原assertionの集計先です。
	 */
	static void clearInlineInstallTerms( MainWindow &window, test::TestContext &context)
	{
		SendMessageW( window.window_, WM_COMMAND, IDC_CLEAR_SELECTION, 0) ;
		DRIVERCRATE_EXPECT( context, !window.presentedInstallTerms_ &&
										window.checkedCandidateIndexes().empty() &&
										!IsWindowEnabled( window.installButton_) &&
										(GetWindowLongPtrW( window.installTermsNote_, GWL_STYLE) &
										 WS_VISIBLE) == 0) ;
	}
	/**
	 * @brief 元選択にないtargetを取得する承認を同workerへ直接送り、私有照合を検査します。
	 * @param[in,out] window 元planとworkerを保持する内部Windowです。
	 * @param[in] original 明示選択した一候補です。
	 * @return 実queueが要求を受理した場合trueです。製品の承認照合はworkerが行います。
	 */
	static bool requestUnselectedIntent( MainWindow &window, const std::wstring &original)
	{
		const auto *plan = window.controller_.preparationPlan() ;	// 元workerが発行した計画です。
		OfficialPreparationApproval approval{.operationId =
												 window.controller_.activeOperationId() + 1U,
											 .scanSessionId = plan->scanSessionId,
											 .planId		= plan->planId,
											 .limits		= plan->limits} ;	// 不正取得集合です。
		approval.installIntentIdentities.push_back( original) ;
		// 元選択外の別recordまで取得する改ざんを明示し、成功へ補完しません。
		for( const auto &target : plan->targets) {
			approval.decisions.push_back(
				{.target	   = target,
				 .acquire	   = true,
				 .eulaAccepted = target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED,
				 .prerequisitesConfirmed = target.requiresPrerequisiteConfirmation}) ;
		}

		return window.worker_->requestPreparation( approval) ;
	}
	/**
	 * @brief 元未取得identityの直接導入をcontrollerが拒否することを確認します。
	 * @param[in,out] window 元参照と同scanを保持する内部Windowです。
	 * @param[in] identity 明示checkした未検査参照です。
	 * @return 実controllerの原拒否結果です。検査や導入は実行しません。
	 */
	static BeginResult rejectDirectIntentInstall( MainWindow &window, const std::wstring &identity)
	{
		const std::array identities{identity} ;	// 一つの元未検査選択です。
		return window.controller_.beginInstall( window.controller_.scanSessionId(), identities,
											   InstallConfirmation::CONFIRMED) ;
	}
	/**
	 * @brief 検査済みの唯一候補だけを通常行のcheckboxから明示選択します。
	 * @param[in,out] window 同scanの本物行と候補を保持する内部Windowです。
	 * @param[in,out] context Assertionの集計先です。
	 * @param[in] expected 発行された導入可能索引候補数です。
	 * @param[in] multiple 同deviceに複数候補があり自動指定してはいけない条件です。
	 * @param[in] initial 初回候補のfilter表示を検査する場合trueです。
	 * @return 詳細選択の正例へ渡す最初の発行候補indexです。候補なしは候補数です。
	 */
	static std::size_t checkPreparedRows( MainWindow &window, test::TestContext &context,
										 const std::size_t expected, const bool multiple,
										 const bool initial)
	{
		window.showRecommendedOnly_ = initial ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK,
					 initial ? BST_CHECKED : BST_UNCHECKED, 0) ;
		window.populateCandidates( window.candidates_) ;
		DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty()) ;
		// 初回を表示できても推奨一括選択による暗黙の導入対象へは加えません。
		if( initial) {
			SendMessageW( window.window_, WM_COMMAND, IDC_SELECT_ALL_RECOMMENDED, 0) ;
			DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty()) ;
		}

		std::size_t count{} ;							// 元publicationから得た候補だけを数えます。
		std::size_t first = window.candidates_.size() ;	// 詳細用の未発見sentinelです。
		// 原候補の順番を保ち、metadataや無関係なready候補を選択しません。
		for( std::size_t index{}; index < window.candidates_.size(); ++index) {
			const auto &candidate = window.candidates_[index] ;	// 同同期scopeの借用です。
			// 現在観測や未検査情報を検査済みpublicationへ水増ししません。
			if( candidate.providerId != SIGNED_INDEX_PROVIDER_ID || !candidate.installable) {
				continue ;
			}

			++count ;
			first = std::min( first, index) ;
			DRIVERCRATE_EXPECT( context,
							   window.candidateItems_[index] != nullptr &&
								   !window.candidateSelected_[index] &&
								   (!initial || candidate.action == DriverAction::INITIAL_INSTALL)) ;
			// 表示行が存在しなければ、その失敗を保持し無効indexを参照しません。
			if( window.candidateItems_[index] == nullptr ||
			   window.candidateRowIndexes_[index] >= window.treeRows_.size()) {
				continue ;
			}

			const auto &row =
				window.treeRows_[window.candidateRowIndexes_[index]] ;	// 元device行です。
			DRIVERCRATE_EXPECT( context, row.hasCandidateChoice == !multiple) ;
			// 複数候補は詳細を案内し、一候補のようにcheckboxへ結合しません。
			if( multiple) {
				DRIVERCRATE_EXPECT( context, row.status.find( window.loadString(
												IDS_DEVICE_CHOOSE_DETAILS)) != std::wstring::npos) ;
				continue ;
			}

			TreeView_SetCheckState( window.updateTree_, window.candidateItems_[index], TRUE) ;
			window.handleTreeCheckChange( window.candidateItems_[index], true) ;
			DRIVERCRATE_EXPECT( context, window.candidateSelected_[index]) ;
		}

		DRIVERCRATE_EXPECT( context, count == expected && window.checkedCandidateIndexes().size() ==
															 (multiple ? 0U : expected)) ;
		std::cout << "SEARCH_ROW_CHECK expected=" << expected << " publications=" << count
				  << " checked=" << window.checkedCandidateIndexes().size()
				  << " multiple=" << multiple << '\n' ;
		// 取得前情報や他Providerの既存候補へcheckbox判断を伝播しません。
		for( std::size_t index{}; index < window.candidates_.size(); ++index) {
			// 検査済み索引候補以外は明示未選択を保持します。
			if( window.candidates_[index].providerId != SIGNED_INDEX_PROVIDER_ID ||
			   !window.candidates_[index].installable) {
				DRIVERCRATE_EXPECT( context, !window.candidateSelected_[index]) ;
			}
		}

		window.updateCommandState() ;
		DRIVERCRATE_EXPECT( context, (IsWindowEnabled( window.installButton_) != FALSE) ==
										(!multiple && expected != 0U)) ;
		return first ;
	}
	/**
	 * @brief 元Provider集合から索引だけを明示無効にします。
	 * @param[in,out] window 同fixtureの通常Windowです。
	 */
	static void disableIndex( MainWindow &window)
	{
		window.enabledProviderIds_ = {std::wstring{DRIVER_STORE_PROVIDER_ID}} ;
	}
	/**
	 * @brief 通常の結果buttonが表示する非機密本文を所有copyで観測します。
	 * @param[in] window 同operationの通常Windowです。
	 * @return URL/ID/pathを追加しない製品本文です。
	 */
	static std::wstring indexResultText( const MainWindow &window)
	{
		return window.preparationResultText_ ;
	}
	/**
	 * @brief 元planに結合する唯一の索引候補が通常の選択guardを通ることを確認します。
	 * @param[in] window 通常scan終端を受理した同じWindowです。
	 * @param[in,out] context 候補数と選択可能性の原assertionです。
	 */
	static void verifyUnchangedCandidate( const MainWindow &window, test::TestContext &context)
	{
		const auto *plan =
			// 元workerが発行した同scan計画です。
			window.controller_.preparationPlan() ;
		DRIVERCRATE_EXPECT( context, plan && plan->targets.size() == 1U) ;
		// 元計画がない場合は任意候補を対象へ補完しません。
		if( !plan || plan->targets.size() != 1U) {
			return ;
		}

		std::size_t matched{} ;	// 一つの元targetへ結合する候補だけを数えます。
		// 通常画面が受理した全候補を元plan identityへ照合します。
		for( const auto &candidate : window.candidates_) {
			// 関係しない現在行や他Provider候補を索引候補へ数えません。
			if( candidate.preparationTargetIdentity != plan->targets.front().identity) {
				continue ;
			}

			++matched ;
			DRIVERCRATE_EXPECT( context, candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
											!candidate.current &&
											window.isSelectableCandidate( candidate)) ;
		}

		DRIVERCRATE_EXPECT( context, matched == 1U) ;
	}
	/**
	 * @brief 原時刻拒否だけの説明と既存HTTP/診断表示を決定的に確認します。
	 * @param[in] window 非通信factoryで作成した通常画面です。
	 * @param[in,out] context 正負例の集計先です。
	 */
	static void verifyRefreshTimeReason( const MainWindow &window, test::TestContext &context)
	{
		IndexScanSummary summary ;	// 実通信や実storeへ接続しない表示用入力です。
		summary.refresh =
			IndexRefreshSummary{.status			= IndexRefreshStatus::MANIFEST_REJECTED,
								.httpStatus		= 200U,
								.manifestStatus = SignedIndexManifestStatus::INVALID_TIME} ;
		const auto reason =
			// 製品resourceの原文です。
			window.loadString( IDS_INDEX_REFRESH_INVALID_TIME) ;
		const auto text =
			// 製品と同じformatterだけです。
			window.formatIndexRefreshSummary( summary) ;
		DRIVERCRATE_EXPECT( context, !reason.empty() && text.find( reason) != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, text.find( window.formatResource(
										IDS_INDEX_REFRESH_FACTS, L"200")) != std::wstring::npos &&
										text.find( L"0x00000000") != std::wstring::npos &&
										text.find( window.loadString( IDS_INDEX_REFRESH_REJECTED)) !=
											std::wstring::npos) ;
		// 他の原拒否へ時刻理由を付けず、元診断の表示を維持します。
		for( const auto status : {SignedIndexManifestStatus::INVALID_SIGNATURE,
								 SignedIndexManifestStatus::INVALID_MANIFEST}) {
			summary.refresh->manifestStatus = status ;
			const auto other = window.formatIndexRefreshSummary( summary) ;	// 別の元拒否です。
			DRIVERCRATE_EXPECT(
				context, other.find( reason) == std::wstring::npos &&
							 other.find( window.formatResource( IDS_INDEX_REFRESH_FACTS, L"200")) !=
								 std::wstring::npos) ;
		}

		summary.refresh->manifestStatus.reset() ;
		DRIVERCRATE_EXPECT( context, window.formatIndexRefreshSummary( summary).find( reason) ==
										std::wstring::npos) ;
		summary.refresh.reset() ;
		DRIVERCRATE_EXPECT( context, window.formatIndexRefreshSummary( summary).empty()) ;
	}
	/**
	 * @brief 製品と同じmenu構築から実項目の名称と有効状態を検査します。
	 * @param[in] window 同UI threadの本物Windowです。
	 * @param[in,out] context 実control検査の集計先です。
	 * @param[in] enabled この固定入力で期待する閲覧可否です。
	 */
	static void inspectRefreshRoute( const MainWindow &window, test::TestContext &context,
									const bool enabled)
	{
		const HMENU menu = CreatePopupMenu() ;	// 同scopeで破棄する実menuです。
		DRIVERCRATE_EXPECT( context, menu != nullptr) ;
		// Menu生成失敗を私有本文の一致で補いません。
		if( menu == nullptr) {
			return ;
		}

		window.appendIndexRefreshMenu( menu) ;
		wchar_t	   text[128]{} ;	// 実menu項目から読み戻す有限文字列です。
		// 製品helperが追加した同じ実menu項目だけを読み戻します。
		const auto length =
			GetMenuStringW( menu, IDM_INDEX_REFRESH_DETAILS, text, 128, MF_BYCOMMAND) ;
		// 同commandの灰色状態を私有boolではなく実menuから取得します。
		const auto state = GetMenuState( menu, IDM_INDEX_REFRESH_DETAILS, MF_BYCOMMAND) ;
		DRIVERCRATE_EXPECT( context, length > 0 &&
										std::wstring_view{text} ==
											window.loadString( IDS_INDEX_REFRESH_DETAILS) &&
										state != static_cast<UINT>( -1) &&
										((state & (MF_GRAYED | MF_DISABLED)) == 0U) == enabled) ;
		DRIVERCRATE_EXPECT(
			context, IsWindowVisible( window.providerSourcesButton_) != FALSE &&
						 (!enabled || IsWindowEnabled( window.providerSourcesButton_) != FALSE)) ;
		DestroyMenu( menu) ;
	}
	/**
	 * @brief 実menuと同じ独立commandから確定summaryを開きます。
	 * @param[in,out] window 同scopeの本物Windowです。
	 */
	static void openRefreshDetails( MainWindow &window)
	{
		SendMessageW( window.window_, WM_COMMAND, IDM_INDEX_REFRESH_DETAILS, 0) ;
	}
	/**
	 * @brief 実dialog呼出しが渡した生成本文を内部観測へcopyします。
	 * @param[in] window 同dialogを同期表示しているUI threadのWindowです。
	 * @return 埋込NULも保持する実生成本文です。可視証拠ではありません。
	 */
	static std::wstring refreshDetailGenerated( const MainWindow &window)
	{
		return window.testIndexRefreshDetailBody_ ;
	}
	/**
	 * @brief 元publicationの同版候補を実Tree行へ照合し推奨一括選択対象外を確認します。
	 * @param[in,out] window 元scan/取得終端を受理した本物Windowです。
	 * @param[in,out] context 同一入力の集計先です。
	 */
	static void inspectReinstallRow( MainWindow &window, test::TestContext &context)
	{
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
		window.handleRecommendedFilterChange() ;
		std::size_t sameVersionRows{} ;								// 元publicationだけの同版行数です。
		std::size_t sameVersionIndex = window.candidates_.size() ;	// 明示指定する元候補です。
		// 同じ通常候補集合を確認し、合成候補は追加しません。
		for( std::size_t index{}; index < window.candidates_.size(); ++index) {
			const auto &candidate = window.candidates_[index] ;	// 次dispatchまでの借用です。
			// 通常現在行を新しい同版publicationへ数えません。
			if( candidate.providerId != SIGNED_INDEX_PROVIDER_ID || !candidate.installable) {
				continue ;
			}

			++sameVersionRows ;
			sameVersionIndex = index ;
			DRIVERCRATE_EXPECT(
				context, candidate.action == DriverAction::REINSTALL &&
							 candidate.version == L"1.0.0.0" && !candidate.recommended &&
							 candidate.defaultPreference == CandidateDefaultPreference::NONE &&
							 !window.candidateSelected_[index] &&
							 window.candidateItems_[index] != nullptr) ;
			const auto &row =
				window.treeRows_[window.candidateRowIndexes_[index]] ;	// 表示と同じ行です。
			DRIVERCRATE_EXPECT( context,
							   row.currentVersion == L"1.0.0.0" &&
								   row.candidateVersion == window.loadString( IDS_VALUE_UNKNOWN) &&
								   !row.hasCandidateChoice && !row.explicitCandidateChoice &&
								   row.status.find( window.loadString( IDS_ACTION_REINSTALL)) ==
									   std::wstring::npos) ;
			TreeView_EnsureVisible( window.updateTree_, window.candidateItems_[index]) ;
			RECT bounds{} ;	// 同版行の実可視領域です。
			DRIVERCRATE_EXPECT( context, TreeView_GetItemRect( window.updateTree_,
															 window.candidateItems_[index], &bounds,
															 FALSE) != FALSE &&
											bounds.bottom > bounds.top) ;
		}

		SendMessageW( window.window_, WM_COMMAND, IDC_SELECT_ALL_RECOMMENDED, 0) ;
		DRIVERCRATE_EXPECT( context, sameVersionRows == 1U &&
										window.checkedCandidateIndexes().empty() &&
										IsWindowEnabled( window.installButton_) == FALSE) ;
		// 詳細の明示指定と同じ操作後だけ、同版を行と選択へ結びます。
		if( sameVersionIndex < window.candidates_.size()) {
			DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( sameVersionIndex)) ;
			// 同deviceの明示指定後の行です。
			const auto &selected = window.treeRows_[window.candidateRowIndexes_[sameVersionIndex]] ;
			DRIVERCRATE_EXPECT( context,
							   selected.hasCandidateChoice && selected.explicitCandidateChoice &&
								   selected.currentVersion == L"1.0.0.0" &&
								   selected.candidateVersion == L"1.0.0.0" &&
								   selected.status.find( window.loadString( IDS_ACTION_REINSTALL)) !=
									   std::wstring::npos &&
								   window.checkedCandidateIndexes() ==
									   std::vector<std::size_t>{sameVersionIndex} &&
								   IsWindowEnabled( window.installButton_) != FALSE) ;
		}
	}
	/**
	 * @brief 実worker eventを順にdispatchし、指定終端だけを観測前に所有します。
	 * @param[in,out] window 同operationの本物Windowです。
	 * @param[in] kind 待つ実終端kindです。
	 * @param[out] unexpectedScans 非nullは待つ種類以外のscan終端数を加算します。同期中だけ借用します。
	 * @param[out] trace 非nullは受信した種類とoperationを最大64件保存します。同期中だけ借用します。
	 * @return 五秒以内の実終端、または未到達nulloptです。
	 */
	static std::optional<WorkerEvent> takeIndexTerminal( MainWindow &window, WorkerEventKind kind,
														std::size_t *unexpectedScans = nullptr,
														IndexTerminalTrace *trace	 = nullptr)
	{
		const auto deadline =
			// 同workerの有限待機です。
			std::chrono::steady_clock::now() + std::chrono::seconds{5} ;
		// 同workerの有限queueを順番に処理し、指定終端または期限で終了します。
		while( std::chrono::steady_clock::now() < deadline) {
			// 実queueから受信した通知だけを通常dispatchへ渡します。
			for( auto &event : window.worker_->takeEvents()) {
				// 有限な受信順だけを保持し、本文・URL・端末IDを観測へ含めません。
				if( trace != nullptr) {
					// 容量不足を黙って正常観測にしません。
					if( trace->count < trace->kinds.size()) {
						trace->kinds[trace->count]		  = event.kind ;
						trace->operations[trace->count++] = event.operationId ;
					} else {
						trace->overflow = true ;
					}
				}

				// 導入待ち中の自動scan終端を正常導入へ紛れ込ませず独立観測します。
				if( unexpectedScans != nullptr && event.kind == WorkerEventKind::SCAN_COMPLETED &&
				   kind != WorkerEventKind::SCAN_COMPLETED) {
					++*unexpectedScans ;
				}

				// 同期観測へ必要な終端だけをdispatch前に返します。
				if( event.kind == kind) {
					return std::move( event) ;
				}

				window.processWorkerEvent( event) ;
			}

			std::this_thread::sleep_for( std::chrono::milliseconds{2}) ;
		}

		return std::nullopt ;
	}
	/**
	 * @brief 元planへ対象別承認を結び、実controllerとworkerで取得を開始します。
	 * @param[in,out] window 元scanの候補とplanを保持する本物Windowです。
	 * @param[in] plan 元workerが発行したplanです。
	 * @return 同controllerの承認と実queue登録の双方が成功した場合trueです。
	 */
	static bool acquireIndexPlan( MainWindow &window, const OfficialPreparationPlan &plan)
	{
		OfficialPreparationApproval approval{
			0U, plan.scanSessionId, plan.planId, plan.limits, {}} ;	// 元planの完全copyです。
		// 固定planの全対象へ明示取得判断を一つずつ結びます。
		for( const auto &target : plan.targets) {
			approval.decisions.push_back( {target, true, false, false, false}) ;
		}

		const auto begin =
			// 元scanと新取得operationを区別します。
			window.controller_.beginPreparation( approval) ;
		// Controllerが拒否した承認をworkerへ送信しません。
		if( !begin.accepted) {
			return false ;
		}

		window.preparationApproval_	 = approval ;
		window.preparationCompleted_ = 0U ;
		return window.worker_->requestPreparation( approval) ;
	}
	/**
	 * @brief 元本物MainWindowの通常取得commandから確認dialogを開始します。
	 * @param[in,out] window 原scan/planを保持する実Windowです。
	 */
	static void reviewIndexPlan( MainWindow &window)
	{
		SendMessageW( window.window_, WM_COMMAND, IDC_PREPARATION, 0) ;
	}
	/**
	 * @brief 通常取得commandが保持した元対象別承認を同UI threadへ貸します。
	 * @param[in] window 原scan/planと承認を保持する実Windowです。
	 * @return 次の取得commandまたはworker dispatchまで有効な原承認です。
	 */
	static const OfficialPreparationApproval &indexApproval( const MainWindow &window)
	{
		return window.preparationApproval_ ;
	}
	/**
	 * @brief 元planの全文/出典/改訂/対象差替えを実controllerで拒否します。
	 * @param[in,out] window 元scanの実Windowです。
	 * @param[in,out] context 元assertionの集計先です。
	 * @param[in] plan 改変前のworker計画です。
	 */
	static void rejectIndexConsentChanges( MainWindow &window, test::TestContext &context,
										  const OfficialPreparationPlan &plan)
	{
		// 原期待T03/T04/T05と全文差を別の一要因に固定します。
		for( unsigned condition = 0; condition < 4U; ++condition) {
			// 元取得全文と条件への本物dialogの明示判断です。
			OfficialPreparationApproval approval{
				0U, plan.scanSessionId, plan.planId, plan.limits, {}} ;
			// 原全対象の権限集合を維持したまま一fieldだけ変更します。
			for( const auto &target : plan.targets) {
				approval.decisions.push_back(
					{target, true, target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED,
					 target.requiresPrerequisiteConfirmation, false}) ;
			}

			// 一要因のsnapshot差だけを元controllerへ送ります。
			switch( condition) {
				// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
				case 0:
					approval.decisions.front().target.eulaText += L"changed" ;
					break ;

				// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
				case 1:
					approval.decisions.front().target.eulaSourceSubject += L"changed" ;
					break ;

				// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
				case 2:
					approval.decisions.front().target.eulaRevision += L"changed" ;
					break ;

				// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
				default:
					++approval.decisions.front().target.deviceCount ;
					break ;
			}

			const auto begin =
				// 元一field差の拒否です。
				window.controller_.beginPreparation( approval) ;
			DRIVERCRATE_EXPECT( context, !begin.accepted && window.controller_.state() ==
															   ApplicationState::SCAN_READY) ;
			// 原subcase IDを同じ実controller拒否へ結び、別の成功結果を合成しません。
			const std::array ids{"T01-TEXT", "T03", "T04", "T05"} ;
			std::cout << "FORMAT_CONSENT_REJECT case=" << ids[condition]
					  << " rejected=" << !begin.accepted << " scanReady="
					  << (window.controller_.state() == ApplicationState::SCAN_READY) << '\n' ;
		}
	}
	/**
	 * @brief 本体発行eventを既存私有dispatchへ通します。
	 * @param[in,out] window 同operationの本物Windowです。
	 * @param[in] event Workerから受けた所有通知です。
	 */
	static void dispatchIndex( MainWindow &window, const WorkerEvent &event)
	{
		window.processWorkerEvent( event) ;
	}
	/**
	 * @brief 結果確定後の旧scan要求を本物worker queueへ送ります。
	 * @param[in,out] window 結果を保持する同じ本物Windowです。
	 * @param[in] operationId 元導入より後の有限な拒否要求IDです。
	 * @param[in] scanSessionId 完了により失効した元scanです。
	 * @param[in] identities 元publicationと元選択のidentityです。
	 * @return 実queueへ登録された場合trueです。成功結果や権限は構築しません。
	 */
	static bool requestExpiredIndexInstall( MainWindow &window, OperationId operationId,
										   ScanSessionId				 scanSessionId,
										   std::span<const std::wstring> identities)
	{
		return window.worker_->requestInstall( operationId, scanSessionId, identities, nullptr,
											  InstallProtectionMode::WINDOWS_RESTORE_POINT) ;
	}
	/**
	 * @brief 元scanに保持した全candidateを同期観測へ貸し出します。
	 * @param[in] window 同じUI threadの所有Windowです。
	 * @return 次のdispatchまでだけ有効な候補集合です。
	 */
	static std::span<const UpdateCandidate> indexCandidates( const MainWindow &window)
	{
		return window.candidates_ ;
	}
	/**
	 * @brief 通常rowの未選択と元candidateへのcheckbox対応を確認します。
	 * @param[in,out] window Publicationを受理した本物Windowです。
	 * @param[in,out] context Assertion集計先です。
	 * @param[in] identities 元publicationの選択可能candidateだけです。
	 */
	static void selectIndexCandidates( MainWindow &window, test::TestContext &context,
									  std::span<const std::wstring> identities)
	{
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
		window.handleRecommendedFilterChange() ;
		// 元publicationの全candidateを同じ実Tree rowへ照合します。
		for( const auto &identity : identities) {
			const auto found = std::ranges::find( window.candidates_, identity,
												 &UpdateCandidate::identity) ;	// 元opaque IDです。
			DRIVERCRATE_EXPECT( context, found != window.candidates_.end()) ;
			// 欠損した元candidateを任意の先頭rowへ補完しません。
			if( found == window.candidates_.end()) {
				continue ;
			}

			const auto index = static_cast<std::size_t>(
				found - window.candidates_.begin()) ;	// 同rowの有限indexです。
			DRIVERCRATE_EXPECT( context,
							   !window.candidateSelected_[index] && found->installable &&
								   !found->recommended &&
								   found->defaultPreference == CandidateDefaultPreference::NONE &&
								   window.candidateItems_[index] != nullptr) ;
			DRIVERCRATE_EXPECT(
				context, !window.treeRows_[window.candidateRowIndexes_[index]].status.empty()) ;
			DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( index)) ;
			TreeView_SetCheckState( window.updateTree_, window.candidateItems_[index], TRUE) ;
			window.handleTreeCheckChange( window.candidateItems_[index], true) ;
			DRIVERCRATE_EXPECT( context, window.candidateSelected_[index]) ;
		}

		window.updateCommandState() ;
		DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().size() == identities.size() &&
										(IsWindowEnabled( window.installButton_) != FALSE) ==
											!identities.empty()) ;
	}
	/**
	 * @brief 同じ実確認dialogとworker requestを使って導入操作を開始します。
	 * @param[in,out] window 元選択を保持する本物Windowです。
	 */
	static void beginIndexInstall( MainWindow &window)
	{
		window.beginInstall() ;
	}
	/**
	 * @brief 実Buttonと同じWM_COMMANDを本物Windowへ送り、製品routingを確認します。
	 * @param[in,out] window 同じ元選択とworkerを保持するWindowです。
	 */
	static void beginIndexInstallCommand( MainWindow &window)
	{
		SendMessageW( window.window_, WM_COMMAND, MAKEWPARAM( IDC_INSTALL, BN_CLICKED), 0) ;
	}
	/**
	 * @brief 元現在行の版/日付を過去scanの観測としてcopyします。
	 * @param[in] window 同UI threadの元scan行を保持するWindowです。
	 * @return 現在行だけの元identity/版/日付です。実状態の再照会を行いません。
	 */
	static std::vector<std::wstring> currentIndexScanFacts( const MainWindow &window)
	{
		std::vector<std::wstring> facts ;	// 元scanで現在行だった事実だけを保持します。
		// 有限な元候補から現在観測だけを集め、導入API成功で版を作りません。
		for( const auto &candidate : window.candidates_) {
			// 更新候補の予定版を新しい現在版へ数えません。
			if( candidate.current) {
				facts.push_back( candidate.identity + L"\n" + candidate.version + L"\n" +
								candidate.driverDate) ;
			}
		}

		return facts ;
	}
	/**
	 * @brief 実TreeView本文と結果columnを同じ候補順でcopyします。
	 * @param[in] window 同UI threadで結果を保持するWindowです。
	 * @param[in,out] context 元assertionの集計先です。
	 * @return 実control本文/結果columnの交互snapshotです。人工行の32766文字上限を確認します。
	 */
	static std::vector<std::wstring> indexResultView( const MainWindow  &window,
													 test::TestContext &context)
	{
		std::vector<std::wstring> view ;	// 結果modelと実controlの両方を保存します。
		// 有限な元候補を同順で読み、未取得行を他の成功本文で補完しません。
		for( std::size_t index = 0U; index < window.candidates_.size(); ++index) {
			DRIVERCRATE_EXPECT( context,
							   index < window.candidateItems_.size() &&
								   window.candidateItems_[index] != nullptr &&
								   index < window.candidateRowIndexes_.size() &&
								   window.candidateRowIndexes_[index] < window.treeRows_.size()) ;
			// 元行の対応が失われた場合は当該結果を未取得へ残します。
			if( index >= window.candidateItems_.size() || window.candidateItems_[index] == nullptr ||
			   index >= window.candidateRowIndexes_.size() ||
			   window.candidateRowIndexes_[index] >= window.treeRows_.size()) {
				continue ;
			}

			std::vector<wchar_t> text( 32768U) ;	// 有限な人工行本文の全終端を受けます。
			TVITEMW				 item{} ;			// 同Windowの実controlへの同期借用です。
			item.mask		= TVIF_TEXT ;
			item.hItem		= window.candidateItems_[index] ;
			item.pszText	= text.data() ;
			item.cchTextMax = static_cast<int>( text.size()) ;
			const bool read =
				// 元取得結果です。
				TreeView_GetItem( window.updateTree_, &item) != FALSE ;
			DRIVERCRATE_EXPECT( context,
							   read && text.back() == L'\0' && text[text.size() - 2U] == L'\0') ;
			DRIVERCRATE_EXPECT( context, !std::wstring_view( text.data()).empty()) ;
			view.push_back( window.formatCandidateDetails( window.candidates_[index])) ;
			view.push_back( window.candidateResultTexts_[index]) ;
		}

		return view ;
	}
	/**
	 * @brief 必要Extensionの個別事実を実TreeView本文と結果columnの両方へ照合します。
	 * @param[in] window 同UI threadで結果を保持するWindowです。
	 * @param[in,out] context 未取得と不一致を失敗へ残す集計先です。
	 * @param[in] identity このWindowが保持する元選択candidateの非秘密identityです。同期中だけ借用します。
	 * @param[in] baseStatus 固定caseが要求する基本役割のresource IDです。
	 * @param[in] extensionStatus 固定caseが要求する必要Extensionのresource IDです。
	 * @note 一候補の人工行だけを同期取得し、Windows個別反映の成功を生成しません。
	 */
	static void verifyExtensionRoleRows( const MainWindow &window, test::TestContext &context,
										const std::wstring_view identity, const UINT baseStatus,
										const UINT extensionStatus)
	{
		const auto view =
			// 本物controlと結果columnの元snapshotです。
			indexResultView( window, context) ;
		const auto base = window.loadString( IDS_INDEX_ROLE_BASE) + L": " +
						  // 原caseが要求する基本役割の事実です。
						  window.loadString( baseStatus) ;
		const auto extension = window.loadString( IDS_INDEX_ROLE_EXTENSION) + L": " +
							   // 個別反映へ昇格しない元役割の事実です。
							   window.loadString( extensionStatus) ;
		const auto found = std::ranges::find(
			window.candidates_, identity,
			&UpdateCandidate::identity) ;	// 未選択DriverStore行と元選択計画を区別します。
		DRIVERCRATE_EXPECT( context, found != window.candidates_.end() &&
										view.size() == window.candidates_.size() * 2U &&
										window.controller_.scanSessionId() == 0U &&
										!IsWindowEnabled( window.installButton_)) ;
		// 元選択行を失った結果を別候補の本文へ付け替えません。
		if( found == window.candidates_.end()) {
			return ;
		}

		const auto index =
			// 元候補順の行位置です。
			static_cast<std::size_t>( found - window.candidates_.begin()) ;
		DRIVERCRATE_EXPECT( context, index < view.size() / 2U) ;
		// 未取得のcontrol行を推測した文字列へ補完しません。
		if( index >= view.size() / 2U) {
			return ;
		}

		// 同候補の本文と結果columnを両方確認し、未観測queue成功の表現を拒否します。
		for( std::size_t offset = 0U; offset < 2U; ++offset) {
			const auto &text = view[index * 2U + offset] ;	// 元選択identityの二つの表示だけです。
			DRIVERCRATE_EXPECT( context, text.find( base) != std::wstring::npos &&
											text.find( extension) != std::wstring::npos &&
											text.find( L"queued済み") == std::wstring::npos) ;
		}
	}
	/**
	 * @brief 失効した元candidateへのcheckbox操作を製品handlerで拒否します。
	 * @param[in,out] window 正常導入結果を保持する同じWindowです。
	 * @param[in,out] context 元assertionの集計先です。
	 * @param[in] identities 元scanで選択したcandidateだけです。
	 * @param[in] completed 個別完了の固定期待です。空は全件完了です。
	 */
	static void rejectExpiredIndexSelection( MainWindow &window, test::TestContext &context,
											std::span<const std::wstring> identities,
											std::span<const bool>		  completed = {})
	{
		DRIVERCRATE_EXPECT( context, completed.empty() || completed.size() == identities.size()) ;
		// 人工の期待母数が不一致なら別対象の完了を参照しません。
		if( !completed.empty() && completed.size() != identities.size()) {
			return ;
		}

		// 元selectionの各行へ実check通知を与え、実行拒否と元表示を確認します。
		for( std::size_t ordinal{}; ordinal < identities.size(); ++ordinal) {
			const auto &identity = identities[ordinal] ;	// 固定期待と同順の元candidateです。
			const auto	found	 = std::ranges::find( window.candidates_, identity,
													 &UpdateCandidate::identity) ;	// 元行だけです。
			DRIVERCRATE_EXPECT( context, found != window.candidates_.end()) ;
			// 消えた元行を新しい任意候補へ付け替えません。
			if( found == window.candidates_.end()) {
				continue ;
			}

			const auto index =
				// 元行位置です。
				static_cast<std::size_t>( found - window.candidates_.begin()) ;
			const UINT expected = INDEXTOSTATEIMAGEMASK(
				// 完了だけ未checkです。
				completed.empty() || completed[ordinal] ? 3U : 4U) ;
			DRIVERCRATE_EXPECT(
				context,
				window.treeRows_[window.candidateRowIndexes_[index]].readonlyCheckbox &&
					(TreeView_GetItemState( window.updateTree_, window.candidateItems_[index],
										   TVIS_STATEIMAGEMASK) &
					 TVIS_STATEIMAGEMASK) == expected) ;
			TreeView_SetCheckState( window.updateTree_, window.candidateItems_[index], TRUE) ;
			window.handleTreeCheckChange( window.candidateItems_[index], true) ;
			DRIVERCRATE_EXPECT( context, !found->installable && !window.candidateSelected_[index] &&
											!window.selectDeviceCandidate( index) &&
											(TreeView_GetItemState( window.updateTree_,
																   window.candidateItems_[index],
																   TVIS_STATEIMAGEMASK) &
											 TVIS_STATEIMAGEMASK) == expected) ;
		}

		window.updateCommandState() ;
		DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty() &&
										!IsWindowEnabled( window.installButton_) &&
										IsWindowEnabled( window.scanButton_)) ;
	}
	/**
	 * @brief 旧行の導入commandが対象再選択案内で止まったことを確認します。
	 * @param[in] window 同じ結果一覧を保持するWindowです。
	 * @param[in,out] context 元assertionの集計先です。
	 * @param[in] text 元標準dialogから取得した全文です。
	 */
	static void verifyExpiredIndexPrompt( const MainWindow &window, test::TestContext &context,
										 std::wstring_view text)
	{
		DRIVERCRATE_EXPECT( context, text.find( window.loadString( IDS_SELECTION_REQUIRED)) !=
										std::wstring_view::npos) ;
	}
	/**
	 * @brief 実確認dialogの対象・版・境界・復旧の本文を確認します。
	 * @param[in] window 確認を作成した本物Windowです。
	 * @param[in,out] context Assertion集計先です。
	 * @param[in] text 実標準dialogから読んだ全文です。
	 * @param[in] count 元選択の件数です。
	 * @param[in] initial 真NO_DRIVER由来の初回操作名を確認する場合trueです。
	 */
	static void verifyIndexConfirmation( const MainWindow &window, test::TestContext &context,
										std::wstring_view text, std::size_t count,
										bool initial = false)
	{
		DRIVERCRATE_EXPECT(
			context,
			text.find( window.formatResource( IDS_CONFIRM_PREFIX, std::to_wstring( count))) !=
					std::wstring::npos &&
				(initial ? text.find( window.loadString( IDS_ACTION_INITIAL_INSTALL)) !=
							   std::wstring::npos
						 : text.find( L"0.9.0.0") != std::wstring::npos) &&
				text.find( L"1.2.3.4") != std::wstring::npos &&
				text.find( window.loadString( IDS_RELAXED_DISCOVERY_WARNING)) != std::wstring::npos &&
				text.find( window.loadString( IDS_CONFIRM_SUFFIX)) != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   text.find( L"TESTBUS") == std::wstring::npos &&
							   text.find( L"https://vendor.example/") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, text.find( window.loadString( IDS_INDEX_INSTALLER_WARNING)) !=
										std::wstring::npos) ;
	}
	/**
	 * @brief 元表示にないidentityと旧sessionの導入開始を実controllerで拒否します。
	 * @param[in,out] window 元publicationの有効sessionを保持する本物Windowです。
	 * @param[in,out] context Assertion集計先です。
	 * @param[in] identities 元publicationで発行したIDだけです。
	 */
	static void verifyIndexSelectionBoundary( MainWindow &window, test::TestContext &context,
											 std::span<const std::wstring> identities)
	{
		const std::array unknown{std::wstring{L"index-never-displayed"}} ;	// 未発行opaque IDです。
		DRIVERCRATE_EXPECT( context, !window.controller_
										 .beginInstall( window.controller_.scanSessionId(), unknown,
													   InstallConfirmation::CONFIRMED)
										 .accepted) ;
		DRIVERCRATE_EXPECT( context, !window.controller_
										 .beginInstall( window.controller_.scanSessionId() + 1U,
													   identities, InstallConfirmation::CONFIRMED)
										 .accepted) ;
	}
	/**
	 * @brief 実結果rowと旧sessionの再選択拒否を確認します。
	 * @param[in,out] window 同install終端を受理済みの本物Windowです。
	 * @param[in,out] context Assertion集計先です。
	 * @param[in] result 実workerの個別結果です。
	 * @param[in] retainedRetry 復元開始前の失敗で元選択の再試行を確認する場合trueです。
	 */
	static void verifyIndexResultRows( MainWindow &window, test::TestContext &context,
									  const InstallResult &result, const bool retainedRetry = false)
	{
		// 復元前に止まった対象は元sessionと選択を保ち、同じ条件で再確認できます。
		if( retainedRetry) {
			DRIVERCRATE_EXPECT(
				context, result.restorePointCreation.outcome == OutcomeCode::FAILURE &&
							 result.installOutcome == OutcomeCode::NOT_STARTED &&
							 window.controller_.scanSessionId() != 0U &&
							 window.controller_.state() == ApplicationState::SCAN_READY &&
							 IsWindowEnabled( window.installButton_) &&
							 window.checkedCandidateIndexes().size() == result.updates.size()) ;
		} else {
			DRIVERCRATE_EXPECT( context,
							   (window.controller_.scanSessionId() == 0U ||
								window.controller_.state() == ApplicationState::SCAN_READY) &&
								   !IsWindowEnabled( window.installButton_) &&
								   window.checkedCandidateIndexes().empty()) ;
		}

		// 消費した元Sを表示専用とし、残Uの原許可と表示可否を照合します。
		for( std::size_t index = 0U; index < window.candidates_.size(); ++index) {
			const auto &candidate = window.candidates_[index] ;	// 元行だけです。
			const bool	selected  = std::ranges::any_of( result.updates, [&]( const auto &item) {
				  return item.identity == candidate.identity ;
			  }) ; // 元Sです。
			// 未実行の元Sと元Uを、保持した許可へそれぞれ照合します。
			if( retainedRetry) {
				const bool allowed = window.controller_.isInstallCandidateAllowed(
					candidate.identity) ;	// 元scanの許可です。
				DRIVERCRATE_EXPECT( context, window.candidateSelected_[index] == selected &&
												candidate.installable == allowed &&
												(!selected || allowed)) ;
			} else {
				DRIVERCRATE_EXPECT(
					context, !window.candidateSelected_[index] &&
								 (selected ? !candidate.installable &&
												 !window.controller_.isInstallCandidateAllowed(
													 candidate.identity)
										   : candidate.installable ==
												 window.controller_.isInstallCandidateAllowed(
													 candidate.identity))) ;
			}
		}

		// 元selectionの各結果が同candidateの実rowへだけ反映されたか照合します。
		for( const auto &item : result.updates) {
			const auto found =
				std::ranges::find( window.candidates_, item.identity,
								  &UpdateCandidate::identity) ;	// 結果の元candidateです。
			DRIVERCRATE_EXPECT( context, found != window.candidates_.end()) ;
			// 欠落candidateを別rowの成功へ付け替えません。
			if( found == window.candidates_.end()) {
				continue ;
			}

			const auto index =
				// 元row位置です。
				static_cast<std::size_t>( found - window.candidates_.begin()) ;
			const auto &status =
				window.candidateResultTexts_[index] ;	// 詳細へ表示する同candidateの個別結果です。
			const UINT expectedStatus =
				result.restorePointCreation.outcome == OutcomeCode::FAILURE
					? IDS_RESTORE_POINT_NOT_CREATED
				: item.installOutcome == OutcomeCode::SUCCESS
					? IDS_INSTALL_SUCCEEDED
					: IDS_INSTALL_FAILED ;	// 復旧拒否と実導入失敗を区別する元契約です。
			DRIVERCRATE_EXPECT( context, status.find( window.loadString( expectedStatus)) !=
											std::wstring::npos) ;
			// 元失敗HRESULTも同じ結果rowへ残します。
			if( item.installError != 0) {
				std::wostringstream diagnostic ;	// 同元HRESULTの全32bitを比較します。
				diagnostic << std::uppercase << std::hex << std::setw( 8) << std::setfill( L'0')
						   << static_cast<std::uint32_t>( item.installError) ;
				DRIVERCRATE_EXPECT( context, status.find( diagnostic.str()) != std::wstring::npos) ;
			}
		}
	}
	/**
	 * @brief 所有候補と外部copyの詳細表示を同じ製品整形へ通します。
	 * @param[in] window 元候補と実行結果を保持するWindowです。
	 * @param[in] candidate 同期中だけ借用する候補です。
	 * @return 製品と同じ読取り専用本文です。
	 */
	static std::wstring candidateDetails( const MainWindow &window, const UpdateCandidate &candidate)
	{
		return window.formatCandidateDetails( candidate) ;
	}
	/**
	 * @brief 元二候補の固定役割結果だけを表示専用入力として与えます。
	 * @param[in,out] window 実worker終端により既に失効したWindowです。
	 * @param[in] result 二候補の元部分結果です。変更しません。
	 * @note 役割fixtureは元native結果ではありません。Providerやcontrollerを再実行しません。
	 */
	static void displayRoleHistoryFixture( MainWindow &window, const InstallResult &result)
	{
		auto fixture = result ;	// 実worker結果と分ける表示専用copyです。
		// 不完全な元部分結果から別候補の役割を補完しません。
		if( fixture.updates.size() != 2U) {
			return ;
		}

		// 一件目は基本と必要componentの指定API完了だけを表します。
		fixture.updates[0].requiredRoles = {
			{.role			 = DriverPlanRole::BASE_DRIVER,
			 .ordinal		 = 1U,
			 .stageOutcome	 = OutcomeCode::SUCCESS,
			 .installOutcome = OutcomeCode::SUCCESS,
			 .reflection	 = DriverPlanReflectionState::INSTALL_API_COMPLETED},
			{.role			 = DriverPlanRole::DRIVER_COMPONENT,
			 .ordinal		 = 2U,
			 .stageOutcome	 = OutcomeCode::SUCCESS,
			 .installOutcome = OutcomeCode::SUCCESS,
			 .reflection	 = DriverPlanReflectionState::INSTALL_API_COMPLETED}} ;
		// 二件目は基本完了と必要component失敗を分け、元の失敗codeを保持します。
		fixture.updates[1].requiredRoles = {
			{.role			 = DriverPlanRole::BASE_DRIVER,
			 .ordinal		 = 1U,
			 .stageOutcome	 = OutcomeCode::SUCCESS,
			 .installOutcome = OutcomeCode::SUCCESS,
			 .reflection	 = DriverPlanReflectionState::INSTALL_API_COMPLETED},
			{.role			 = DriverPlanRole::DRIVER_COMPONENT,
			 .ordinal		 = 2U,
			 .stageOutcome	 = OutcomeCode::SUCCESS,
			 .installOutcome = OutcomeCode::FAILURE,
			 .installError	 = result.updates[1].installError,
			 .reflection	 = DriverPlanReflectionState::FAILED}} ;
		window.displayInstallResult( fixture, window.controller_.scanSessionId()) ;
	}
	/**
	 * @brief 保持結果の所有境界と失効した入力の拒否を確認します。
	 * @param[in,out] window 二初回候補の実worker終端を受理したWindowです。
	 * @param[in,out] context 元assertionの集計先です。
	 * @param[in] result 同じ二候補の元部分結果です。
	 */
	static void verifyExpiredHistoryBoundary( MainWindow &window, test::TestContext &context,
											 const InstallResult &result)
	{
		std::vector<std::wstring> identities ;	// 元二候補だけの失効選択です。
		// 同じ所有二候補から外部copyを作り、履歴を他snapshotへ付け替えません。
		for( const auto &item : result.updates) {
			const auto found =
				std::ranges::find( window.candidates_, item.identity,
								  &UpdateCandidate::identity) ;	// 元candidateの所有要素です。
			DRIVERCRATE_EXPECT( context, found != window.candidates_.end()) ;
			// 欠落を先頭候補の履歴で補いません。
			if( found == window.candidates_.end()) {
				continue ;
			}

			identities.push_back( item.identity) ;
			const auto index =
				// 元順です。
				static_cast<std::size_t>( found - window.candidates_.begin()) ;
			DRIVERCRATE_EXPECT( context, found->action == DriverAction::INITIAL_INSTALL &&
											found->providerId == SIGNED_INDEX_PROVIDER_ID &&
											!isCandidateDetailsValid( *found)) ;
			// 同じIDを持つcopyも所有履歴の参照先にせず、不正assessmentは拒否を維持します。
			for( unsigned condition{}; condition < 4U; ++condition) {
				auto external = *found ;	// 製品候補の所有外に置いた試験入力です。
				// 別候補のIDだけから元結果を探索しません。
				if( condition == 1U) {
					external.identity += L"-other" ;
				}
				// 同candidate IDでも別deviceへ結果を移しません。
				else if( condition == 2U) {
					external.deviceIdentity += L"-other" ;
				}
				// READY監査に矛盾するassessmentを検証済みとして表示しません。
				else if( condition == 3U && external.assessment) {
					external.installable				 = true ;
					external.assessment->signature.state = CandidateAssessmentState::REJECTED ;
				}

				const auto text =
					// 拒否本文だけの期待です。
					window.formatCandidateDetails( external) ;
				DRIVERCRATE_EXPECT( context,
								   !isCandidateDetailsValid( external) &&
									   text.find( window.loadString( IDS_ASSESSMENT_INCONSISTENT)) !=
										   std::wstring::npos &&
									   text.find( L"前回の実行結果（履歴）") == std::wstring::npos &&
									   text.find( window.candidateResultTexts_[index]) ==
										   std::wstring::npos) ;
			}

			TreeView_SelectItem( window.updateTree_, window.candidateItems_[index]) ;
			SendMessageW( window.updateTree_, WM_KEYDOWN, VK_SPACE, 0) ;
			SendMessageW( window.updateTree_, WM_KEYUP, VK_SPACE, 0) ;
			DRIVERCRATE_EXPECT( context, !window.selectDeviceCandidate( index) &&
											!window.candidateSelected_[index]) ;
		}

		// 結果のない現在観測やmetadataへ同deviceの他候補の結果を付けません。
		for( std::size_t index{}; index < window.candidates_.size(); ++index) {
			// 未実行の所有候補だけを独立確認します。
			if( window.candidateResultTexts_[index].empty()) {
				DRIVERCRATE_EXPECT( context,
								   window.formatCandidateDetails( window.candidates_[index])
										   .find( L"前回の実行結果（履歴）") == std::wstring::npos) ;
			}
		}

		const std::array completed{true, false} ;	// U21の先頭成功/後続失敗という固定期待です。
		rejectExpiredIndexSelection( window, context, identities, completed) ;
	}
	/**
     * @brief Window生成前に両fakeを設定する。
     * @param[in,out] window 未生成の所有Window。
     * @param[in] state WorkerとUIで共有するfixture。
     */
	static void configure( MainWindow &window, const std::shared_ptr<test::MetadataUiState> &state)
	{
		// 元factoryをworker上で一回だけ呼び、実所属を先に検査します。
		window.testProviderFactory_ = [factory = test::metadataUiProviderFactory( state)] {
			// 所属不一致のworkerを元fakeの成功へ数えません。
			if( !test::observePrivateThread( "fake-worker")) {
				throw std::runtime_error( "private worker desktop mismatch") ;
			}

			++test::privateWorkerObservations ;
			return factory() ;
		} ;
		window.testRestorePointFactory_ = test::metadataUiRestoreFactory( state) ;
	}
	/**
     * @brief 所有Windowの非所有handleを返す。
     * @param[in] window 試験が所有するWindow。
     * @return 作成したHWND。破棄後は再利用しない。
     */
	static HWND handle( const MainWindow &window)
	{
		DWORD		process{} ;	// この実HWNDの所有PIDです。
		const DWORD thread =
			// 実UI threadです。
			GetWindowThreadProcessId( window.window_, &process) ;
		// Windowと起動threadの実所属を照合し、元表示期待は変更しません。
		if( window.window_ && (process != GetCurrentProcessId() || thread != GetCurrentThreadId() ||
							  !test::observePrivateThread( "MainWindow-HWND"))) {
			test::privateLifecycleFailed = true ;
		}

		return window.window_ ;
	}
	/**
     * @brief 状態機械の公開read-only契約を参照する。
     * @param[in] window UI threadの所有Window。
     * @return Windowより短い借用参照。
     */
	static const OperationController &controller( const MainWindow &window)
	{
		return window.controller_ ;
	}
	/**
     * @brief 一覧に保持する現在行と情報行の数を返す。
     * @param[in] window UI threadの所有Window。
     * @return 現在の有限候補数。
     */
	static std::size_t count( const MainWindow &window)
	{
		return window.candidates_.size() ;
	}
	/**
     * @brief 読み上げ用の全行本文をcopyする。
     * @param[in] window 合成候補だけを保持するWindow。
     * @return 実端末情報を含まない全行文字列。
     */
	static std::wstring displayText( const MainWindow &window)
	{
		std::wstring text ;	// 各candidateに対応する全列の読み上げ文字列。
		// 有限の合成候補を表示順で集める。
		for( const auto &row : window.treeRows_) {
			text += row.primaryText + L" | " + row.currentVersion + L" | " + row.candidateVersion +
					L" | " + row.status + L"\n" ;
		}

		return text ;
	}
	/**
     * @brief 第一列だけでなく版・状態の実row値を確認する。
     * @param[in] window 終端済みの合成Window。
     * @param[in,out] context Assertion集計先。
     */
	static void verifyDisplayOnly( const MainWindow &window, test::TestContext &context)
	{
		DRIVERCRATE_EXPECT( context, GetWindowLongPtrW( window.window_, GWLP_USERDATA) ==
										reinterpret_cast<LONG_PTR>( &window)) ;
		DRIVERCRATE_EXPECT( context, window.controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) ;
		DRIVERCRATE_EXPECT( context, window.controller_.scanSessionId() == 0U) ;
		DRIVERCRATE_EXPECT( context, window.candidates_.empty() ||
										window.formatCandidateDetails( window.candidates_.front())
												.find( window.loadString( IDS_MEASUREMENT_EXPIRED)) ==
											std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, !window.showRecommendedOnly_) ;
		DRIVERCRATE_EXPECT( context, std::none_of( window.candidateSelected_.begin(),
												 window.candidateSelected_.end(),
												 []( bool selected) { return selected ; })) ;
		// 現在版・配布版のどちらにもinstall checkboxを残さない。
		for( const auto item : window.candidateItems_) {
			DRIVERCRATE_EXPECT( context, item != nullptr) ;
			DRIVERCRATE_EXPECT(
				context, (TreeView_GetItemState( window.updateTree_, item, TVIS_STATEIMAGEMASK) &
						  TVIS_STATEIMAGEMASK) == 0U) ;
		}

		// 不可能な取得や導入操作を見かけだけ有効にしない。
		for( const HWND control : {window.installButton_, window.selectAllButton_,
								  window.clearSelectionButton_, window.recommendedOnlyCheckbox_}) {
			DRIVERCRATE_EXPECT( context, IsWindowEnabled( control) == FALSE) ;
		}

		DRIVERCRATE_EXPECT( context, IsWindowEnabled( window.scanButton_) != FALSE &&
										GetDlgItem( window.window_, IDC_METADATA_SEARCH) == nullptr) ;
		// KeyboardのSpaceと合成check変更でも、表示専用行を導入選択へ変換しない。
		for( const auto item : window.candidateItems_) {
			TreeView_SelectItem( window.updateTree_, item) ;
			SetFocus( window.updateTree_) ;
			SendMessageW( window.updateTree_, WM_KEYDOWN, VK_SPACE, 0) ;
			SendMessageW( window.updateTree_, WM_KEYUP, VK_SPACE, 0) ;
			TreeView_SetItemState( window.updateTree_, item, INDEXTOSTATEIMAGEMASK( 2),
								  TVIS_STATEIMAGEMASK) ;
			// Focus選択bitをinstall用state imageと混同せず、確認するmaskを明示する。
			DRIVERCRATE_EXPECT(
				context, (TreeView_GetItemState( window.updateTree_, item, TVIS_STATEIMAGEMASK) &
						  TVIS_STATEIMAGEMASK) == 0U) ;
		}

		DRIVERCRATE_EXPECT( context, std::none_of( window.candidateSelected_.begin(),
												 window.candidateSelected_.end(),
												 []( bool selected) { return selected ; })) ;
	}
	/**
     * @brief 分類と三deviceの初期折畳み、情報あり二deviceの件数を照合する。
     * @param[in] window 情報行を受理した合成Window。
     * @param[in,out] context Assertion集計先。
     */
	static void verifyRows( const MainWindow &window, test::TestContext &context)
	{
		unsigned classes{} ;	// 同じ種類に属する三deviceの分類数。
		unsigned devices{} ;	// Opaque identityで分離したdevice数。
		DRIVERCRATE_EXPECT( context, Header_GetItemCount( window.treeHeader_) == 3) ;
		// 分類→deviceの二階層だけを実controlで辿る。
		for( auto category = TreeView_GetRoot( window.updateTree_); category != nullptr;
			category	  = TreeView_GetNextSibling( window.updateTree_, category)) {
			++classes ;
			DRIVERCRATE_EXPECT( context, TreeView_GetItemState( window.updateTree_, category,
															  TVIS_STATEIMAGEMASK) == 0U) ;
			// 同名の別deviceを統合せず、driverやmetadataの子行を残さない。
			for( auto device = TreeView_GetChild( window.updateTree_, category); device != nullptr;
				device		= TreeView_GetNextSibling( window.updateTree_, device)) {
				++devices ;
				DRIVERCRATE_EXPECT( context,
								   TreeView_GetChild( window.updateTree_, device) == nullptr &&
									   TreeView_GetItemState( window.updateTree_, device,
															 TVIS_STATEIMAGEMASK) == 0U) ;
			}
		}

		DRIVERCRATE_EXPECT( context, classes == 1U && devices == 3U &&
										TreeView_GetCount( window.updateTree_) == 4U) ;
		unsigned explicitVersion{} ;	// 配布版を持つdeviceだけを数える。
		// 現在INF版・配布申告版の区別を四列の表示modelでも確認する。
		for( const auto &row : window.treeRows_) {
			// 分類件数を候補数へ読み替えない。
			if( row.kind == MainWindow::TreeRowKind::DEVICE_CLASS) {
				DRIVERCRATE_EXPECT(
					context, row.primaryText.find( L"3") != std::wstring::npos &&
								 row.status ==
									 window.formatResource( IDS_TREE_CLASS_INFORMATION_COUNT, L"2")) ;
				continue ;
			}

			// 同deviceの候補だけを詳細へ残し、表示数を増やさない。
			for( const auto index : row.candidateIndexes) {
				const auto &candidate = window.candidates_[index] ;	// 元の配布情報。
				// 明示配布版がある候補で、現在版へ転記していないことを検証する。
				if( !candidate.current && candidate.metadataDistribution &&
				   !candidate.metadataDistribution->version.empty()) {
					++explicitVersion ;
					DRIVERCRATE_EXPECT( context, row.candidateVersion == L"9.8" &&
													row.currentVersion != L"9.8" &&
													candidate.version.empty()) ;
					DRIVERCRATE_EXPECT( context, window.formatCandidateDetails( candidate).find(
													L"123456") != std::wstring::npos) ;
				}
			}
		}

		DRIVERCRATE_EXPECT( context, explicitVersion == 1U) ;
	}
	/**
	 * @brief 種類別一覧の通常候補を実controlへ直接渡して表示操作を検証する。
	 * @param[in,out] window 通常fake scanを終えたWindow。実Provider操作は行わない。
	 * @param[in,out] context Assertion集計先。
	 */
	static void verifyClassGrouping( MainWindow &window, test::TestContext &context)
	{
		const std::wstring net = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;		// Windows標準の分類ID。
		const std::wstring display = L"{4d36e968-e325-11ce-bfc1-08002be10318}" ;	// Display分類ID。
		DRIVERCRATE_EXPECT( context, window.controller_.scanPurpose() == ScanPurpose::STANDARD) ;
		DRIVERCRATE_EXPECT( context,
						   window.deviceClassKey( net) ==
							   window.deviceClassKey( L"{4D36E972-E325-11CE-BFC1-08002BE10318}")) ;
		// 欠損、任意名称、末尾付加、形式不正を分類GUIDとして許可しない。
		for( const auto &invalid : {std::wstring{}, std::wstring( L"Net"), net + L"x",
								   std::wstring( L"{zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz}")}) {
			DRIVERCRATE_EXPECT( context, window.deviceClassKey( invalid).empty()) ;
		}

		DRIVERCRATE_EXPECT( context, window.deviceClassName( L"").empty()) ;
		DRIVERCRATE_EXPECT( context, !window.deviceClassName( window.deviceClassKey( net)).empty()) ;
		window.candidates_.clear() ;
		// 架空属性だけを使い、現在行の優先と同名別deviceの保持を検証する。
		const auto append = [&]( const wchar_t *id, const wchar_t *name, const std::wstring &guid,
								const bool current, const DriverAction action,
								const bool installable) {
			UpdateCandidate row ;	// UI専用合成候補。Workerには渡さない。
			row.identity		= L"class-fixture-" + std::to_wstring( window.candidates_.size()) ;
			row.deviceIdentity	= id ;
			row.model			= name ;
			row.title			= current ? L"Current driver"
										  : L"Candidate " + std::to_wstring( window.candidates_.size()) ;
			row.deviceClassGuid = guid ;
			row.manufacturer	= current ? L"Device maker" : L"Candidate maker" ;
			row.provider		= L"Driver publisher" ;
			row.current			= current ;
			row.action			= action ;
			row.installable		= installable ;
			row.recommended		= installable && action == DriverAction::UPDATE ;
			row.version			= std::to_wstring( window.candidates_.size()) ;
			window.candidates_.push_back( std::move( row)) ;
		} ;
		append( L"net-a", L"Wrong candidate name", display, false, DriverAction::UPDATE,
			   true) ;	// 0。
		// 1。
		append( L"net-a", L"Ethernet adapter", net, true, DriverAction::NONE, false) ;
		// 2。
		append( L"net-a", L"Ethernet adapter", net, false, DriverAction::UPDATE, true) ;
		// 3。
		append( L"net-a", L"Ethernet adapter", net, false, DriverAction::DOWNGRADE, true) ;
		// 4。
		append( L"net-b", L"Ethernet adapter", net, true, DriverAction::NONE, false) ;
		// 5。
		append( L"net-b", L"Ethernet adapter", net, false, DriverAction::UPDATE, true) ;
		// 6。
		append( L"display", L"Graphics device", display, true, DriverAction::NONE, false) ;
		append( L"display", L"Graphics device", display, false, DriverAction::REINSTALL,
			   true) ;	// 7。
		// 8。
		append( L"missing", L"Unknown class A", L"", true, DriverAction::NONE, false) ;
		// 9。
		append( L"missing", L"Misleading candidate", net, false, DriverAction::NONE, false) ;
		append( L"invalid", L"Unknown class B", L"not-guid", true, DriverAction::NONE,
			   false) ;	// 10。
		append( L"unregistered", L"Unknown class C", L"{00000000-0000-0000-0000-000000000000}", true,
			   DriverAction::NONE, false) ;	// 11。
		window.candidateSelected_.assign( window.candidates_.size(), false) ;
		window.showRecommendedOnly_ = false ;
		window.sortedColumn_		= 0U ;
		window.sortAscending_		= true ;
		window.populateCandidates( window.candidates_) ;
		// 旧版は詳細と同じ明示指定を経て一候補へ結合します。
		DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( 3U)) ;

		DRIVERCRATE_EXPECT( context, Header_GetItemCount( window.treeHeader_) == 3 &&
										TreeView_GetCount( window.updateTree_) == 9U) ;
		const auto rowOf = [&]( const HTREEITEM item) {
			TVITEMW value{} ;	// 同期参照する実itemのparameter。
			value.mask	= TVIF_PARAM ;
			value.hItem = item ;
			return TreeView_GetItem( window.updateTree_, &value) != FALSE
					   ? window.treeRowFromParameter( value.lParam)
					   : nullptr ;
		} ; // Windowは本検査中だけ借用し、callbackを保存しない。
		unsigned	 classes{} ;			// 既知二分類とその他一分類。
		unsigned	 devices{} ;			// 同名の別PnP機能も個別に数える。
		std::wstring previous ;				// 既知分類の昇順確認。
		HTREEITEM	 networkCategory{} ;	// 同名二deviceの所属分類。
		// 全分類を辿り、二階層以外の子行や分類checkboxを拒否する。
		for( auto category = TreeView_GetRoot( window.updateTree_); category != nullptr;
			category	  = TreeView_GetNextSibling( window.updateTree_, category)) {
			++classes ;
			const auto *row = rowOf( category) ;	// 同じcontrolの表示行。
			DRIVERCRATE_EXPECT( context, row != nullptr) ;
			// 未取得の行を検査側でも参照しない。
			if( row == nullptr) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context, row->kind == MainWindow::TreeRowKind::DEVICE_CLASS) ;
			// 不明分類を消さず末尾へ配置する。
			if( row->unknownClass) {
				DRIVERCRATE_EXPECT(
					context, TreeView_GetNextSibling( window.updateTree_, category) == nullptr &&
								 row->primaryText ==
									 window.loadString( IDS_TREE_CLASS_UNKNOWN) +
										 window.formatResource( IDS_TREE_CLASS_DEVICE_COUNT, L"3")) ;
			} else {
				DRIVERCRATE_EXPECT(
					context, previous.empty() ||
								 CompareStringEx( LOCALE_NAME_USER_DEFAULT,
												 NORM_IGNORECASE | SORT_DIGITSASNUMBERS,
												 previous.c_str(), -1, row->className.c_str(), -1,
												 nullptr, nullptr, 0) != CSTR_GREATER_THAN) ;
				previous = row->className ;
			}

			// 更新の件数は二deviceであり、四つの更新候補へ増やさない。
			if( row->status == window.formatResource( IDS_TREE_CLASS_UPDATE_COUNT, L"2")) {
				networkCategory = category ;
			}

			TreeView_SetItemState( window.updateTree_, category, INDEXTOSTATEIMAGEMASK( 2),
								  TVIS_STATEIMAGEMASK) ;
			DRIVERCRATE_EXPECT( context, TreeView_GetItemState( window.updateTree_, category,
															  TVIS_STATEIMAGEMASK) == 0U) ;
			// 各deviceは一行だけで、現在構成・metadata・候補を子に表示しない。
			for( auto item = TreeView_GetChild( window.updateTree_, category); item != nullptr;
				item	  = TreeView_GetNextSibling( window.updateTree_, item)) {
				++devices ;
				DRIVERCRATE_EXPECT( context,
								   TreeView_GetChild( window.updateTree_, item) == nullptr &&
									   rowOf( item) != nullptr &&
									   rowOf( item)->kind == MainWindow::TreeRowKind::DEVICE) ;
			}
		}

		const auto deviceA = window.candidateItems_[0] ;	// 四候補を一行へまとめた最初のdevice。
		const auto deviceB = window.candidateItems_[5] ;	// 同名の別device。
		DRIVERCRATE_EXPECT( context,
						   classes == 3U && devices == 6U && networkCategory != nullptr &&
							   deviceA != deviceB &&
							   TreeView_GetParent( window.updateTree_, deviceA) == networkCategory &&
							   TreeView_GetParent( window.updateTree_, deviceB) == networkCategory) ;
		DRIVERCRATE_EXPECT( context, window.candidateItems_[0] == window.candidateItems_[1] &&
										window.candidateItems_[1] == window.candidateItems_[2] &&
										window.candidateItems_[2] == window.candidateItems_[3] &&
										rowOf( deviceA)->primaryText == L"Ethernet adapter" &&
										rowOf( deviceA)->currentVersion == L"1" &&
										rowOf( deviceA)->candidateVersion == L"3") ;
		DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( 0U)) ;
		TreeView_SetCheckState( window.updateTree_, deviceB, TRUE) ;
		DRIVERCRATE_EXPECT( context, window.candidateSelected_[0] && window.candidateSelected_[5] &&
										!window.candidateSelected_[3]) ;
		DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( 2U)) ;
		DRIVERCRATE_EXPECT( context, !window.candidateSelected_[0] && window.candidateSelected_[2] &&
										window.candidateSelected_[5] &&
										window.checkedCandidateIndexes() ==
											std::vector<std::size_t>( {2U, 5U})) ;
		DRIVERCRATE_EXPECT( context, !window.selectDeviceCandidate( 1U) &&
										!window.selectDeviceCandidate( window.candidates_.size())) ;
		// 四列全てのsortでもdevice所属・選択候補indexを維持する。
		for( int column{}; column < 3; ++column) {
			window.handleHeaderClick( column) ;
			DRIVERCRATE_EXPECT( context,
							   TreeView_GetParent( window.updateTree_, deviceA) == networkCategory &&
								   window.checkedCandidateIndexes() ==
									   std::vector<std::size_t>( {2U, 5U})) ;
		}

		window.sortedColumn_  = 1U ;
		window.sortAscending_ = false ;
		window.sortTreeItems() ;
		DRIVERCRATE_EXPECT( context,
						   TreeView_GetChild( window.updateTree_, networkCategory) == deviceB) ;
		DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( 3U)) ;
		window.showRecommendedOnly_ = true ;
		window.populateCandidates( window.candidates_) ;
		const auto filteredSelection = window.checkedCandidateIndexes() ;	// Filter中の実要求対象。
		DRIVERCRATE_EXPECT(
			context, TreeView_GetCount( window.updateTree_) == 3U && window.candidateSelected_[3] &&
						 std::ranges::find( filteredSelection, 3U) == filteredSelection.end()) ;
		DRIVERCRATE_EXPECT( context, !window.selectDeviceCandidate( 3U) &&
										window.selectDeviceCandidate( 2U) &&
										!window.candidateSelected_[3]) ;
		window.showRecommendedOnly_ = false ;
		window.sortedColumn_		= 0U ;
		window.sortAscending_		= true ;
		window.populateCandidates( window.candidates_) ;
		window.clearCandidateSelection() ;
		DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty() &&
										std::none_of( window.candidateSelected_.begin(),
													 window.candidateSelected_.end(),
													 []( const bool selected) { return selected ; })) ;
		DRIVERCRATE_EXPECT( context,
						   window.selectDeviceCandidate( 2U) && window.selectDeviceCandidate( 5U)) ;
		window.updateTreeSortIndicator() ;
		TreeView_SelectItem( window.updateTree_, nullptr) ;
		DRIVERCRATE_EXPECT( context, TreeView_GetCount( window.updateTree_) == 9U &&
										window.checkedCandidateIndexes() ==
											std::vector<std::size_t>( {2U, 5U})) ;
	}
	/**
	 * @brief 合成画像の確認用に分類とdeviceを明示展開する。
	 * @param[in,out] window 実情報を含まない試験Window。
	 */
	static void expandClassPreview( MainWindow &window)
	{
		// 二階層を見える状態にし、展開だけで候補を変更しない。
		for( auto category = TreeView_GetRoot( window.updateTree_); category != nullptr;
			category	  = TreeView_GetNextSibling( window.updateTree_, category)) {
			TreeView_Expand( window.updateTree_, category, TVE_EXPAND) ;
			// Deviceに第三階層が残っていないことを確認する。
			for( auto device = TreeView_GetChild( window.updateTree_, category); device != nullptr;
				device		= TreeView_GetNextSibling( window.updateTree_, device)) {
				TreeView_Expand( window.updateTree_, device, TVE_EXPAND) ;
			}
		}

		TreeView_SelectSetFirstVisible( window.updateTree_, TreeView_GetRoot( window.updateTree_)) ;
	}
	/**
	 * @brief Providerを呼ばず結果表示だけを渡し、二階層の失効と詳細の個別結果保持を検証する。
	 * @param[in,out] window 通常候補の表示試験を終えたWindow。
	 * @param[in,out] context Assertion集計先。
	 */
	static void verifyClassInstallResults( MainWindow &window, test::TestContext &context)
	{
		InstallResult result ;	// 実導入ではなく結果表示専用の合成data。
		result.updates.push_back( {.identity		   = window.candidates_[2].identity,
								  .downloadOutcome = OutcomeCode::SUCCESS,
								  .installOutcome  = OutcomeCode::FAILURE}) ;
		window.displayInstallResult( result, window.controller_.scanSessionId()) ;
		DRIVERCRATE_EXPECT( context, TreeView_GetCount( window.updateTree_) == 9U &&
										window.checkedCandidateIndexes().empty()) ;
		// 全候補が失効し、分類が導入可能件数のまま残らない。
		for( const auto &row : window.treeRows_) {
			// 分類の失効説明を全rootで確認する。
			if( row.kind == MainWindow::TreeRowKind::DEVICE_CLASS) {
				DRIVERCRATE_EXPECT( context,
								   row.status == window.loadString( IDS_TREE_CLASS_EXPIRED)) ;
			}
		}

		DRIVERCRATE_EXPECT( context, window.candidateResultTexts_[2].find( window.loadString(
										IDS_INSTALL_FAILED)) != std::wstring::npos) ;
		// 合成check通知でも失効候補を再選択できない。
		for( const auto item : window.candidateItems_) {
			TreeView_SetCheckState( window.updateTree_, item, TRUE) ;
			DRIVERCRATE_EXPECT(
				context, (TreeView_GetItemState( window.updateTree_, item, TVIS_STATEIMAGEMASK) &
						  TVIS_STATEIMAGEMASK) == 0U) ;
		}

		UpdateCandidate standalone =
			window.candidates_[0] ;	// Local現在行がないProvider候補の表示だけを再現する。
		window.candidates_		  = {standalone} ;
		window.candidateSelected_ = {false} ;
		window.populateCandidates( window.candidates_) ;
		DRIVERCRATE_EXPECT( context, TreeView_GetCount( window.updateTree_) == 2U) ;
		DRIVERCRATE_EXPECT( context, std::any_of( window.treeRows_.begin(), window.treeRows_.end(),
												[&]( const auto &row) {
													return row.kind ==
															   MainWindow::TreeRowKind::DEVICE &&
														   row.primaryText == standalone.model ;
												})) ;
		window.candidates_.clear() ;
		window.candidateSelected_.clear() ;
		window.populateCandidates( window.candidates_) ;
		DRIVERCRATE_EXPECT( context,
						   TreeView_GetCount( window.updateTree_) == 0U && window.treeRows_.empty()) ;
	}
	/**
     * @brief 禁止stageの偽進捗で表示が変わらないことを確認する。
     * @param[in,out] window 実行中の非通信Window。
     * @param[in,out] context Assertion集計先。
     */
	static void verifyProgress( MainWindow &window, test::TestContext &context)
	{
		const auto	previous = window.statusPercentage_ ;	// 直前の確定値。
		WorkerEvent event ;									// 同operationだが用途違反の進捗。
		event.operationId = window.controller_.activeOperationId() ;
		event.kind		  = WorkerEventKind::PROGRESS ;
		event.progress	  = {.stage = ProviderStage::INSTALLING, .percentComplete = 99U} ;
		window.processOperationProgress( event) ;
		DRIVERCRATE_EXPECT( context, window.statusPercentage_ == previous) ;
		event.progress = {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = previous,
						  .completedItems  = 0U,
						  .totalItems	   = 1U} ;
		window.processOperationProgress( event) ;
		DRIVERCRATE_EXPECT( context, window.statusBusy_ && window.statusPercentage_ == previous) ;
	}
	/**
	 * @brief 観測と候補判定の異なる状態を、合成dataだけで実controlへ表示する。
	 * @param[in,out] window 先行表示試験を終えたWindow。
	 * @param[in,out] context Assertion集計先。
	 */
	static void verifyObservations( MainWindow &window, test::TestContext &context)
	{
		UpdateCandidate current ;	// 名称・版欠損の未導入代表。
		current.identity							= L"observation-current" ;
		current.deviceIdentity						= L"observation-device" ;
		current.providerId							= DRIVER_STORE_PROVIDER_ID ;
		current.current								= true ;
		current.discoveryBasis						= CandidateDiscoveryBasis::LOCAL_INVENTORY ;
		current.audit								= makeWindowsManagedCandidateAudit( true) ;
		current.deviceObservation					= DeviceObservation{} ;
		current.deviceObservation->scanSessionId	= 83U ;
		current.deviceObservation->deviceIdentity	= current.deviceIdentity ;
		current.deviceObservation->node.read.state	= DevicePropertyReadState::VALUE ;
		current.deviceObservation->node.statusFlags = 0x400U ;
		current.deviceObservation->node.problemCode = 28U ;
		current.deviceObservation->driverPresence	= DeviceDriverPresence::NOT_INSTALLED ;
		current.deviceObservation->driverKey.state	= DevicePropertyReadState::EMPTY ;
		current.deviceObservation->provider			= {
			DevicePropertyReadState::FAILED,
			{DeviceDiagnosticDomain::WINDOWS_ERROR, ERROR_ACCESS_DENIED}} ;
		const auto observedText = window.formatCandidateDetails( current) ;	// 秘密値を持たない本文。
		DRIVERCRATE_EXPECT( context, observedText.find( L"未導入") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, observedText.find( L"現在使用中") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, observedText.find( L"28") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, observedText.find( window.loadString( IDS_DEVICE_READ_EMPTY)) !=
										std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, observedText.find( window.loadString(
										IDS_DEVICE_ACCESS_DENIED)) != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   observedText.find( current.deviceIdentity) == std::wstring::npos) ;
		UpdateCandidate changed			= current ;	// 別の表示状態だけを同じfixtureから作る。
		changed.deviceObservation->node = {} ;
		changed.deviceObservation->driverKey.state = DevicePropertyReadState::VALUE ;
		changed.deviceObservation->driverPresence  = DeviceDriverPresence::REGISTERED ;
		DRIVERCRATE_EXPECT( context, window.formatCandidateState( changed).find( L"登録済み") !=
										std::wstring::npos) ;
		changed.deviceObservation->driverKey.state = DevicePropertyReadState::EMPTY ;
		changed.deviceObservation->driverPresence  = DeviceDriverPresence::UNKNOWN ;
		DRIVERCRATE_EXPECT( context, window.formatCandidateState( changed).find(
										L"現在ドライバー未確認") != std::wstring::npos) ;
		changed.deviceObservation.reset() ;
		DRIVERCRATE_EXPECT( context, window.formatCandidateState( changed) ==
										window.loadString( IDS_DEVICE_OBSERVATION_MISSING)) ;
		UpdateCandidate candidate ;	// 導入しない公式installer方式の初回候補。
		candidate.identity						= L"assessment-candidate" ;
		candidate.deviceIdentity				= current.deviceIdentity ;
		candidate.title							= L"Fixture driver package" ;
		candidate.action						= DriverAction::INITIAL_INSTALL ;
		candidate.discoveryBasis				= CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
		candidate.audit							= makeOfficialDiscoveryCandidateAudit() ;
		candidate.audit.installReadiness		= CandidateInstallReadiness::BLOCKED ;
		candidate.assessment					= CandidateAssessment{} ;
		candidate.assessment->scanSessionId		= 83U ;
		candidate.assessment->candidateIdentity = candidate.identity ;
		candidate.assessment->deviceIdentity	= candidate.deviceIdentity ;
		candidate.assessment->installMethod		= CandidateInstallMethod::OFFICIAL_INSTALLER ;
		candidate.assessment->origin			= {CandidateAssessmentState::PASSED,
												   CandidateAssessmentReason::VALIDATED,
												   CandidateEvidenceKind::OFFICIAL_RECORD,
												   1U,
												   {}} ;
		candidate.assessment->acquisition		= {CandidateAssessmentState::UNSUPPORTED,
												   CandidateAssessmentReason::FORMAT_UNSUPPORTED,
												   CandidateEvidenceKind::PACKAGE_INSPECTION,
												   2U,
												   {}} ;
		candidate.assessment->method			= {CandidateAssessmentState::UNSUPPORTED,
												   CandidateAssessmentReason::EXECUTOR_UNAVAILABLE,
												   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
												   3U,
												   {}} ;
		DRIVERCRATE_EXPECT( context, isCandidateDetailsValid( candidate, 83U)) ;
		const auto detailedText = window.formatCandidateDetails( candidate) ;	// 八軸の固定表示。
		DRIVERCRATE_EXPECT( context, detailedText.find( window.loadString(
										IDS_ASSESSMENT_COMPONENT_ROLE)) != std::wstring::npos) ;
		candidate.assessment->componentRole = CandidateComponentRole::BASE_DRIVER ;
		DRIVERCRATE_EXPECT( context, window.formatCandidateDetails( candidate).find( window.loadString(
										IDS_ASSESSMENT_ROLE_BASE)) != std::wstring::npos) ;
		candidate.assessment->componentRole.reset() ;
		// 全軸を省略せず、未検査を合格へ補完しない。
		for( const UINT label : {IDS_ASSESSMENT_AXIS_ORIGIN, IDS_ASSESSMENT_AXIS_ACQUISITION,
								IDS_ASSESSMENT_AXIS_SIGNATURE, IDS_ASSESSMENT_AXIS_APPLICABILITY,
								IDS_ASSESSMENT_AXIS_SELECTION, IDS_ASSESSMENT_AXIS_DRIVER_ONLY,
								IDS_ASSESSMENT_AXIS_REQUIREMENTS, IDS_ASSESSMENT_AXIS_METHOD}) {
			DRIVERCRATE_EXPECT( context,
							   detailedText.find( window.loadString( label)) != std::wstring::npos) ;
		}

		DRIVERCRATE_EXPECT( context, detailedText.find( window.loadString(
										IDS_ASSESSMENT_STATE_UNSUPPORTED)) != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, detailedText.find( candidate.identity) == std::wstring::npos) ;
		changed		   = candidate ;
		changed.action = DriverAction::NONE ;
		changed.assessment.reset() ;
		DRIVERCRATE_EXPECT( context, window.formatCandidateDetails( changed).find( window.loadString(
										IDS_ASSESSMENT_UNCOLLECTED)) != std::wstring::npos) ;
		window.candidates_			   = {current, candidate, changed} ;
		window.candidates_[2].identity = L"legacy-information" ;
		window.candidateSelected_.assign( 3U, false) ;
		window.showRecommendedOnly_ = false ;
		window.populateCandidates( window.candidates_) ;
		// 表示行のSpaceとcheck通知でも未実装方式を選択できない。
		for( const auto item : window.candidateItems_) {
			TreeView_SetCheckState( window.updateTree_, item, TRUE) ;
			DRIVERCRATE_EXPECT(
				context, (TreeView_GetItemState( window.updateTree_, item, TVIS_STATEIMAGEMASK) &
						  TVIS_STATEIMAGEMASK) == 0U) ;
		}

		DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty()) ;
	}
	/**
	 * @brief 詳細閲覧前後の指定候補とcheckboxを値で比較します。
	 * @param[in] window 同UI threadの所有Window。
	 * @return 候補選択と各device行の指定indexを含むsnapshot。
	 */
	static std::vector<std::size_t> simpleSelection( const MainWindow &window)
	{
		auto values = window.checkedCandidateIndexes() ;	// 現在checkされた元候補。
		// 指定の有無も含め、閲覧が候補選択を変えないことを比較する。
		for( const auto &row : window.treeRows_) {
			values.push_back( row.candidateIndex) ;
			values.push_back( row.hasCandidateChoice ? 1U : 0U) ;
		}

		return values ;
	}
	/**
	 * @brief 名前・版・driver観測がないdeviceにも同じ詳細を開けるfixtureを作ります。
	 * @param[in,out] window 通常scanを受理できる所有Window。
	 * @param[in,out] context 元assertion集計先。
	 */
	static void unknownSimpleDetails( MainWindow &window, test::TestContext &context)
	{
		// 推奨候補のない現在行も全件表示で閲覧します。
		window.showRecommendedOnly_ = false ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
		const auto begin = window.controller_.beginScan() ;	// 新規scanの正規状態遷移。
		DRIVERCRATE_EXPECT( context, begin.accepted) ;
		UpdateCandidate current ;	// 表示属性が不明でもopaque deviceを保持する。
		current.identity	   = L"unknown-current" ;
		current.deviceIdentity = L"unknown-device" ;
		current.current		   = true ;
		WorkerEvent event{.kind		   = WorkerEventKind::SCAN_COMPLETED,
						  .operationId = begin.operationId,
						  .scanResult  = {.succeeded	 = true,
										  .scanSessionId = 1999U,
										  .outcome		 = OutcomeCode::SUCCESS,
										  .candidates	 = {current}}} ;	// 通信なしの結果。
		window.processWorkerEvent( event) ;
		window.preparationResultText_ = L"Fixture inspection report" ;
		DRIVERCRATE_EXPECT( context, window.candidateItems_.size() == 1U &&
										window.candidateItems_.front() != nullptr &&
										TreeView_GetCount( window.updateTree_) == 2U) ;
	}
	/**
	 * @brief 診断fixtureだけで元controllerへ一件の合成完了を渡します。
	 * @param[in,out] window 有効な通常local候補の所有Windowです。
	 * @param[in,out] context 元assertion集計先です。
	 */
	static void diagnosticResult( MainWindow &window, test::TestContext &context)
	{
		const auto		 session = window.controller_.scanSessionId() ;	// 元scanの表示結合です。
		const std::array identities{window.candidates_[1].identity} ;	// 元一件だけです。
		const auto		 begin = window.controller_.beginInstall(
			  session, identities,
			  InstallConfirmation::CONFIRMED) ;	// 実Providerは呼びません。
		DRIVERCRATE_EXPECT( context, begin.accepted) ;
		const std::array<std::size_t, 1> selected{1U} ;	// 匿名開始recordの元一件です。
		recordInstallSelectionDiagnostics( begin.operationId, window.candidates_, selected, true) ;
		WorkerEvent event ;	// controllerに受理される合成結果です。
		event.kind								   = WorkerEventKind::INSTALL_COMPLETED ;
		event.operationId						   = begin.operationId ;
		event.installResult.succeeded			   = true ;
		event.installResult.downloadOutcome		   = OutcomeCode::SUCCESS ;
		event.installResult.installOutcome		   = OutcomeCode::SUCCESS ;
		event.installResult.restorePointCreation   = {OutcomeCode::SUCCESS, 0, 7} ;
		event.installResult.restorePointCompletion = {OutcomeCode::SUCCESS, 0, 7} ;
		event.installResult.restorePointProtection = {
			.disposition	   = RestorePointDisposition::WINDOWS_SELECTED_POINT,
			.verification	   = OutcomeCode::SUCCESS,
			.sequenceNumber	   = event.installResult.restorePointCreation.sequenceNumber,
			.createdUtc		   = 1,
			.localDay		   = 20261110U,
			.verifiedBefore	   = true,
			.verifiedAfter	   = true,
			.nativeBeginCalled = true,
			.nativeEndCalled   = true} ;	// 人工DTOの明示fake実在です。
		event.installResult.updates.push_back( {.identity		= identities.front(),
											   .downloadOutcome = OutcomeCode::SUCCESS,
											   .installOutcome	= OutcomeCode::SUCCESS}) ;
		PostInstallDeviceObservation observed ;	// 元現在観測の読取DTOだけです。
		observed.observation = *window.candidates_.front().deviceObservation ;
		observed.version	 = window.candidates_.front().version ;
		event.installResult.currentDevices.push_back( observed) ;
		window.processWorkerEvent( event) ;
		DRIVERCRATE_EXPECT( context, window.controller_.scanSessionId() == 0U &&
										window.checkedCandidateIndexes().empty() &&
										!window.selectDeviceCandidate( 1U)) ;
	}
	/**
	 * @brief 既status帯の匿名保存案内と元候補数を確認します。
	 * @param[in] window 所有候補と実controlです。
	 * @param[in,out] context 元集計先です。
	 * @param[in] failed 固定失敗案内を期待する場合trueです。
	 */
	static void diagnosticStatus( const MainWindow &window, test::TestContext &context,
								 const bool failed)
	{
		wchar_t text[2048]{} ;	// 元controlの有限本文だけを読みます。
		GetWindowTextW( window.status_, text, 2048) ;
		DRIVERCRATE_EXPECT( context,
						   std::wstring_view( text).find( L"匿名診断") != std::wstring_view::npos) ;
		// 保存不能の固定説明と数値位置が表示されています。
		if( failed) {
			DRIVERCRATE_EXPECT(
				context, std::wstring_view( text).find( L"元コード有無") != std::wstring_view::npos &&
							 std::wstring_view( text).find( L"3/8/1/29/") != std::wstring_view::npos) ;
		}
	}
	/**
	 * @brief 所有する取得計画へ同deviceの新版/旧版参照を結ぶ表示fixtureです。
	 * @param[in,out] window 同期試験の所有Windowです。
	 * @param[in,out] context 原失敗を保持する集計先です。
	 */
	static void historyDetails( MainWindow &window, test::TestContext &context)
	{
		const auto begin = window.controller_.beginScan() ;	// 元の正常scan遷移です。
		DRIVERCRATE_EXPECT( context, begin.accepted) ;
		constexpr ScanSessionId	  session = 7741U ;	// この表示fixtureだけの元sessionです。
		OfficialPreparationTarget target ;			// 二deviceが共有する取得前targetです。
		target.identity		   = L"history-target" ;
		target.providerId	   = SIGNED_INDEX_PROVIDER_ID ;
		target.resourceId	   = L"history-resource" ;
		target.releaseIdentity = L"history-release" ;
		target.parserRevision  = 1U ;
		target.maximumBytes	   = 4096U ;
		target.deviceCount	   = 2U ;
		target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
		WorkerEvent event{.kind			   = WorkerEventKind::SCAN_COMPLETED,
						  .operationId	   = begin.operationId,
						  .scanResult	   = {.succeeded	 = true,
											  .scanSessionId = session,
											  .outcome		 = OutcomeCode::SUCCESS},
						  .preparationPlan = OfficialPreparationPlan{
							  session,
							  session,
							  {4096U, 4096U, 4096U, 1U, 1U},
							  {target}}} ;	// 取得/署名を発行しない完全fake結果です。
		// 同device二参照と、選択を保持する別device一参照を元planへ置きます。
		for( unsigned device = 0U; device < 2U; ++device) {
			UpdateCandidate current ;	// 生IDを持たない現在観測です。
			current.identity		= L"history-current-" + std::to_wstring( device) ;
			current.deviceIdentity	= L"history-device-" + std::to_wstring( device) ;
			current.model			= L"Fixture Ethernet adapter" ;
			current.title			= L"Fixture current driver" ;
			current.deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
			current.current			= true ;
			current.version			= L"2.0.0.0" ;
			current.driverDate		= L"11/01/2026" ;
			current.providerId		= DRIVER_STORE_PROVIDER_ID ;
			current.discoveryBasis	= CandidateDiscoveryBasis::LOCAL_INVENTORY ;
			current.audit			= makeWindowsManagedCandidateAudit( true) ;
			DeviceObservation observed ;	// 同scan/deviceに結ぶ非秘密観測です。
			observed.scanSessionId	  = session ;
			observed.deviceIdentity	  = current.deviceIdentity ;
			observed.driverPresence	  = DeviceDriverPresence::REGISTERED ;
			observed.node.read.state  = DevicePropertyReadState::VALUE ;
			observed.node.statusFlags = 0U ;
			observed.driverKey.state  = DevicePropertyReadState::VALUE ;
			observed.version.state	  = DevicePropertyReadState::VALUE ;
			current.deviceObservation = observed ;
			DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observed)) ;
			// 必須観測が破損したら製品modalへ渡さず、元失敗を有限に返します。
			if( !isDeviceObservationValid( observed)) {
				throw std::runtime_error( "history observation invalid") ;
			}

			event.scanResult.candidates.push_back( current) ;
			// 第一deviceだけ旧版を追加し、同じtarget/deviceの別候補として保持します。
			for( unsigned variant = 0U; variant < (device == 0U ? 2U : 1U); ++variant) {
				UpdateCandidate reference ;	// 元署名索引参照に結ぶ表示値だけです。
				reference.identity = L"history-reference-" + std::to_wstring( device) + L"-" +
									 std::to_wstring( variant) ;
				reference.deviceIdentity = current.deviceIdentity ;
				reference.model			 = current.model ;
				reference.title = variant == 0U ? L"Fixture newer driver" : L"Fixture older driver" ;
				reference.deviceClassGuid = current.deviceClassGuid ;
				reference.providerId	  = SIGNED_INDEX_PROVIDER_ID ;
				reference.discoveryBasis =
					CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
				reference.preparationTargetIdentity = target.identity ;
				reference.sourceName				= L"Fixture signed index" ;
				reference.audit						= makeOfficialDiscoveryCandidateAudit() ;
				event.scanResult.candidates.push_back( std::move( reference)) ;
			}
		}

		window.showRecommendedOnly_ = true ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_CHECKED, 0) ;
		// 既validatorが拒否するsnapshotをmodal待機へ渡しません。
		if( !isCandidateDetailsSetValid( event.scanResult.candidates, session)) {
			throw std::runtime_error( "history candidate snapshot invalid") ;
		}

		window.processWorkerEvent( event) ;
		DRIVERCRATE_EXPECT( context, window.candidates_.size() == 5U &&
										window.controller_.preparationPlan() != nullptr) ;
		// 受理されないscanから後段の人工表示を生成しません。
		if( window.candidates_.size() != 5U ||
		   window.controller_.state() != ApplicationState::SCAN_READY ||
		   window.controller_.preparationPlan() == nullptr) {
			throw std::runtime_error( "history scan not ready") ;
		}

		// 本workerの限定投影と同じ明示版を表示copyへ与え、取得/適用性成功は作りません。
		for( const std::size_t index : {1U, 2U, 4U}) {
			window.candidates_[index].version = index == 2U ? L"1.0.0.0" : L"3.0.0.0" ;
		}

		window.preparationResultText_ =
			window.loadString( IDS_PREPARATION_ITEM_FAILED) +
			L"\r\n0x80070005 - fixture failure" ;	// 元匿名状態と数値だけです。
		// 主treeの長いバージョン見出しを実font/列幅で確認します。
		for( int column = 0; column < 3; ++column) {
			wchar_t text[64]{} ;	// 実見出しを読みます。
			HDITEMW heading{} ;		// 元headerの文字/幅です。
			heading.mask	   = HDI_TEXT | HDI_WIDTH ;
			heading.pszText	   = text ;
			heading.cchTextMax = 64 ;
			DRIVERCRATE_EXPECT( context,
							   Header_GetItem( window.treeHeader_, column, &heading) &&
								   std::wstring_view( text) ==
									   (column == 0	  ? L"デバイス（ダブルクリックで候補を表示）"
										: column == 1 ? L"現在のバージョン"
													  : L"候補のバージョン")) ;
			const HDC  dc	= GetDC( window.treeHeader_) ;	// 同controlだけのfont測定です。
			const auto font = reinterpret_cast<HFONT>(
				// 実fontです。
				SendMessageW( window.treeHeader_, WM_GETFONT, 0, 0)) ;
			const auto previous =
				dc != nullptr ? SelectObject( dc, font) : nullptr ;	// 測定後に戻します。
			SIZE extent{} ;											// 必要な実文字幅です。
			DRIVERCRATE_EXPECT(
				context, dc != nullptr &&
							 GetTextExtentPoint32W( dc, text,
												   static_cast<int>( std::wstring_view( text).size()),
												   &extent) &&
							 heading.cxy >= extent.cx + 12) ;
			// API成功時だけ借用DC/fontを解放します。
			if( dc != nullptr) {
				SelectObject( dc, previous) ;
				ReleaseDC( window.treeHeader_, dc) ;
			}
		}

		window.populateCandidates( window.candidates_) ;
		DRIVERCRATE_EXPECT( context, window.isSelectableCandidate( window.candidates_[2]) &&
										classifyPendingReferenceVersion(
											window.candidates_[2], window.candidates_, session) ==
											PendingReferenceVersion::OLDER) ;
		DRIVERCRATE_EXPECT( context, !window.selectDeviceCandidate( 2U)) ;
		DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( 4U)) ;
	}
	/**
	 * @brief 実行権限を作らず、既観測fixtureで最新解消の有限な表示条件を確認します。
	 * @param[in,out] window 元scan/planを受理する所有Windowです。
	 * @param[in,out] context 正負のassertion集計先です。
	 * @param[in] variant 元の固定15条件の一つです。
	 */
	static void latestBoundaries( MainWindow &window, test::TestContext &context,
								 const unsigned variant)
	{
		// 既known-version参照/必要役割を一条件だけ変え、API成功と実一致を分離します。
		historyDetails( window, context) ;
		auto &current				  = window.candidates_[0] ;	// 元deviceの現在行です。
		window.candidates_[1].version = variant == 1U	 ? L"2.0.0.0"
										: variant == 10U ? L""
														 : L"3.0.0.0" ;
		window.candidates_[2].version = (variant == 6U || variant == 7U) ? L"4.0.0.0" : L"1.0.0.0" ;
		// 初回も元の推奨表示predicateを使い、UPDATEへ分類し直しません。
		if( variant == 7U) {
			current.deviceObservation->driverPresence	= DeviceDriverPresence::NOT_INSTALLED ;
			current.deviceObservation->node.statusFlags = 0x400U ;
			current.deviceObservation->node.problemCode = 28U ;
		}

		UpdateCandidate selected = current ;	// 適合許可を発行しない表示分類の入力です。
		selected.identity		 = L"latest-selected" ;
		selected.current		 = false ;
		selected.installable	 = true ;
		selected.recommended	 = true ;
		selected.action			 = variant == 1U   ? DriverAction::REINSTALL
								   : variant == 5U ? DriverAction::DOWNGRADE
								   : variant == 7U ? DriverAction::INITIAL_INSTALL
												   : DriverAction::UPDATE ;
		selected.version		 = variant == 1U ? L"2.0.0.0" : L"3.0.0.0" ;
		selected.deviceObservation.reset() ;
		selected.requiredExtensionCount = variant == 9U ? 1U : 0U ;
		selected.audit					= makeWindowsManagedCandidateAudit( false) ;
		window.knownRecommendedBeforeInstall_.clear() ;
		// 実beginInstallと同じ元filter判定を、事後の現在版変更より前に保持します。
		for( const auto &candidate : window.candidates_) {
			// 元の推奨表示predicateが認識した候補だけを保持します。
			if( window.visibleInRecommendedFilter( candidate)) {
				window.knownRecommendedBeforeInstall_.insert( candidate.identity) ;
			}
		}

		// 元recommended=false/action NONEの取得前参照でも既知新版は隠しません。
		if( variant == 6U || variant == 7U) {
			DRIVERCRATE_EXPECT( context, !window.candidates_[2].recommended &&
											window.candidates_[2].action == DriverAction::NONE &&
											window.knownRecommendedBeforeInstall_.contains(
												window.candidates_[2].identity)) ;
		}

		PostInstallDeviceObservation observed ;	// 実一致を明示した非秘密の分類入力です。
		observed.observation				  = *current.deviceObservation ;
		observed.observation.driverPresence	  = DeviceDriverPresence::REGISTERED ;
		observed.observation.node.statusFlags = variant == 12U ? 0x408U : 8U ;
		observed.observation.node.problemCode =
			variant == 12U ? std::optional<std::uint32_t>{31U} : std::nullopt ;
		DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observed.observation)) ;
		observed.deviceClassGuid =
			variant == 13U ? L"{4d36e978-e325-11ce-bfc1-08002be10318}" : current.deviceClassGuid ;
		observed.version			   = selected.version ;
		observed.selectedTargetMatched = variant != 3U && variant != 8U ;
		window.candidates_.push_back( selected) ;
		InstallResult		  result ;	// native成功だけでは最新確認を作りません。
		// 個別の元API事実と再起動だけを与えます。
		UpdateExecutionResult update ;
		update.identity		   = selected.identity ;
		update.downloadOutcome = OutcomeCode::SUCCESS ;
		update.installOutcome  = variant == 2U ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
		update.installError	   = variant == 2U ? static_cast<NativeError>( E_ACCESSDENIED) : 0U ;
		update.rebootRequired  = variant == 4U ;
		// 未反映の必要roleがあればbase成功だけで解消しません。
		if( variant == 9U) {
			update.requiredRoles.push_back(
				{.role			 = DriverPlanRole::BASE_DRIVER,
				 .ordinal		 = 1U,
				 .stageOutcome	 = OutcomeCode::SUCCESS,
				 .installOutcome = OutcomeCode::SUCCESS,
				 .reflection	 = DriverPlanReflectionState::INSTALL_API_COMPLETED}) ;
		}

		result.updates.push_back( update) ;
		// 欠測条件以外にだけ実観測入力を与えます。
		if( variant != 14U) {
			result.currentDevices.push_back( observed) ;
		}

		window.applyPostInstallObservations( result, window.controller_.scanSessionId()) ;
		window.recordResolvedInstallDevices( result, window.controller_.scanSessionId()) ;
		const bool expected = variant == 0U || variant == 1U || variant == 10U || variant == 11U ||
							  // 実確認済みの既知更新解消だけです。
							  variant == 12U ;
		DRIVERCRATE_EXPECT(
			context, window.resolvedInstallDevices_.contains( selected.deviceIdentity) == expected) ;
		std::cout << "LATEST_BOUNDARY case=" << variant << " resolved="
				  << window.resolvedInstallDevices_.contains( selected.deviceIdentity)
				  << " expected=" << expected << " realOS=0\n"
				  << std::flush ;
	}
	/**
	 * @brief 実checkboxから全候補表示へ切り替えます。
	 * @param[in,out] window 元plan/候補を保持するWindowです。
	 */
	static void historyShowAll( MainWindow &window)
	{
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
		window.handleRecommendedFilterChange() ;
	}
	/**
	 * @brief 同版/未知/計画欠測を同じ元参照の表示copyへ一要因で与えます。
	 * @param[in,out] window 所有する原planと候補です。
	 * @param[in] variant 0同版、1未知版、2計画欠測、3元旧版へ復帰します。
	 */
	static void historyVariant( MainWindow &window, const unsigned variant)
	{
		auto &candidate	  = window.candidates_[2] ;	// 原旧版参照だけです。
		candidate.version = variant == 0U ? L"2.0.0.0" : variant == 1U ? L"" : L"1.0.0.0" ;
		candidate.preparationTargetIdentity = variant == 2U ? L"missing-target" : L"history-target" ;
		window.populateCandidates( window.candidates_) ;
	}
	/**
	 * @brief 元選択二件と複数分類で準備失敗後の表示と権限を確認します。
	 * @param[in,out] window 同private desktopの所有Windowです。
	 * @param[in,out] context 原assertionの集計先です。
	 * @param[in] variant 取得/内容/適用性/発行/結合/summary/取消し/遅延/表示選択拒否の番号です。
	 */
	static void preparationFailure( MainWindow &window, test::TestContext &context,
								   const unsigned variant)
	{
		historyDetails( window, context) ;
		auto plan = *window.controller_.preparationPlan() ;	// 元の有効な共有targetを再利用します。
		auto candidates = window.candidates_ ;				// 実inventoryではない所有fixtureだけです。
		const auto scan = window.controller_.beginScan() ;	// 新scanが旧表示snapshotを破棄します。
		DRIVERCRATE_EXPECT( context, scan.accepted) ;
		plan.scanSessionId = 8798U ;
		plan.planId		   = 8798U ;
		// 元現在観測を同じ新scanへ結合し、二つ目の分類を別にします。
		for( std::size_t index{}; index < candidates.size(); ++index) {
			// 合成現在行だけの元観測sessionを更新します。
			if( candidates[index].deviceObservation) {
				candidates[index].deviceObservation->scanSessionId = plan.scanSessionId ;
			}

			// 同deviceの現在行と参照を同じMEDIA分類へ保ちます。
			if( index >= 3U) {
				candidates[index].deviceClassGuid = L"{4d36e96c-e325-11ce-bfc1-08002be10318}" ;
			}
		}

		auto current			= candidates.front() ;	// 第三deviceの合成現在観測です。
		current.identity		= L"failure-current-verified" ;
		current.deviceIdentity	= L"failure-device-verified" ;
		current.model			= L"Fixture verified device" ;
		current.deviceClassGuid = L"{4d36e97d-e325-11ce-bfc1-08002be10318}" ;
		current.deviceObservation->deviceIdentity = current.deviceIdentity ;
		candidates.push_back( current) ;
		UpdateCandidate verified ;	// 既Windows管理候補の有効性を新たに失効させません。
		verified.identity		   = L"failure-verified" ;
		verified.deviceIdentity	   = current.deviceIdentity ;
		verified.model			   = current.model ;
		verified.deviceClassGuid   = current.deviceClassGuid ;
		verified.title			   = L"Fixture verified update" ;
		verified.version		   = L"4.0.0.0" ;
		verified.providerId		   = WINDOWS_UPDATE_PROVIDER_ID ;
		verified.discoveryBasis	   = CandidateDiscoveryBasis::MANAGED_SERVICE ;
		verified.sourceName		   = L"Windows Update" ;
		verified.action			   = DriverAction::UPDATE ;
		verified.installable	   = true ;
		verified.recommended	   = true ;
		verified.defaultPreference = CandidateDefaultPreference::MANAGED_APPLICABLE ;
		verified.audit			   = makeWindowsManagedCandidateAudit( false) ;
		candidates.push_back( verified) ;
		current.identity	   = L"failure-current-hidden" ;
		current.deviceIdentity = L"failure-device-hidden" ;
		current.deviceClassGuid.clear() ;
		current.deviceObservation->deviceIdentity = current.deviceIdentity ;
		candidates.push_back( current) ;
		verified.identity		   = L"failure-valid-alternative" ;
		verified.deviceIdentity	   = candidates.front().deviceIdentity ;
		verified.deviceClassGuid   = candidates.front().deviceClassGuid ;
		verified.recommended	   = false ;
		verified.providerId		   = DRIVER_STORE_PROVIDER_ID ;
		verified.discoveryBasis	   = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
		verified.sourceName		   = L"Windows Driver Store" ;
		verified.defaultPreference = CandidateDefaultPreference::NONE ;
		candidates.push_back( verified) ;
		DRIVERCRATE_EXPECT( context, isCandidateDetailsSetValid( candidates, plan.scanSessionId)) ;
		// 同じ人工候補を通常scan終端として受理させます。
		WorkerEvent scanned{.kind			 = WorkerEventKind::SCAN_COMPLETED,
							.operationId	 = scan.operationId,
							.scanResult		 = {.succeeded	   = true,
												.scanSessionId = plan.scanSessionId,
												.outcome	   = OutcomeCode::SUCCESS,
												.candidates	   = candidates},
							.preparationPlan = plan} ;
		const auto	coverage = aggregateLocalCoverage(
			 candidates, builtInProviderDescriptors()) ;	// 元scanのgroup母数です。
		DRIVERCRATE_EXPECT( context, coverage.has_value()) ;
		// 不正な人工coverageを製品の計測保持guardへ渡しません。
		if( !coverage) {
			throw std::runtime_error( "preparation failure coverage invalid") ;
		}

		scanned.scanResult.localCoverage = *coverage ;
		window.processWorkerEvent( scanned) ;
		window.showRecommendedOnly_ = true ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_CHECKED, 0) ;
		window.populateCandidates( window.candidates_) ;
		DRIVERCRATE_EXPECT( context,
						   window.selectDeviceCandidate( 1U) && window.selectDeviceCandidate( 6U)) ;
		std::map<std::wstring, bool> expansion ;	// 開状態と閉状態を正規分類keyで固定します。
		std::vector<HTREEITEM>
					originalItems ;		// 元filter内の分類とdeviceを同じnative順で保持します。
		std::size_t originalDevices{} ;	// 非表示deviceを後から全表示へ追加しません。
		// 元三分類のMEDIAだけを閉じ、その他はまだ非表示にします。
		for( HTREEITEM item = TreeView_GetRoot( window.updateTree_); item != nullptr;
			item		   = TreeView_GetNextSibling( window.updateTree_, item)) {
			TVITEMW native{} ;	// 元の実controlにだけ送ります。
			native.mask	 = TVIF_PARAM ;
			native.hItem = item ;
			DRIVERCRATE_EXPECT( context, TreeView_GetItem( window.updateTree_, &native)) ;
			const auto *row = window.treeRowFromParameter( native.lParam) ;	// 有効分類です。
			// 元MEDIA分類だけを閉状態として固定します。
			const bool	open = row && CompareStringOrdinal( row->classKey.c_str(), -1,
														   L"{4d36e96c-e325-11ce-bfc1-08002be10318}",
														   -1, TRUE) != CSTR_EQUAL ;
			TreeView_Expand( window.updateTree_, item, open ? TVE_EXPAND : TVE_COLLAPSE) ;
			expansion.emplace( row->classKey, open) ;
			originalItems.push_back( item) ;
			// 元filterで存在した子行のhandleと順序を終端後にも照合します。
			for( HTREEITEM child = TreeView_GetChild( window.updateTree_, item); child != nullptr;
				child			= TreeView_GetNextSibling( window.updateTree_, child)) {
				originalItems.push_back( child) ;
				++originalDevices ;
			}
		}

		DRIVERCRATE_EXPECT( context, expansion.size() == 3U) ;
		OfficialPreparationApproval approval ;	// Workerには送らない人工の正規承認です。
		approval.scanSessionId = plan.scanSessionId ;
		approval.planId		   = plan.planId ;
		approval.limits		   = plan.limits ;
		approval.decisions.push_back( {plan.targets.front(), true}) ;
		approval.installIntentIdentities = {candidates[1].identity, candidates[6].identity} ;
		const auto begin =
			// 原controllerへ同じ判断を固定します。
			window.controller_.beginPreparation( approval) ;
		DRIVERCRATE_EXPECT( context, begin.accepted) ;
		window.preparationApproval_				= approval ;
		window.continueInstallAfterPreparation_ = true ;
		OfficialPreparationOperationResult result ;	// 実取得や実導入を行わない終端です。
		result.operationId		   = begin.operationId ;
		result.scanSessionId	   = plan.scanSessionId ;
		result.planId			   = plan.planId ;
		result.approvalError	   = OfficialPreparationError::NONE ;
		const bool		  acquired = variant >= 1U && variant <= 3U ;	// 内容以降の三ケースだけです。
		const NativeError failure =
			variant == 6U ? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
						  : static_cast<NativeError>( E_ACCESSDENIED) ;	// 元段階の人工codeです。
		result.items.push_back( {plan.targets.front().identity,
								{acquired ? OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION
								 : variant == 6U ? OfficialPreparationItemState::CANCELLED
												 : OfficialPreparationItemState::REJECTED,
								 acquired ? 0 : failure, acquired ? 1024U : 0U}}) ;
		result.installResolutions = {{candidates[1].identity,
									  variant == 4U	  ? L"missing-resolved"
									  : variant == 8U ? candidates[8].identity
													  : L"",
									  variant == 4U || variant == 8U
										  ? PreparedInstallResolutionState::READY
										  : PreparedInstallResolutionState::NOT_READY},
									 {candidates[6].identity, candidates[6].identity,
									  PreparedInstallResolutionState::READY}} ;
		// 非空reportによる最初の再描画でも元開閉・版を失わせません。
		if( acquired) {
			OfficialPreparationAuditReport report ;	// 正規validatorへ通す内容/適用性の人工結果です。
			report.targetIdentity = plan.targets.front().identity ;
			report.providerId	  = SIGNED_INDEX_PROVIDER_ID ;
			report.content =
				variant == 1U ? CandidateAuditGateState::REJECTED : CandidateAuditGateState::PASSED ;
			report.contentError			 = variant == 1U ? static_cast<NativeError>( E_FAIL) : 0 ;
			report.firstContentRejection = report.contentError ;
			report.applicability		 = variant == 1U   ? CandidateAuditGateState::PENDING
										   : variant == 2U ? CandidateAuditGateState::REJECTED
														   : CandidateAuditGateState::PASSED ;
			report.infCount				 = 1U ;
			report.acceptedInfCount		 = variant == 1U ? 0U : 1U ;
			report.examinedPairCount	 = variant == 1U ? 0U : 2U ;
			report.applicablePairCount	 = variant == 3U ? 2U : 0U ;
			// 監査合格後も発行候補0である事実を保持します。
			if( variant == 3U) {
				report.publication = {
					OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES, 2U, 0U,
					2U, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND))} ;
			}

			// 同じ元targetの参照三行だけへ監査を付けます。
			for( const std::size_t index : {1U, 2U, 4U}) {
				auto audit				  = candidates[index].audit ;	// 他属性は変更しません。
				audit.inspectionDownload  = CandidateAuditGateState::PASSED ;
				audit.contentIntegrity	  = report.content ;
				audit.systemApplicability = report.applicability ;
				report.candidates.push_back( {candidates[index].identity, audit}) ;
			}

			result.auditReports.push_back( report) ;
		}

		IndexPreparationSummary summary ;	// 同じ元targetの取得・内容結果です。
		summary.operationId	   = begin.operationId ;
		summary.scanSessionId  = plan.scanSessionId ;
		summary.planId		   = plan.planId + (variant == 5U ? 1U : 0U) ;
		summary.plannedTargets = 1U ;
		summary.items.push_back(
			{.targetIdentity	 = plan.targets.front().identity,
			 .acquisition		 = acquired ? OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION
								   : variant == 6U ? OfficialAcquisitionState::CANCELLED
												   : OfficialAcquisitionState::REJECTED,
			 .acquisitionError	 = acquired ? 0 : failure,
			 .content			 = variant == 1U ? IndexedDriverInspectionState::INSPECTION_FAILED
								   : acquired ? IndexedDriverInspectionState::INSPECTION_COMPLETED
											  : IndexedDriverInspectionState::NOT_STARTED,
			 .contentError		 = variant == 1U ? static_cast<NativeError>( E_FAIL) : 0,
			 .inputBound		 = acquired,
			 .inventoryFileCount = variant == 2U || variant == 3U ? 3U : 0U,
			 .infCount			 = variant == 2U || variant == 3U ? 1U : 0U,
			 .parsedInfCount	 = variant == 2U || variant == 3U ? 1U : 0U,
			 .acceptedInfCount	 = variant == 2U || variant == 3U ? 1U : 0U}) ;
		// 取消しも受理した元終端でだけ表示を更新します。
		if( variant == 6U) {
			DRIVERCRATE_EXPECT( context,
							   window.controller_.markPreparationCancelling( begin.operationId)) ;
		}

		// 遅延した別operationは表示snapshotも候補も変更しません。
		if( variant == 7U) {
			auto stale = result ;	// 原通知は保持します。
			++stale.operationId ;
			window.processPreparationCompleted( stale, summary) ;
			DRIVERCRATE_EXPECT( context,
							   window.preparationDisplayBindings_.empty() &&
								   window.preparationDisplaySession_ == 0U &&
								   window.showRecommendedOnly_ &&
								   !window.candidates_[1].preparationTargetIdentity.empty()) ;
		}

		// 枠だけの未指定行には元candidate identityを補いません。
		if( variant == 7U) {
			window.treeRows_[window.candidateRowIndexes_[4]].hasCandidateChoice = false ;
		}

		window.processPreparationCompleted( result, summary) ;
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::SCAN_READY &&
										window.controller_.preparationPlan() == nullptr &&
										window.controller_.scanSessionId() == plan.scanSessionId) ;
		DRIVERCRATE_EXPECT( context, window.showRecommendedOnly_ &&
										SendMessageW( window.recommendedOnlyCheckbox_, BM_GETCHECK,
													 0, 0) == BST_CHECKED &&
										window.candidates_.size() == 9U &&
										window.checkedCandidateIndexes().empty()) ;
		DRIVERCRATE_EXPECT( context, !window.isSelectableCandidate( window.candidates_[1]) &&
										!window.selectDeviceCandidate( 1U) &&
										window.isSelectableCandidate( window.candidates_[6])) ;
		std::size_t			   devices{} ;		// 元filterに存在したdevice行だけを数えます。
		std::size_t			   classes{} ;		// 非表示分類を終端で追加しません。
		std::vector<HTREEITEM> remainingItems ;	// 元native itemを作り直していないことを確認します。
		// 元分類の開閉とhandle順序を照合し、非表示分類を追加しません。
		for( HTREEITEM item = TreeView_GetRoot( window.updateTree_); item != nullptr;
			item		   = TreeView_GetNextSibling( window.updateTree_, item)) {
			++classes ;
			remainingItems.push_back( item) ;
			TVITEMW native{} ;	// 終端後も保持した元itemです。
			native.mask	 = TVIF_PARAM ;
			native.hItem = item ;
			DRIVERCRATE_EXPECT( context, TreeView_GetItem( window.updateTree_, &native)) ;
			const auto *row	  = window.treeRowFromParameter( native.lParam) ;	// 正規keyの同分類です。
			const auto	prior = expansion.find( row->classKey) ;				// 元分類にだけ保存値があります。
			DRIVERCRATE_EXPECT(
				context, ((TreeView_GetItemState( window.updateTree_, item, TVIS_EXPANDED) &
						   TVIS_EXPANDED) != 0U) == (prior != expansion.end() && prior->second)) ;
			// 全deviceを行として保持し、展開済みの個数と混同しません。
			for( HTREEITEM child = TreeView_GetChild( window.updateTree_, item); child != nullptr;
				child			= TreeView_GetNextSibling( window.updateTree_, child)) {
				++devices ;
				remainingItems.push_back( child) ;
			}
		}

		DRIVERCRATE_EXPECT( context, devices == originalDevices && classes == expansion.size() &&
										remainingItems == originalItems) ;
		const auto &row =
			window.treeRows_[window.candidateRowIndexes_[1]] ;	// 元参照の同device行です。
		DRIVERCRATE_EXPECT(
			context, !row.hasCandidateChoice && window.preparationDisplayCandidate( row) == 1U &&
						 row.candidateVersion.find( L"3.0.0.0") != std::wstring::npos &&
						 row.status.find( L"Fixture signed index") != std::wstring::npos) ;
		const auto expected = variant == 4U || variant == 5U || variant == 8U
								  ? IDS_INSTALL_PREPARATION_BINDING_REJECTED
							  : variant == 6U
								  ? IDS_INSTALL_PREPARATION_CANCELLED
								  : IDS_INSTALL_PREPARATION_NOT_READY ;	// 原未成立を優先します。
		DRIVERCRATE_EXPECT( context, window.preparationResultText_.find(
										window.loadString( expected)) != std::wstring::npos) ;
	}
	/**
	 * @brief 元checkbox枠/意図を実行権限から分離し入力拒否を確認します。
	 * @param[in,out] window 準備失敗後の元Windowです。
	 * @param[in,out] context このprocessの原集計先です。
	 * @param[in] variant 元九条件の番号です。
	 */
	static void retainedCheckboxInput( MainWindow &window, test::TestContext &context,
									  const unsigned variant)
	{
		// 選択参照/未選択参照/既検証WUAの元枠を別々に照合します。
		for( const std::size_t index : {1U, 4U, 6U}) {
			const auto &row =
				window.treeRows_[window.candidateRowIndexes_[index]] ;	// 同deviceです。
			const auto	   item		= window.candidateItems_[index] ;	// 実checkboxを持つ行です。
			const unsigned expected = index == 4U ? 3U : 4U ;			// 灰色枠と灰色checkです。
			DRIVERCRATE_EXPECT( context, row.readonlyCheckbox &&
											(TreeView_GetItemState( window.updateTree_, item,
																   TVIS_STATEIMAGEMASK) >>
											 12U) == expected) ;
			TreeView_EnsureVisible( window.updateTree_, item) ;
			RECT	   rectangle{} ;	// 所有行のcheckbox位置だけを探します。
			const bool measured = TreeView_GetItemRect( window.updateTree_, item, &rectangle,
													   FALSE) != FALSE ;		// 元controlの座標です。
			POINT	   checkbox{-1, (rectangle.top + rectangle.bottom) / 2} ;	// 発見前は無効です。
			// 一行の先頭256pxだけからstate iconのnative hit位置を求めます。
			for( int x{}; measured && x < 256 && checkbox.x < 0; ++x) {
				TVHITTESTINFO hit{} ;	// 外部Windowや画面を調べません。
				hit.pt = {x, checkbox.y} ;
				// 対象行のstate iconだけをクリック先に固定します。
				if( TreeView_HitTest( window.updateTree_, &hit) == item &&
				   (hit.flags & TVHT_ONITEMSTATEICON) != 0U) {
					checkbox.x = x ;
				}
			}

			DRIVERCRATE_EXPECT( context, checkbox.x >= 0) ;
			// 元state iconが発見された場合だけ通常mouse入力を送ります。
			if( checkbox.x >= 0) {
				PostMessageW( window.updateTree_, WM_LBUTTONDOWN, MK_LBUTTON,
							 MAKELPARAM( checkbox.x, checkbox.y)) ;
				PostMessageW( window.updateTree_, WM_LBUTTONUP, 0,
							 MAKELPARAM( checkbox.x, checkbox.y)) ;
				MSG mouse{} ;	// 事前queueした同controlのmouse通知だけです。
				// Down内部のnative追跡loopにもUpが既に届くようにdispatchします。
				while( PeekMessageW( &mouse, window.updateTree_, WM_MOUSEFIRST, WM_MOUSELAST,
								   PM_REMOVE)) {
					TranslateMessage( &mouse) ;
					DispatchMessageW( &mouse) ;
				}
			}

			DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty() &&
											(TreeView_GetItemState( window.updateTree_, item,
																   TVIS_STATEIMAGEMASK) >>
											 12U) == expected) ;
			TreeView_SetCheckState( window.updateTree_, item, FALSE) ;
			window.handleTreeCheckChange( item, false) ;
			DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty() &&
											(TreeView_GetItemState( window.updateTree_, item,
																   TVIS_STATEIMAGEMASK) >>
											 12U) == expected) ;
			TreeView_SelectItem( window.updateTree_, item) ;
			SetFocus( window.updateTree_) ;
			SendMessageW( window.updateTree_, WM_KEYDOWN, VK_SPACE, 0) ;
			SendMessageW( window.updateTree_, WM_KEYUP, VK_SPACE, 0) ;
			DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty() &&
											(TreeView_GetItemState( window.updateTree_, item,
																   TVIS_STATEIMAGEMASK) >>
											 12U) == expected) ;
		}

		// 元choiceのない枠は閲覧用candidateも捏造しません。
		if( variant == 7U) {
			const auto &row = window.treeRows_[window.candidateRowIndexes_[4]] ;	// 元未指定行です。
			const auto *binding = window.retainedDisplayBinding( row) ;				// 同snapshotだけです。
			DRIVERCRATE_EXPECT( context, binding && binding->frame &&
											binding->candidateIdentity.empty() &&
											!window.preparationDisplayCandidate( row)) ;
		}

		// 明示解除は履歴checkだけを消し、元枠と失効guardを保持します。
		if( variant == 8U) {
			window.clearCandidateSelection() ;
			window.applyCandidateSelectionToTree() ;
			DRIVERCRATE_EXPECT(
				context, window.checkedCandidateIndexes().empty() &&
							 (TreeView_GetItemState( window.updateTree_, window.candidateItems_[1],
													TVIS_STATEIMAGEMASK) >>
							  12U) == 3U &&
							 (TreeView_GetItemState( window.updateTree_, window.candidateItems_[6],
													TVIS_STATEIMAGEMASK) >>
							  12U) == 1U) ;
		}

		DRIVERCRATE_EXPECT( context,
						   !window.selectDeviceCandidate( 1U) && window.selectDeviceCandidate( 6U)) ;
		DRIVERCRATE_EXPECT( context,
						   window.checkedCandidateIndexes() == std::vector<std::size_t>{6U} &&
							   !window.treeRows_[window.candidateRowIndexes_[6]].readonlyCheckbox &&
							   (TreeView_GetItemState( window.updateTree_, window.candidateItems_[6],
													  TVIS_STATEIMAGEMASK) >>
								12U) == 2U) ;
	}
	/**
	 * @brief 合成install終端だけから個別完了checkの解除と未処理保持を確認します。
	 * @param[in,out] window 新たに明示選択した元WUA候補のWindowです。
	 * @param[in,out] context このprocessの原集計先です。
	 * @param[in] variant 成功/失敗/取消/未処理/役割待ち/引継ぎ/重複/遅延/復旧失敗です。
	 */
	static void retainedCheckboxTerminal( MainWindow &window, test::TestContext &context,
										 const unsigned variant)
	{
		const auto		 session = window.controller_.scanSessionId() ;	// 失効前の正当sessionです。
		const std::array identities{window.candidates_[6].identity} ;	// 実Providerは呼びません。
		const auto		 begin = window.controller_.beginInstall(
			  session, identities, InstallConfirmation::CONFIRMED) ;	// 元guardです。
		DRIVERCRATE_EXPECT( context, begin.accepted) ;
		// 不正な人工入力を結果dialogの待機へ進めません。
		if( !begin.accepted) {
			throw std::runtime_error( "retained checkbox install input rejected") ;
		}

		WorkerEvent event ;	// 同controllerへ渡す人工の終端だけです。
		event.kind							= WorkerEventKind::INSTALL_COMPLETED ;
		event.operationId					= begin.operationId ;
		event.installResult.succeeded		= variant == 0U ;
		event.installResult.downloadOutcome = OutcomeCode::SUCCESS ;
		event.installResult.installOutcome =
			variant == 0U ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
		event.installResult.restorePointCreation   = {OutcomeCode::SUCCESS, 0, 7} ;
		event.installResult.restorePointCompletion = {OutcomeCode::SUCCESS, 0, 7} ;
		event.installResult.restorePointProtection = {
			.disposition	   = RestorePointDisposition::WINDOWS_SELECTED_POINT,
			.verification	   = OutcomeCode::SUCCESS,
			.sequenceNumber	   = event.installResult.restorePointCreation.sequenceNumber,
			.createdUtc		   = 1,
			.localDay		   = 20261110U,
			.verifiedBefore	   = true,
			.verifiedAfter	   = true,
			.nativeBeginCalled = true,
			.nativeEndCalled   = true} ;	// 人工DTOの明示fake実在です。
		UpdateExecutionResult result ;		// 原個別結果と役割だけで完了を決めます。
		result.identity			= identities.front() ;
		result.downloadOutcome	= OutcomeCode::SUCCESS ;
		result.installOutcome	= variant == 1U || variant == 7U ? OutcomeCode::FAILURE
								  : variant == 2U				 ? OutcomeCode::ABORTED
																 : OutcomeCode::SUCCESS ;
		result.installError		= variant == 1U || variant == 7U ? static_cast<NativeError>( E_FAIL)
								  : variant == 2U
									  ? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
									  : 0 ;
		result.installerHandoff = variant == 5U ;
		DriverPlanRoleExecutionResult role ;	// 必要roleが未完了ならbase成功でも保持します。
		role.ordinal		= 1U ;
		role.stageOutcome	= OutcomeCode::SUCCESS ;
		role.installOutcome = variant == 4U ? OutcomeCode::NOT_STARTED : OutcomeCode::SUCCESS ;
		role.reflection		= variant == 4U ? DriverPlanReflectionState::WINDOWS_PENDING
											: DriverPlanReflectionState::INSTALL_API_COMPLETED ;
		result.requiredRoles.push_back( role) ;
		// 未処理には個別結果そのものを作りません。
		if( variant != 3U) {
			event.installResult.updates.push_back( result) ;
		}

		// 一意に対応しない個別結果を完了へ補いません。
		if( variant == 6U) {
			event.installResult.updates.push_back( result) ;
		}

		// 復旧保護が開始できなかった場合は個別成功から解除しません。
		if( variant == 8U) {
			event.installResult.restorePointCreation = {
				OutcomeCode::FAILURE, static_cast<NativeError>( E_ACCESSDENIED), 0} ;
		}

		// 遅延通知は元実行checkとsnapshotのどちらにもcommitしません。
		if( variant == 7U) {
			auto stale = event ;	// 元終端はそのまま保持します。
			++stale.operationId ;
			window.processInstallCompleted( stale) ;
			DRIVERCRATE_EXPECT( context, window.controller_.scanSessionId() == session &&
											window.candidateSelected_[6]) ;
		}

		window.processInstallCompleted( event) ;
		DRIVERCRATE_EXPECT( context, window.controller_.scanSessionId() == 0U &&
										window.checkedCandidateIndexes().empty() &&
										!window.selectDeviceCandidate( 6U) &&
										window.showRecommendedOnly_) ;
		DRIVERCRATE_EXPECT( context,
						   (TreeView_GetItemState( window.updateTree_, window.candidateItems_[6],
												  TVIS_STATEIMAGEMASK) >>
							12U) == (variant == 0U ? 3U : 4U) &&
							   (TreeView_GetItemState( window.updateTree_, window.candidateItems_[1],
													  TVIS_STATEIMAGEMASK) >>
								12U) == (variant == 8U ? 3U : 4U) &&
							   (TreeView_GetItemState( window.updateTree_, window.candidateItems_[4],
													  TVIS_STATEIMAGEMASK) >>
								12U) == 3U) ;
	}
	/**
	 * @brief 新scanで旧表示snapshotを捨てることを確認します。
	 * @param[in,out] window 準備不成立後の所有Windowです。
	 * @param[in,out] context 原assertionの集計先です。
	 */
	static void preparationFailureReset( MainWindow &window, test::TestContext &context)
	{
		historyLocalScan( window, context) ;
		DRIVERCRATE_EXPECT( context, window.preparationDisplaySession_ == 0U &&
										window.preparationDisplayBindings_.empty()) ;
	}
	/**
	 * @brief 取得後旧版のUI停止はworker成功DTOの人工注入として独立確認します。
	 * @param[in,out] window 元参照を保持した同scanのWindowです。
	 * @param[in,out] context 元集計先です。
	 */
	static void historyPreparedBlock( MainWindow &window, test::TestContext &context)
	{
		window.preparationApproval_.installIntentIdentities = {window.candidates_[2].identity} ;
		OfficialPreparationOperationResult result{} ;		// 実取得/公開の成功を生成しないUI入力です。
		PreparedInstallResolution		   resolution{} ;	// 元選択へ戻す明示的な停止区分です。
		resolution.originalIdentity = window.candidates_[2].identity ;
		resolution.state			= PreparedInstallResolutionState::DOWNGRADE_REQUIRES_SELECTION ;
		result.installResolutions.push_back( resolution) ;
		window.continuePreparedInstall( result) ;
		DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty() &&
										window.preparationResultText_.find(
											window.loadString( IDS_INSTALL_PREPARATION_DOWNGRADE)) !=
											std::wstring::npos) ;
	}
	/**
	 * @brief 正常scanから検査済み旧版または拒否候補の閲覧/取消しを確認する表示入力です。
	 * @param[in,out] window 元fake workerの所有Windowです。
	 * @param[in,out] context 正常scanの集計先です。
	 * @param[in] blocked trueなら非適合で選択不可の索引候補へします。
	 */
	static void historyLocalScan( MainWindow &window, test::TestContext &context,
								 const bool blocked = false)
	{
		const auto begin = window.controller_.beginScan() ;	// 正規の新scan遷移です。
		DRIVERCRATE_EXPECT( context, begin.accepted) ;
		UpdateCandidate current = window.candidates_.front() ;	// 元有効現在観測を再利用します。
		constexpr ScanSessionId session			 = 7742U ;		// この新scanだけの同sessionです。
		current.deviceObservation->scanSessionId = session ;
		UpdateCandidate candidate{} ;	// 通常Driver Storeの有効な委譲候補です。
		candidate.identity		  = L"history-local-old" ;
		candidate.deviceIdentity  = current.deviceIdentity ;
		candidate.model			  = current.model ;
		candidate.deviceClassGuid = current.deviceClassGuid ;
		candidate.title			  = L"Fixture validated older driver" ;
		candidate.version		  = L"1.0.0.0" ;
		candidate.driverDate	  = L"10/01/2026" ;
		candidate.sourceName	  = L"Windows Driver Store" ;
		candidate.providerId	  = DRIVER_STORE_PROVIDER_ID ;
		candidate.discoveryBasis  = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
		candidate.action		  = DriverAction::DOWNGRADE ;
		candidate.installable	  = true ;
		candidate.audit			  = makeWindowsManagedCandidateAudit( false) ;
		// 非適合は取得計画なしの非導入候補として、既auditの拒否を維持します。
		if( blocked) {
			candidate.providerId	 = SIGNED_INDEX_PROVIDER_ID ;
			candidate.discoveryBasis = CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
			candidate.action		 = DriverAction::NONE ;
			candidate.installable	 = false ;
			candidate.audit			 = makeOfficialDiscoveryCandidateAudit() ;
			candidate.audit.systemApplicability = CandidateAuditGateState::REJECTED ;
			candidate.audit.installReadiness	= CandidateInstallReadiness::BLOCKED ;
		}

		// 有効な同sessionの現在観測と候補を渡すscan終端です。
		WorkerEvent event{.kind		   = WorkerEventKind::SCAN_COMPLETED,
						  .operationId = begin.operationId,
						  .scanResult  = {.succeeded	 = true,
										  .scanSessionId = session,
										  .outcome		 = OutcomeCode::SUCCESS,
										  .candidates	 = {current, candidate}}} ;
		DRIVERCRATE_EXPECT( context,
						   isCandidateDetailsSetValid( event.scanResult.candidates, session)) ;
		window.processWorkerEvent( event) ;
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::SCAN_READY &&
										window.candidates_.size() == 2U) ;

		window.showRecommendedOnly_ = false ;
		window.populateCandidates( window.candidates_) ;
	}
	/**
	 * @brief 元同scanの二参照へ表示同一性と一field差だけを置きます。
	 * @param[in,out] window 元planと候補を保持するWindowです。
	 * @param[in,out] context 元候補/選択の集計先です。
	 * @param[in] variant 0は同内容、1〜6は別情報、7は個別結果です。
	 */
	static void historyDisplayVariant( MainWindow &window, test::TestContext &context,
									  const unsigned variant)
	{
		const auto secondIdentity =
			window.candidates_[2].identity ;	// 元二参照のidentityを保持します。
		window.candidates_[2]						= window.candidates_[1] ;
		window.candidates_[2].identity				= secondIdentity ;
		window.candidates_[1].detailDisplayIdentity = L"fixture-display-only" ;
		window.candidates_[2].detailDisplayIdentity = L"fixture-display-only" ;
		window.candidates_[0].detailDisplayIdentity = L"fixture-display-only" ;
		// 表示だけの一field差を元二参照の別identityへ保ちます。
		switch( variant) {
			// 根拠が異なる同表示は別情報として残します。
			case 1U:
				window.candidates_[2].detailDisplayIdentity += L"-other" ;
				break ;

			// 日付差を同versionで消しません。
			case 2U:
				window.candidates_[2].driverDate = L"11/02/2026" ;
				break ;

			// 別実packageを表示tokenだけで消しません。
			case 3U:
				window.candidates_[2].packageIdentity = L"fixture-other-package" ;
				break ;

			// 取得計画がないreadonlyを選択可能行へ吸収しません。
			case 4U:
				window.candidates_[2].preparationTargetIdentity.clear() ;
				break ;

			// 必要構成が異なる行を残します。
			case 5U:
				window.candidates_[2].requiredExtensionCount = 1U ;
				break ;

			// 表示同一性が不明の候補を残します。
			case 6U:
				window.candidates_[2].detailDisplayIdentity.clear() ;
				break ;

			// 同内容でも個別結果は別行で保持します。
			case 7U:
				window.candidateResultTexts_[2] = L"Fixture result 0x80070005" ;
				break ;

			// 正例は元二候補を同じ表示groupにします。
			default:
				break ;
		}

		window.showRecommendedOnly_ = false ;
		window.populateCandidates( window.candidates_) ;
		DRIVERCRATE_EXPECT( context,
						   window.candidates_.size() == 5U &&
							   window.candidates_[1].identity != window.candidates_[2].identity &&
							   window.controller_.preparationPlan() != nullptr) ;
		// 後出の元memberだけを明示選択し、group表示で先頭へ戻らないことを確認します。
		if( variant != 4U) {
			DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( 2U)) ;
		}
	}
	/**
	 * @brief 初期highlightの有限条件を既同scan/元planへ置きます。
	 * @param[in,out] window 元五候補の所有Windowです。
	 * @param[in,out] context 元失敗を保持する集計先です。
	 * @param[in] variant 数値/明示/暗黙/初回/readonly等の固定条件です。
	 */
	static void historyLatestVariant( MainWindow &window, test::TestContext &context,
									 const unsigned variant)
	{
		window.candidates_[0].version = L"2.1.5.7" ;
		window.candidates_[1].version = L"2.1.5.9" ;
		window.candidates_[2].version = L"2.1.5.12" ;
		window.showRecommendedOnly_	  = false ;
		// 同版再導入は新しい日付でも自動候補にしません。
		if( variant == 0U || variant == 2U || variant == 10U) {
			auto &local =
				window.candidates_[variant == 10U ? 2U : 1U] ;	// 実Windows候補の表示fakeです。
			local.version		 = variant == 10U ? L"32.0.16.2101" : L"2.1.5.7" ;
			local.driverDate	 = L"2026/01/19" ;
			local.providerId	 = DRIVER_STORE_PROVIDER_ID ;
			local.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
			local.preparationTargetIdentity.clear() ;
			local.installable = true ;
			local.action	  = variant == 10U ? DriverAction::UPDATE : DriverAction::REINSTALL ;
			local.audit		  = makeWindowsManagedCandidateAudit( false) ;
		}

		// 12対9を入力順と独立に比較します。
		if( variant == 1U) {
			std::swap( window.candidates_[1].version, window.candidates_[2].version) ;
		}

		// 最大値のtieと同内容groupは別の固定条件です。
		if( variant == 4U || variant == 17U) {
			window.candidates_[1].version = window.candidates_[2].version ;
		}

		// 同じ/古い版を日付から昇格しません。
		if( variant == 5U) {
			window.candidates_[1].version	 = L"2.1.5.7" ;
			window.candidates_[2].version	 = L"2.1.5.6" ;
			window.candidates_[1].driverDate = L"2027/01/01" ;
		}

		// suffixやoverflowを比較不能のまま残します。
		if( variant == 6U || variant == 9U || variant == 13U || variant == 14U) {
			window.candidates_[1].version.clear() ;
			window.candidates_[2].version = variant == 9U ? L"2.1.5.65536" : L"2.1.5.x" ;
		}

		// 現在版欠損と真の未導入を区別します。
		if( variant == 7U || variant == 8U || variant == 9U) {
			window.candidates_[0].version.clear() ;
			window.candidates_[0].deviceObservation->version.state = DevicePropertyReadState::EMPTY ;
			// 初回は元Code28と同観測の未導入へ結びます。
			if( variant != 7U) {
				window.candidates_[0].deviceObservation->node.statusFlags = 0x00000400U ;
				window.candidates_[0].deviceObservation->node.problemCode = 28U ;
				window.candidates_[0].deviceObservation->driverPresence =
					DeviceDriverPresence::NOT_INSTALLED ;
			}
		}

		// Windows driver版とreadonly公開番号を混ぜません。
		if( variant == 10U) {
			window.candidates_[0].version = L"32.0.15.9636" ;
			window.candidates_[1].version = L"32.0.16.1088" ;
			UpdateCandidate catalog		  = window.candidates_[1] ;	// 取得計画のない公開番号です。
			catalog.identity			  = L"fixture-readonly-catalog" ;
			catalog.title				  = L"Fixture catalog 621.14" ;
			catalog.version				  = L"621.14" ;
			catalog.preparationTargetIdentity.clear() ;
			window.candidates_.push_back( std::move( catalog)) ;
			window.candidateSelected_.push_back( false) ;
		}

		// 個別結果を新版で置換しません。
		if( variant == 11U) {
			window.candidateResultTexts_[2] = L"Fixture result 0x80070005" ;
		}

		// 現在観測なしはreportまたは初期選択なしへ戻します。
		if( variant == 13U || variant == 14U) {
			window.candidates_[0].current = false ;
			// 初期行なしの条件だけ全体reportもありません。
			if( variant == 13U) {
				window.preparationResultText_.clear() ;
			}
		}

		// 不適合と計画なしを自動候補へ昇格しません。
		if( variant == 15U) {
			window.candidates_[2].audit.systemApplicability = CandidateAuditGateState::REJECTED ;
		}

		// readonlyの公開情報は既選択可否へ任せます。
		if( variant == 16U) {
			window.candidates_[2].preparationTargetIdentity.clear() ;
		}

		// 後出の明示memberは元同内容groupの代表に残します。
		if( variant == 17U) {
			window.candidates_[2].title					= window.candidates_[1].title ;
			window.candidates_[1].detailDisplayIdentity = L"fixture-latest-group" ;
			window.candidates_[2].detailDisplayIdentity = L"fixture-latest-group" ;
		}

		DRIVERCRATE_EXPECT( context,
						   isDeviceObservationValid( *window.candidates_[0].deviceObservation)) ;
		window.populateCandidates( window.candidates_) ;
		DRIVERCRATE_EXPECT( context,
						   window.selectDeviceCandidate( variant == 4U || variant == 17U ? 2U : 1U)) ;
		auto &row =
			window.treeRows_[window.candidateRowIndexes_[1]] ;	// 元checkboxへの一件結合です。
		row.explicitCandidateChoice = variant == 2U || variant == 17U ;
	}
	/**
	 * @brief 新scanの拒否後も残る旧表示の選択を失効します。
	 * @param[in,out] window 同じprivate fake Windowです。
	 * @param[in,out] context 正規状態遷移の集計先です。
	 */
	static void historyInvalidate( MainWindow &window, test::TestContext &context)
	{
		const auto		 begin = window.controller_.beginScan() ;	// 新scanが旧sessionを失効します。
		const ScanResult failure{.succeeded = false,
								 .outcome	= OutcomeCode::FAILURE,
								 .error		= static_cast<NativeError>( E_FAIL)} ;	// 確定失敗です。
		DRIVERCRATE_EXPECT( context,
						   begin.accepted &&
							   window.controller_.completeScan( begin.operationId, failure) &&
							   window.controller_.scanSessionId() == 0U) ;
	}
	/**
	 * @brief 指定候補のEnterまたはdouble-click通知を実Windowへ送る。
	 * @param[in,out] window 合成候補を保持するWindow。
	 * @param[in] index 有効な候補index。
	 * @param[in] code NM_RETURNまたはNM_DBLCLK。
	 */
	static void openCandidateDetails( MainWindow &window, const std::size_t index, const UINT code)
	{
		TreeView_SelectItem( window.updateTree_, window.candidateItems_[index]) ;
		NMHDR notification{window.updateTree_,
						   static_cast<UINT_PTR>( GetDlgCtrlID( window.updateTree_)),
						   code} ;	// 実controlと同じ通知。
		SendMessageW(
			window.window_, WM_NOTIFY, notification.idFrom,
			reinterpret_cast<LPARAM>( &notification)) ;	// 同期通知の間だけstack上の構造体を借用する。
	}
	/**
	 * @brief 詳細が返した候補指定を元indexと一device一件の要求対象へ照合する。
	 * @param[in] window 同じ合成scanの所有Window。
	 * @param[in,out] context Assertion集計先。
	 * @param[in] first 最初のdeviceで選択した元候補index。
	 */
	static void verifyDetailChoice( const MainWindow &window, test::TestContext &context,
								   const std::size_t first)
	{
		DRIVERCRATE_EXPECT(
			context,
			window.checkedCandidateIndexes() == std::vector<std::size_t>( {first, 5U}) &&
				window.treeRows_[window.candidateRowIndexes_[first]].candidateIndex == first &&
				window.candidateItems_[0] == window.candidateItems_[3] &&
				window.candidateItems_[first] != window.candidateItems_[5]) ;
	}
	/**
	 * @brief 複数候補を未指定へ戻し、device checkboxから実詳細dialogを開く。
	 * @param[in,out] window 同じ合成scanの所有Window。
	 * @param[in,out] context Assertion集計先。
	 */
	static void checkAmbiguousDevice( MainWindow &window, test::TestContext &context)
	{
		auto &row =
			window.treeRows_[window.candidateRowIndexes_[0]] ;	// 同deviceの全候補を持つ一行。
		// 候補は削らず、最初のdeviceだけを未選択・未指定へ戻す。
		for( const auto index : row.candidateIndexes) {
			window.candidateSelected_[index] = false ;
		}

		row.hasCandidateChoice = false ;
		window.applyCandidateSelectionToTree() ;
		DRIVERCRATE_EXPECT( context,
						   !row.hasCandidateChoice &&
							   row.candidateVersion ==
								   window.formatResource( IDS_DEVICE_MULTIPLE_CANDIDATES, L"3")) ;
		TreeView_SetCheckState( window.updateTree_, window.candidateItems_[0], TRUE) ;
	}
	/**
     * @brief 古い専用終端を直接渡しても現在一覧を変更しないことを確認する。
     * @param[in,out] window 終端一覧を保持するWindow。
     * @param[in,out] context Assertion集計先。
     */
	static void verifyStale( MainWindow &window, test::TestContext &context)
	{
		const auto	before = window.candidates_.size() ;	// 保持した行数。
		WorkerEvent old ;									// 古いまたは別operationの不正packet。
		old.kind			   = WorkerEventKind::METADATA_SEARCH_COMPLETED ;
		old.operationId		   = window.controller_.activeOperationId() + 100U ;
		old.scanResult.purpose = ScanPurpose::METADATA_ONLY ;
		window.processMetadataSearchCompleted( old) ;
		DRIVERCRATE_EXPECT( context, window.candidates_.size() == before) ;
		DRIVERCRATE_EXPECT( context, window.controller_.metadataSearchSummary() != nullptr) ;
	}
	/**
     * @brief Fake workerを安全停止し、次回enqueue拒否を作る。
     * @param[in,out] window 待機中operationを持たないWindow。
     */
	static void stopWorker( MainWindow &window)
	{
		// Closeが既に所有者を解放した場合は非所有pointerを再参照しません。
		if( window.worker_ != nullptr) {
			window.worker_->stop() ;
		}
	}
	/**
     * @brief 取消し後、終端通知前にHWNDを保持しているか返す。
     * @param[in] window 終了待ち中のWindow。
     * @return Close要求を完了通知まで保持している場合true。
     */
	static bool closePending( const MainWindow &window)
	{
		return window.closeAfterMetadataSearch_ ;
	}

	/**
	 * @brief 登録済み参照とCode28初回を同じ通常filter・実controlで区別します。
	 * @param[in,out] window 完全fake factoryを持つ内部Windowです。
	 * @param[in,out] context 原失敗を保持するassertion集計先です。
	 * @note 表示専用の人工入力であり、選択後に取得・導入commandを送信しません。
	 */
	static void verifyInstalledClassification( MainWindow &window, test::TestContext &context)
	{
		struct Case {
			/// 原結果へ残す有限条件名です。
			const char			*id ;
			/// 現在版の表示値です。空を未導入と推測しません。
			const wchar_t		*currentVersion ;
			/// 同scanの元OS観測に設定する登録分類です。
			DeviceDriverPresence presence ;
			/// 0は未取得、1/2/3は同版/新版/旧版、4/5はWUA/Storeの既存候補です。
			unsigned			 kind{} ;
			/// 1/2/3は旧session/別device/不正node観測です。
			unsigned			 mutation{} ;
			/// 通常filter内へ残る二deviceを期待する場合trueです。
			bool				 visible{} ;
		} ;
		const std::array cases{
			Case{"installed-pending-image", L"1.9.74.0", DeviceDriverPresence::REGISTERED},
			Case{"newer-pending-confirmation", L"1.9.74.0", DeviceDriverPresence::REGISTERED, 6U,
				 0U, true},
			Case{"same-pending-information", L"1.9.74.0", DeviceDriverPresence::REGISTERED, 7U},
			Case{"older-pending-information", L"1.9.74.0", DeviceDriverPresence::REGISTERED, 8U},
			Case{"newer-current-version-unknown", L"", DeviceDriverPresence::REGISTERED, 9U},
			Case{"registered-no-version", L"", DeviceDriverPresence::REGISTERED},
			Case{"unknown-no-version", L"", DeviceDriverPresence::UNKNOWN},
			Case{"code28-pending", L"", DeviceDriverPresence::NOT_INSTALLED, 0U, 0U, true},
			Case{"code28-old-key-version", L"1.9.74.0", DeviceDriverPresence::NOT_INSTALLED, 0U, 0U,
				 true},
			Case{"stale-observation", L"", DeviceDriverPresence::NOT_INSTALLED, 0U, 1U},
			Case{"other-device-observation", L"", DeviceDriverPresence::NOT_INSTALLED, 0U, 2U},
			Case{"invalid-node-observation", L"", DeviceDriverPresence::NOT_INSTALLED, 0U, 3U},
			Case{"same-version-ready", L"1.9.74.0", DeviceDriverPresence::REGISTERED, 1U},
			Case{"new-version-ready", L"1.9.74.0", DeviceDriverPresence::REGISTERED, 2U, 0U, true},
			Case{"old-version-ready", L"1.9.74.0", DeviceDriverPresence::REGISTERED, 3U},
			Case{"wua-applicable-same-version", L"1.9.74.0", DeviceDriverPresence::REGISTERED, 4U,
				 0U, true},
			Case{"store-recommended-update", L"1.9.74.0", DeviceDriverPresence::REGISTERED, 5U, 0U,
				 true}} ;									// 画像相当・未知・根拠ある初回と正当な新候補の固定十三条件です。
		const auto	before	 = context.assertionCount() ;	// この有限matrixの元分母です。
		const auto	failures = context.failureCount() ;		// 前段の失敗を隠しません。
		std::size_t ordinal{} ;								// 条件ごとの新sessionを発行する連番です。
		// 各条件へ同名の別device二件を与え、表示名による統合を検出します。
		for( const auto &item : cases) {
			const auto caseFailures = context.failureCount() ;			// 条件別の元失敗数です。
			const auto begin		= window.controller_.beginScan() ;	// 実状態機械の通常開始です。
			DRIVERCRATE_EXPECT( context, begin.accepted) ;
			// 不成立のoperationへ偽の終端を送信しません。
			if( !begin.accepted) {
				continue ;
			}

			const ScanSessionId session = 2100U + ++ordinal ;	// 一条件だけに結合するsessionです。
			OfficialPreparationTarget target ;					// 二deviceで共有する元取得対象です。
			target.identity		   = L"classification-target" ;
			target.providerId	   = SIGNED_INDEX_PROVIDER_ID ;
			target.resourceId	   = L"classification-resource" ;
			target.releaseIdentity = L"package-release-99.0" ;
			target.parserRevision  = 1U ;
			target.maximumBytes	   = 4096U ;
			target.deviceCount	   = 2U ;
			target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
			WorkerEvent event{.kind			   = WorkerEventKind::SCAN_COMPLETED,
							  .operationId	   = begin.operationId,
							  .scanResult	   = {.succeeded	 = true,
												  .scanSessionId = session,
												  .outcome		 = OutcomeCode::SUCCESS},
							  .preparationPlan = OfficialPreparationPlan{
								  session,
								  session,
								  {4096U, 4096U, 4096U, 1U, 1U},
								  {target}}} ;	// network・実deviceを使わない表示入力です。
			// 二つのopaque identityを別行にし、現在版と配布版を転記しません。
			for( unsigned index{}; index < 2U; ++index) {
				UpdateCandidate current ;	// 架空の現在観測とWindows種類です。
				current.identity		= L"classification-current-" + std::to_wstring( index) ;
				current.deviceIdentity	= L"classification-device-" + std::to_wstring( index) ;
				current.model			= L"Ethernet adapter" ;
				current.deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
				current.current			= true ;
				current.version			= item.currentVersion ;
				current.providerId		= DRIVER_STORE_PROVIDER_ID ;
				current.discoveryBasis	= CandidateDiscoveryBasis::LOCAL_INVENTORY ;
				current.audit			= makeWindowsManagedCandidateAudit( true) ;
				DeviceObservation observed ;	// 生IDを含まない、同sessionの有限観測です。
				observed.scanSessionId	  = session ;
				observed.deviceIdentity	  = current.deviceIdentity ;
				observed.driverPresence	  = item.presence ;
				observed.node.read.state  = DevicePropertyReadState::VALUE ;
				observed.node.statusFlags = 0U ;
				// 明示Code28を、空のversionから独立した未導入根拠にします。
				if( item.presence == DeviceDriverPresence::NOT_INSTALLED) {
					observed.node.statusFlags = 0x400U ;
					observed.node.problemCode = 28U ;
				}

				// Code28時の古いkey残存は既存観測契約で許されます。
				if( item.presence == DeviceDriverPresence::REGISTERED || !current.version.empty()) {
					observed.driverKey.state = DevicePropertyReadState::VALUE ;
				}

				observed.version.state = current.version.empty() ? DevicePropertyReadState::NOT_READ
																 : DevicePropertyReadState::VALUE ;
				DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observed)) ;
				current.deviceObservation = observed ;
				event.scanResult.candidates.push_back( current) ;
				UpdateCandidate candidate ;	// 元target結合は、版や適用性の成功ではありません。
				candidate.identity		  = L"classification-reference-" + std::to_wstring( index) ;
				candidate.deviceIdentity  = current.deviceIdentity ;
				candidate.model			  = current.model ;
				candidate.deviceClassGuid = current.deviceClassGuid ;
				candidate.providerId	  = SIGNED_INDEX_PROVIDER_ID ;
				candidate.discoveryBasis =
					CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
				candidate.preparationTargetIdentity = target.identity ;
				candidate.audit						= makeOfficialDiscoveryCandidateAudit() ;
				event.scanResult.candidates.push_back( std::move( candidate)) ;
			}

			window.showRecommendedOnly_ = true ;
			SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_CHECKED, 0) ;
			window.processWorkerEvent( event) ;
			DRIVERCRATE_EXPECT( context,
							   window.controller_.state() == ApplicationState::SCAN_READY &&
								   window.candidates_.size() == 4U) ;
			// 不受理の入力を後段の人工更新で成功へ補完しません。
			if( window.candidates_.size() != 4U) {
				continue ;
			}

			// 不正観測と検証後actionはUI表示copyだけへ与え、worker許可を生成しません。
			for( unsigned index{}; index < 2U; ++index) {
				auto &current	= window.candidates_[index * 2U] ;		// 同じ人工deviceの元現在行です。
				auto &candidate = window.candidates_[index * 2U + 1U] ;	// 同deviceの候補です。
				// 旧sessionの明示Code28を現scanへ流用できません。
				if( item.mutation == 1U) {
					--current.deviceObservation->scanSessionId ;
				}
				// 別deviceのCode28を名前一致で転用できません。
				else if( item.mutation == 2U) {
					current.deviceObservation->deviceIdentity = L"another-device" ;
				}
				// DN_HAS_PROBLEMなしのproblem値は観測不正です。
				else if( item.mutation == 3U) {
					current.deviceObservation->node.statusFlags = 0U ;
				}

				// 後段actionの表示試験は、実取得・適用性判定の代用にしません。
				if( item.kind != 0U && item.kind <= 5U) {
					candidate.installable	   = true ;
					candidate.allContentCached = true ;
					candidate.audit			   = makeOfficialReadyCandidateAudit() ;
					candidate.action		   = item.kind == 1U   ? DriverAction::REINSTALL
												 : item.kind == 3U ? DriverAction::DOWNGRADE
																   : DriverAction::UPDATE ;
					candidate.version		   = item.kind == 2U || item.kind == 5U ? L"2.0.0.0"
												 : item.kind == 3U					? L"1.0.0.0"
																					: L"1.9.74.0" ;
					// OSが適用可能とした候補はUI独自の同版比較で消しません。
					if( item.kind >= 4U) {
						candidate.providerId =
							item.kind == 4U ? WINDOWS_UPDATE_PROVIDER_ID : DRIVER_STORE_PROVIDER_ID ;
						candidate.discoveryBasis = item.kind == 4U
													   ? CandidateDiscoveryBasis::MANAGED_SERVICE
													   : CandidateDiscoveryBasis::LOCAL_INVENTORY ;
						candidate.preparationTargetIdentity.clear() ;
						candidate.recommended = true ;
						candidate.audit		  = makeWindowsManagedCandidateAudit( false) ;
					}
				}

				// Workerの限定投影後と同じ版情報だけを人工参照へ与えます。
				if( item.kind >= 6U) {
					candidate.version = item.kind == 7U	  ? item.currentVersion
										: item.kind == 8U ? L"1.0.0.0"
														  : L"2.0.0.0" ;
				}
			}

			// 非推奨のStore候補が新版metadata参照の既定代表を上書きしないことを確認します。
			if( item.kind == 6U) {
				auto store			 = window.candidates_[1] ;	// 同deviceの別経路候補です。
				store.identity		 = L"classification-nonrecommended-store" ;
				store.providerId	 = DRIVER_STORE_PROVIDER_ID ;
				store.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
				store.preparationTargetIdentity.clear() ;
				store.installable = true ;
				store.action	  = DriverAction::UPDATE ;
				store.audit		  = makeWindowsManagedCandidateAudit( false) ;
				window.candidates_.push_back( std::move( store)) ;
				window.candidateSelected_.push_back( false) ;
			}

			// 新版と同版が同deviceに混在しても、filterの代表は新版だけに結合します。
			if( item.kind == 2U) {
				auto same = window.candidates_[1] ;	// 同じ元deviceの同版候補を保持する表示copyです。
				same.identity += L"-same-version" ;
				same.action	 = DriverAction::REINSTALL ;
				same.version = item.currentVersion ;
				window.candidates_.push_back( std::move( same)) ;
				window.candidateSelected_.push_back( false) ;
			}

			window.populateCandidates( window.candidates_) ;
			window.updateScanSummaryStatus() ;
			window.updateCommandState() ;
			const auto visibleCount =
				// 分類一行と別device二行です。
				TreeView_GetCount( window.updateTree_) ;
			wchar_t status[2048]{} ;	// 最下段の実control本文です。
			GetWindowTextW( window.status_, status, 2048) ;
			const auto ready = item.visible && item.kind != 0U && item.kind <= 5U
								   ? 2U
								   : 0U ;	// 未取得を検査済みに数えません。
			DRIVERCRATE_EXPECT( context, visibleCount == (item.visible ? 3U : 0U)) ;
			DRIVERCRATE_EXPECT( context,
							   item.kind == 6U ||
								   std::wstring_view{status}.find( window.formatResource(
									   IDS_STATUS_RECOMMENDED_COUNT, std::to_wstring( ready))) !=
									   std::wstring_view::npos) ;
			// 新版参照を実導入候補0件だけと案内せず、確認数を独立表示します。
			if( item.kind == 6U) {
				const auto &row =
					window.treeRows_[window.candidateRowIndexes_[1]] ;	// 実checkboxの代表です。
				DRIVERCRATE_EXPECT(
					context,
					std::wstring_view{status}.find( window.formatResource(
						IDS_STATUS_UPDATE_CONFIRMATION_COUNT, L"2")) != std::wstring_view::npos &&
						std::wstring_view{status}.find( window.formatResource(
							IDS_STATUS_RECOMMENDED_COUNT, L"0")) == std::wstring_view::npos) ;
				DRIVERCRATE_EXPECT(
					context,
					row.hasCandidateChoice && row.candidateIndex == 1U &&
						row.candidateVersion ==
							window.formatResource( IDS_REFERENCE_VERSION_FORMAT, L"2.0.0.0") &&
						!window.candidates_[1].installable && !window.candidates_[1].recommended &&
						window.candidates_[1].action == DriverAction::NONE) ;
			}

			DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes().empty() &&
											!IsWindowEnabled( window.installButton_)) ;
			const auto pendingFirst =
				item.visible && item.kind == 0U ? 2U : 0U ;	// 未検査の初回確認だけの別件数です。
			const auto initialText = window.formatResource(
				IDS_STATUS_INITIAL_PREPARATION_COUNT, L"2") ;	// 検査済み件数へ混ぜない本文です。
			DRIVERCRATE_EXPECT( context, (std::wstring_view{status}.find( initialText) !=
										 std::wstring_view::npos) == (pendingFirst != 0U)) ;
			DRIVERCRATE_EXPECT(
				context, std::wstring_view{status}.find( window.loadString(
							 IDS_STATUS_PREPARATION_REQUIRED)) != std::wstring_view::npos &&
							 std::wstring_view{status}.find( L"最新") == std::wstring_view::npos) ;

			// 隠した参照の元データと全候補の明示選択を維持します。
			for( unsigned index{}; index < 2U; ++index) {
				const auto ordinalIndex = index * 2U + 1U ;	// 当該deviceだけの候補位置です。
				DRIVERCRATE_EXPECT( context, (window.candidateItems_[ordinalIndex] != nullptr) ==
												item.visible) ;
				// 非表示行を詳細から選択可能へすり抜けさせません。
				if( !item.visible) {
					DRIVERCRATE_EXPECT( context, !window.selectDeviceCandidate( ordinalIndex)) ;
				}
			}

			SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
			window.handleRecommendedFilterChange() ;
			DRIVERCRATE_EXPECT( context, TreeView_GetCount( window.updateTree_) == 3U &&
											window.candidateItems_[1] != window.candidateItems_[3]) ;
			// 未確認・同版・旧版は既定代表やcheckboxへしません。
			for( unsigned index : {1U, 3U}) {
				const auto &row =
					window.treeRows_[window.candidateRowIndexes_[index]] ;	// 元deviceの行です。
				DRIVERCRATE_EXPECT(
					context,
					row.hasCandidateChoice == item.visible &&
						((TreeView_GetItemState( window.updateTree_, window.candidateItems_[index],
												TVIS_STATEIMAGEMASK) != 0U) == item.visible)) ;
			}

			DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( 1U) &&
											window.selectDeviceCandidate( 3U)) ;
			TreeView_SetCheckState( window.updateTree_, window.candidateItems_[1], TRUE) ;
			window.handleTreeCheckChange( window.candidateItems_[1], true) ;
			TreeView_SetCheckState( window.updateTree_, window.candidateItems_[3], TRUE) ;
			window.handleTreeCheckChange( window.candidateItems_[3], true) ;
			DRIVERCRATE_EXPECT( context, window.checkedCandidateIndexes() ==
											std::vector<std::size_t>( {1U, 3U})) ;
			DRIVERCRATE_EXPECT( context,
							   window.treeRows_[window.candidateRowIndexes_[1]].currentVersion ==
								   (std::wstring_view{item.currentVersion}.empty()
										? window.loadString( IDS_VALUE_UNKNOWN)
										: item.currentVersion)) ;
			// 同版の明示選択は全候補表示で保持し、filter復帰で新版の代表へ戻します。
			if( item.kind == 2U) {
				DRIVERCRATE_EXPECT(
					context,
					window.selectDeviceCandidate( 4U) &&
						window.treeRows_[window.candidateRowIndexes_[4]].candidateVersion ==
							item.currentVersion) ;
			}

			// 全候補で選んだ非推奨Storeを推奨filter復帰で既定へ残しません。
			if( item.kind == 6U) {
				DRIVERCRATE_EXPECT( context, window.selectDeviceCandidate( 4U)) ;
			}

			window.clearCandidateSelection() ;
			SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_CHECKED, 0) ;
			window.handleRecommendedFilterChange() ;
			DRIVERCRATE_EXPECT( context,
							   TreeView_GetCount( window.updateTree_) == (item.visible ? 3U : 0U) &&
								   window.checkedCandidateIndexes().empty()) ;
			// 同じ元targetの新版参照だけをcheckbox代表へ戻します。
			if( item.kind == 6U) {
				const auto &row =
					window.treeRows_[window.candidateRowIndexes_[1]] ;	// 同じdeviceの元行です。
				DRIVERCRATE_EXPECT( context, row.hasCandidateChoice && row.candidateIndex == 1U &&
												!window.selectDeviceCandidate( 4U)) ;
			}

			// 非表示の同版をcheckboxや詳細指定から選び直さず、検査済み新版を代表へ残します。
			if( item.kind == 2U) {
				const auto &row =
					window.treeRows_[window.candidateRowIndexes_[1]] ;	// 同deviceの一行です。
				DRIVERCRATE_EXPECT( context, row.hasCandidateChoice && row.candidateIndex == 1U &&
												row.candidateVersion == L"2.0.0.0" &&
												!window.selectDeviceCandidate( 4U)) ;
			}

			std::cout << "CLASSIFICATION case=" << item.id << " tree=" << visibleCount
					  << " ready=" << ready << " failures=" << context.failureCount() - caseFailures
					  << " realOS=0\n" ;
		}

		std::cout << "CLASSIFICATION_END cases=" << cases.size()
				  << " assertions=" << context.assertionCount() - before
				  << " failures=" << context.failureCount() - failures << '\n' ;
	}

	/**
	 * @brief 再検出段階・終端事実・未取得metadata案内と旧通知拒否を確認します。
	 * @param[in,out] window 実native処理を持たないfake Windowです。
	 * @param[in,out] context Assertion集計先です。
	 */
	static void verifyHardwareRefresh( MainWindow &window, test::TestContext &context)
	{
		const auto begin = window.controller_.beginScan() ;	// 同じ通常状態機械を使用します。
		DRIVERCRATE_EXPECT( context, begin.accepted && !window.controller_.beginScan().accepted) ;
		// 開始できなかった場合に偽の終端を適用しません。
		if( !begin.accepted) {
			return ;
		}

		WorkerEvent progress{.kind		  = WorkerEventKind::PROGRESS,
							 .operationId = begin.operationId,
							 .progress	  = {ProviderStage::REFRESHING_HARDWARE, 0U, 0U,
											 1U}} ;	// 同operationの事実入力です。
		window.processWorkerEvent( progress) ;
		DRIVERCRATE_EXPECT( context, window.statusBusy_ && window.statusPercentage_ == 0U) ;
		progress.progress.completedItems  = 1U ;
		progress.progress.percentComplete = 5U ;
		window.processWorkerEvent( progress) ;
		wchar_t status[2048]{} ;	// 既存status controlを読む有限領域です。
		GetWindowTextW( window.status_, status, 2048) ;
		DRIVERCRATE_EXPECT( context, window.statusPercentage_ == 5U &&
										std::wstring_view{status}.find( L"1 / 1") !=
											std::wstring_view::npos &&
										std::wstring_view{status}.find( L"ハードウェア") !=
											std::wstring_view::npos) ;
		++progress.operationId ;
		progress.progress.percentComplete = 99U ;
		window.processWorkerEvent( progress) ;
		DRIVERCRATE_EXPECT( context, window.statusPercentage_ == 5U) ;
		OfficialPreparationTarget target ;	// 未取得の配布情報だけです。
		target.identity		   = L"hardware-ui-target" ;
		target.providerId	   = SIGNED_INDEX_PROVIDER_ID ;
		target.resourceId	   = L"fixture-resource" ;
		target.releaseIdentity = L"fixture-release" ;
		target.parserRevision  = 1U ;
		target.maximumBytes	   = 4096U ;
		target.deviceCount	   = 1U ;
		target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
		WorkerEvent event{
			.kind		 = WorkerEventKind::SCAN_COMPLETED,
			.operationId = begin.operationId,
			.scanResult	 = {.succeeded	   = true,
							.scanSessionId = 701U,
							.outcome	   = OutcomeCode::SUCCESS},
			.preparationPlan =
				OfficialPreparationPlan{701U, 1U, {4096U, 4096U, 4096U, 1U, 1U}, {target}},
			.hardwareRefresh =
				HardwareRefreshResult{true, HardwareRefreshStage::REENUMERATE}} ;	// 合成終端です。
		UpdateCandidate current ;													// 名称/class欠損でも現在行を残す基礎です。
		current.identity	   = L"hardware-ui-current" ;
		current.deviceIdentity = L"hardware-ui-device" ;
		current.model		   = L"Ethernet Controller" ;
		current.current		   = true ;
		current.providerId	   = DRIVER_STORE_PROVIDER_ID ;
		current.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
		current.audit		   = makeWindowsManagedCandidateAudit( true) ;
		event.scanResult.candidates.push_back( current) ;
		UpdateCandidate metadata ;	// 未検査を導入許可へ昇格しない行です。
		metadata.identity		= L"hardware-ui-metadata" ;
		metadata.deviceIdentity = current.deviceIdentity ;
		metadata.model			= current.model ;
		metadata.providerId		= SIGNED_INDEX_PROVIDER_ID ;
		metadata.discoveryBasis = CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
		metadata.audit			= makeOfficialDiscoveryCandidateAudit() ;
		event.scanResult.candidates.push_back( metadata) ;
		window.processWorkerEvent( event) ;
		GetWindowTextW( window.status_, status, 2048) ;
		DRIVERCRATE_EXPECT(
			context,
			window.controller_.state() == ApplicationState::SCAN_READY &&
				window.controller_.preparationPlan() && window.checkedCandidateIndexes().empty() &&
				IsWindowEnabled( window.installButton_) == FALSE &&
				GetDlgItem( window.window_, IDC_PREPARATION) == nullptr &&
				std::wstring_view{status}.find( L"取得前情報") != std::wstring_view::npos &&
				std::wstring_view{status}.find( L"適用性") != std::wstring_view::npos &&
				std::wstring_view{status}.find( L"再検出: 完了") != std::wstring_view::npos) ;
		const std::wstring accepted{status} ;	// 旧結果で上書きされない本文です。
		++event.operationId ;
		event.hardwareRefresh->succeeded = false ;
		window.processWorkerEvent( event) ;
		GetWindowTextW( window.status_, status, 2048) ;
		DRIVERCRATE_EXPECT( context, std::wstring_view{status} == accepted &&
										window.hardwareRefresh_->succeeded) ;
		// 同じ失敗formatterが元CONFIGRETをWin32と取り違えません。
		window.hardwareRefresh_ =
			HardwareRefreshResult{false, HardwareRefreshStage::REENUMERATE,
								  HardwareRefreshErrorDomain::CONFIGURATION_MANAGER, 5} ;
		DRIVERCRATE_EXPECT( context, window.formatHardwareRefreshSummary().find( L"CONFIGRET") !=
											std::wstring::npos &&
										window.formatHardwareRefreshSummary().find(
											L"検索は開始していません") != std::wstring::npos) ;
		window.hardwareRefresh_ = HardwareRefreshResult{true, HardwareRefreshStage::REENUMERATE} ;
	}

	/**
	 * @brief 取得待ち案内を混在候補数・filterと分離し、取得能力がない場合は表示しません。
	 * @param[in,out] window 先行するhardware表示試験を終えた非通信Windowです。
	 * @param[in,out] context Assertion集計先です。
	 */
	static void verifyPreparationGuidance( MainWindow &window, test::TestContext &context)
	{
		/** @brief 既存の取得準備能力と候補構成を固定する表示条件です。 */
		struct Case {
			/// 導入可能な他device候補の実表示件数です。
			std::size_t readyCount{} ;
			/// 未取得metadataとその現在行を二device分保持する場合trueです。
			bool		metadata{} ;
			/// 未使用の取得計画を同じscanへ発行する場合trueです。
			bool		preparation{} ;
			/// 推奨候補だけを表示するfilterです。
			bool		recommendedOnly{} ;
			/// 件数案内と併記する元scan分類です。
			OutcomeCode outcome{OutcomeCode::SUCCESS} ;
		} ;
		const std::array cases{
			Case{59U, true, true, false, OutcomeCode::SUCCEEDED_WITH_ERRORS},
			Case{0U, true, true},
			Case{59U, false, false},
			Case{0U, true, false},
			Case{59U, true, true, true},
			Case{0U, true, true, true},
			Case{0U, false,
				 false}} ;	// 混在/metadataのみ/なし/取得能力なし/filterを固定する七条件です。
		const auto guidance =
			// 比較する既存本文です。
			window.loadString( IDS_STATUS_PREPARATION_REQUIRED) ;
		std::size_t caseIndex{} ;	// 同じWindowでも新しいsessionを発行する番号です。
		// 七条件を順番に適用し、前回の計画や選択を新scanへ継承しません。
		for( const auto &testCase : cases) {
			const auto begin = window.controller_.beginScan() ;	// 通常状態機械の新しい操作です。
			DRIVERCRATE_EXPECT( context, begin.accepted) ;
			// 失敗した開始へ偽の終端を適用しません。
			if( !begin.accepted) {
				continue ;
			}

			const ScanSessionId session = 800U + ++caseIndex ;	// この条件だけの正のsessionです。
			WorkerEvent			event{.kind			   = WorkerEventKind::SCAN_COMPLETED,
									  .operationId	   = begin.operationId,
									  .scanResult	   = {.succeeded	 = true,
														  .scanSessionId = session,
														  .outcome		 = testCase.outcome},
									  .hardwareRefresh = HardwareRefreshResult{
								  true, HardwareRefreshStage::REENUMERATE}} ;	// 表示だけの入力です。
			// 元59件を他deviceの選択可能候補として保持し、metadataへ件数を移しません。
			for( std::size_t index = 0U; index < testCase.readyCount; ++index) {
				UpdateCandidate ready ;	// 未選択の架空Driver Store候補です。
				ready.identity		 = L"guidance-ready-" + std::to_wstring( index) ;
				ready.deviceIdentity = L"guidance-ready-device-" + std::to_wstring( index) ;
				ready.model			 = L"Driver Store fixture" ;
				ready.providerId	 = DRIVER_STORE_PROVIDER_ID ;
				ready.action		 = DriverAction::UPDATE ;
				ready.installable	 = true ;
				ready.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
				ready.audit			 = makeWindowsManagedCandidateAudit( false) ;
				event.scanResult.candidates.push_back( std::move( ready)) ;
			}

			// 同名の別device二件を現在行と未検査metadataのまま保持します。
			if( testCase.metadata) {
				// 二件だけを生成し、実機の名前・instanceを使用しません。
				for( std::size_t index = 0U; index < 2U; ++index) {
					UpdateCandidate current ;	// 端末内の現在行に相当する人工入力です。
					current.identity	   = L"guidance-current-" + std::to_wstring( index) ;
					current.deviceIdentity = L"guidance-pending-device-" + std::to_wstring( index) ;
					current.model		   = L"Ethernet Controller" ;
					current.current		   = true ;
					current.providerId	   = DRIVER_STORE_PROVIDER_ID ;
					current.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
					current.audit		   = makeWindowsManagedCandidateAudit( true) ;
					event.scanResult.candidates.push_back( current) ;
					UpdateCandidate metadata ;	// 導入権限やcheckboxを持たない配布情報です。
					metadata.identity		= L"guidance-metadata-" + std::to_wstring( index) ;
					metadata.deviceIdentity = current.deviceIdentity ;
					metadata.model			= current.model ;
					metadata.providerId		= SIGNED_INDEX_PROVIDER_ID ;
					metadata.discoveryBasis =
						CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
					metadata.audit = makeOfficialDiscoveryCandidateAudit() ;
					event.scanResult.candidates.push_back( std::move( metadata)) ;
				}
			}

			// 取得結果の閲覧だけと、未使用の取得準備能力を区別します。
			if( testCase.preparation) {
				OfficialPreparationTarget
					target ;	// 一つの共有取得対象に二deviceを結合した入力です。
				target.identity		   = L"guidance-target" ;
				target.providerId	   = SIGNED_INDEX_PROVIDER_ID ;
				target.resourceId	   = L"guidance-resource" ;
				target.releaseIdentity = L"guidance-release" ;
				target.parserRevision  = 1U ;
				target.maximumBytes	   = 4096U ;
				target.deviceCount	   = 2U ;
				target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
				event.preparationPlan  = OfficialPreparationPlan{
					 session, session, {4096U, 4096U, 4096U, 1U, 1U}, {target}} ;
			}

			window.showRecommendedOnly_ = testCase.recommendedOnly ;
			window.processWorkerEvent( event) ;
			wchar_t status[2048]{} ;	// 本物のstatus controlを読む有限領域です。
			GetWindowTextW( window.status_, status, 2048) ;
			const std::wstring text{status} ;						// 一回の更新で確定した表示本文です。
			const auto		   position = text.find( guidance) ;	// 既存案内の最初の出現位置です。
			DRIVERCRATE_EXPECT( context,
							   window.controller_.state() == ApplicationState::SCAN_READY &&
								   (window.controller_.preparationPlan() != nullptr) ==
									   testCase.preparation) ;
			DRIVERCRATE_EXPECT( context, testCase.preparation
											? position != std::wstring::npos &&
												  text.find( guidance, position + guidance.size()) ==
													  std::wstring::npos
											: position == std::wstring::npos) ;
			const auto readyCount = std::count_if(
				window.candidates_.begin(), window.candidates_.end(), []( const auto &candidate) {
					return candidate.installable ;
				}) ; // 導入可能数だけです。
			DRIVERCRATE_EXPECT( context,
							   static_cast<std::size_t>( readyCount) == testCase.readyCount &&
								   window.candidates_.size() ==
									   testCase.readyCount + (testCase.metadata ? 4U : 0U) &&
								   window.checkedCandidateIndexes().empty() &&
								   IsWindowEnabled( window.installButton_) == FALSE) ;
			// 他候補の件数/部分失敗やfilterの案内を、新しい取得待ち文言で消しません。
			if( testCase.readyCount != 0U || testCase.recommendedOnly) {
				const auto summary = window.formatResource(
					testCase.recommendedOnly ? IDS_STATUS_RECOMMENDED_COUNT
					: testCase.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS
						? IDS_STATUS_SCAN_WARNING
						: IDS_STATUS_SCAN_COUNT,
					std::to_wstring(
						testCase.recommendedOnly ? 0U : testCase.readyCount)) ;	// 元件数の本文です。
				DRIVERCRATE_EXPECT( context, text.find( summary) != std::wstring::npos) ;
			}

			// 二つの未検査候補はどちらも明示選択を拒否し、他候補から権限を継承しません。
			if( testCase.metadata) {
				DRIVERCRATE_EXPECT( context,
								   !window.selectDeviceCandidate( testCase.readyCount + 1U) &&
									   !window.selectDeviceCandidate( testCase.readyCount + 3U) &&
									   window.checkedCandidateIndexes().empty()) ;
			}
		}
	}

	/** @brief 同じitemの並び・元label・開閉とnative表示位置だけを比較する試験値です。 */
	struct InstallTreeView {
		/// Native順の分類とdevice itemです。
		std::vector<HTREEITEM>	  items ;
		/// 各itemの元表示名です。事後の名前変更で上書きしません。
		std::vector<std::wstring> labels ;
		/// 各itemの元分類keyです。
		std::vector<std::wstring> classes ;
		/// 各itemのnative開閉状態です。
		std::vector<UINT>		  expanded ;
		/// 選択行です。非所有handleの同一性だけを比較します。
		HTREEITEM				  caret{} ;
		/// 垂直表示の先頭行です。
		HTREEITEM				  first{} ;
		/// 水平scrollの元位置です。
		int						  horizontal{} ;
		/// 垂直scrollの元位置です。
		int						  vertical{} ;
	} ;
	/**
	 * @brief 自作TreeViewの二階層だけから元の表示状態を読みます。
	 * @param[in] window 同private desktopの所有Windowです。
	 * @return 結果やcheckを含まない同itemの比較値です。
	 */
	static InstallTreeView installTreeView( const MainWindow &window)
	{
		InstallTreeView view ;	// 同一Windowの同scan内だけで比較します。
		// 二階層をnative順に辿り、折りたたまれたdeviceも分母へ残します。
		for( auto category = TreeView_GetRoot( window.updateTree_); category;
			category	  = TreeView_GetNextSibling( window.updateTree_, category)) {
			auto item = category ;	// 分類から直下deviceへ一回だけ進みます。
			// 子の兄弟が尽きるまで同じ分類の順序を保存します。
			while( item) {
				TVITEMW native{} ;	// 本同期読取だけの非所有itemです。
				native.mask		= TVIF_PARAM ;
				native.hItem	= item ;
				const auto *row = TreeView_GetItem( window.updateTree_, &native)
									  ? window.treeRowFromParameter( native.lParam)
									  : nullptr ;	// 表示modelだけです。
				view.items.push_back( item) ;
				view.labels.push_back( row ? row->primaryText : L"") ;
				view.classes.push_back( row ? row->classKey : L"") ;
				const auto nativeState = TreeView_GetItemState(
					window.updateTree_, item,
					TVIS_EXPANDED) ;	// Native戻り値のmask外check bitを開閉へ混入させません。
				// 新比較の読取でmask外の状態が返る場合を非機密な原数値だけで確認します。
				if( (nativeState & ~UINT{TVIS_EXPANDED}) != 0U && view.items.size() == 2U) {
					std::cout << "INSTALL_VIEW_NATIVE_STATE raw=" << nativeState
							  << " expanded=" << (nativeState & TVIS_EXPANDED) << '\n' ;
				}

				view.expanded.push_back( nativeState & TVIS_EXPANDED) ;
				item = item == category ? TreeView_GetChild( window.updateTree_, category)
										: TreeView_GetNextSibling( window.updateTree_, item) ;
			}
		}

		view.caret		= TreeView_GetSelection( window.updateTree_) ;
		view.first		= TreeView_GetFirstVisible( window.updateTree_) ;
		view.horizontal = GetScrollPos( window.updateTree_, SB_HORZ) ;
		view.vertical	= GetScrollPos( window.updateTree_, SB_VERT) ;
		return view ;
	}
	/**
	 * @brief 結果反映の前後で元行集合・順序・表示位置が完全に同じことを確認します。
	 * @param[in] window 結果を反映した所有Windowです。
	 * @param[in] before 操作前の比較値です。
	 * @param[in,out] context このprocessの原集計先です。
	 */
	static void verifyInstallTreeView( const MainWindow &window, const InstallTreeView &before,
									  test::TestContext &context)
	{
		const auto after = installTreeView( window) ;	// native再生成を隠さない実handle比較です。
		// 差分のある場合だけ非機密な一致区分を出し、元の複合失敗を隠しません。
		if( after.items != before.items || after.labels != before.labels ||
		   after.classes != before.classes || after.expanded != before.expanded) {
			std::cout << "INSTALL_VIEW_COMPARE items=" << (after.items == before.items)
					  << " labels=" << (after.labels == before.labels)
					  << " classes=" << (after.classes == before.classes)
					  << " expanded=" << (after.expanded == before.expanded)
					  << " counts=" << before.items.size() << ',' << after.items.size() << '\n' ;
		}

		DRIVERCRATE_EXPECT( context, after.items == before.items && after.labels == before.labels &&
										after.classes == before.classes &&
										after.expanded == before.expanded) ;
		DRIVERCRATE_EXPECT( context, after.caret == before.caret && after.first == before.first &&
										after.horizontal == before.horizontal &&
										after.vertical == before.vertical) ;
	}
	/**
	 * @brief 準備で追加された候補が元同deviceのitemへ正確に結合したことを確認します。
	 * @param[in] window 準備終端を受理した所有Windowです。
	 * @param[in] originalCount 準備前の元候補数です。
	 * @param[in,out] context 元assertion集計先です。
	 */
	static void verifyPreparedRowBindings( const MainWindow &window, const std::size_t originalCount,
										  test::TestContext &context)
	{
		DRIVERCRATE_EXPECT( context, window.candidates_.size() > originalCount) ;
		// 発行された全候補を同deviceへ照合し、未結合を分母から除きません。
		for( auto index = originalCount; index < window.candidates_.size(); ++index) {
			const auto rowIndex =
				// 対応しなければ失敗する元位置です。
				window.candidateRowIndexes_.at( index) ;
			DRIVERCRATE_EXPECT( context, rowIndex < window.treeRows_.size()) ;
			// 不正位置を参照して試験を強制終了させません。
			if( rowIndex < window.treeRows_.size()) {
				const auto &row = window.treeRows_[rowIndex] ;	// 名前ではなく同deviceを比較します。
				DRIVERCRATE_EXPECT( context,
								   window.candidateItems_.at( index) != nullptr &&
									   window.candidateItems_[index] ==
										   window.candidateItems_[row.deviceIndex] &&
									   window.candidates_[index].deviceIdentity ==
										   window.candidates_[row.deviceIndex].deviceIdentity &&
									   std::ranges::find( row.candidateIndexes, index) !=
										   row.candidateIndexes.end()) ;
			}
		}
	}
	/**
	 * @brief 多数行・混在開閉・非零scrollのまま一対象だけ完了させます。
	 * @param[in,out] window 実Providerを呼ばない所有Windowです。
	 * @param[in,out] context 元assertionの集計先です。
	 * @param[in] filter 通常filterをONにする場合trueです。
	 * @param[in] deliver 元結果dialogを既driverで閉じる同期関数です。
	 */
	static void verifyScrolledInstallView( MainWindow &window, test::TestContext &context,
										  const bool filter,
										  void ( *deliver)( MainWindow &, const WorkerEvent &,
														  test::TestContext &))
	{
		const auto scan = window.controller_.beginScan() ;	// 新scanの正規入口です。
		DRIVERCRATE_EXPECT( context, scan.accepted) ;
		WorkerEvent event{
			.kind		 = WorkerEventKind::SCAN_COMPLETED,
			.operationId = scan.operationId,
			.scanResult	 = {.succeeded	   = true,
							.scanSessionId = filter ? 8801U : 8802U,
							.outcome	   = OutcomeCode::SUCCESS}} ;	// 人工の同名別deviceだけです。
		// 縦横scrollを実際に持つ有限48deviceを三分類へ分散します。
		for( unsigned index{}; index < 48U; ++index) {
			UpdateCandidate current ;	// 元classと表示名は事後変更させません。
			current.identity	   = L"view-current-" + std::to_wstring( index) ;
			current.deviceIdentity = L"view-device-" + std::to_wstring( index) ;
			current.model =
				L"Fixture adapter with a deliberately long display name to retain the horizontal scroll position " ;
			current.deviceClassGuid = index % 3U == 0U	 ? L"{4d36e972-e325-11ce-bfc1-08002be10318}"
									  : index % 3U == 1U ? L"{4d36e96c-e325-11ce-bfc1-08002be10318}"
														 : L"" ;
			current.version			= std::to_wstring( index + 1U) ;
			current.current			= true ;
			current.providerId		= DRIVER_STORE_PROVIDER_ID ;
			current.discoveryBasis	= CandidateDiscoveryBasis::LOCAL_INVENTORY ;
			current.audit			= makeWindowsManagedCandidateAudit( true) ;
			event.scanResult.candidates.push_back( current) ;
			// 元filterで隠れる現在行を一つ残し、終端で勝手に追加しないことを確認します。
			if( index != 47U) {
				auto candidate		  = current ;	// 同deviceの独立した元選択候補です。
				candidate.identity	  = L"view-candidate-" + std::to_wstring( index) ;
				candidate.current	  = false ;
				candidate.version	  = L"2.0.0.0" ;
				candidate.installable = true ;
				candidate.recommended = true ;
				candidate.action	  = DriverAction::UPDATE ;
				candidate.audit		  = makeWindowsManagedCandidateAudit( false) ;
				event.scanResult.candidates.push_back( candidate) ;
			}
		}

		window.showRecommendedOnly_ = filter ;
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK,
					 filter ? BST_CHECKED : BST_UNCHECKED, 0) ;
		window.sortedColumn_  = 1U ;
		window.sortAscending_ = false ;
		window.processWorkerEvent( event) ;
		DRIVERCRATE_EXPECT( context,
						   window.selectDeviceCandidate( 1U) && window.selectDeviceCandidate( 3U)) ;
		// 名前の同じ別deviceを別itemで保持し、一対象の完了を他へ伝播しません。
		DRIVERCRATE_EXPECT( context, window.candidateItems_[1] != window.candidateItems_[3]) ;
		// MEDIAだけを閉じ、他分類には縦scrollできるだけの行を表示します。
		for( auto category = TreeView_GetRoot( window.updateTree_); category;
			category	  = TreeView_GetNextSibling( window.updateTree_, category)) {
			TreeView_Expand(
				window.updateTree_, category,
				category == TreeView_GetParent( window.updateTree_, window.candidateItems_[3])
					? TVE_COLLAPSE
					: TVE_EXPAND) ;
		}

		TreeView_SelectItem( window.updateTree_, window.candidateItems_[1]) ;
		TreeView_SelectSetFirstVisible( window.updateTree_, window.candidateItems_[36]) ;
		SendMessageW( window.updateTree_, WM_HSCROLL, MAKEWPARAM( SB_THUMBPOSITION, 80), 0) ;
		const auto before = installTreeView( window) ;	// 成功前の元native表示です。
		DRIVERCRATE_EXPECT( context, before.vertical > 0 && before.horizontal > 0) ;
		const std::array identity{window.candidates_[1].identity} ;	// 元一対象だけを実行へ渡します。
		const auto		 install = window.controller_.beginInstall(
			  event.scanResult.scanSessionId, identity,
			  InstallConfirmation::CONFIRMED) ;	// 実workerへ送信しません。
		DRIVERCRATE_EXPECT( context, install.accepted) ;
		InstallResult result ;	// 個別成功からだけcheckを解除します。
		result.succeeded			  = true ;
		result.downloadOutcome		  = OutcomeCode::SUCCESS ;
		result.installOutcome		  = OutcomeCode::SUCCESS ;
		result.restorePointCreation	  = {OutcomeCode::SUCCESS, 0, 7} ;
		result.restorePointCompletion = {OutcomeCode::SUCCESS, 0, 7} ;
		result.restorePointProtection = {
			.disposition	   = RestorePointDisposition::WINDOWS_SELECTED_POINT,
			.verification	   = OutcomeCode::SUCCESS,
			.sequenceNumber	   = result.restorePointCreation.sequenceNumber,
			.createdUtc		   = 1,
			.localDay		   = 20261110U,
			.verifiedBefore	   = true,
			.verifiedAfter	   = true,
			.nativeBeginCalled = true,
			.nativeEndCalled   = true} ;	// 人工DTOの明示fake実在です。
		result.updates.push_back( {.identity		   = identity.front(),
								  .downloadOutcome = OutcomeCode::SUCCESS,
								  .installOutcome  = OutcomeCode::SUCCESS,
								  .rebootRequired  = true}) ;
		PostInstallDeviceObservation observed ;	// 元deviceだけの実観測相当の所有DTOです。
		observed.observation.scanSessionId	  = event.scanResult.scanSessionId ;
		observed.observation.deviceIdentity	  = window.candidates_[1].deviceIdentity ;
		observed.observation.node.read.state  = DevicePropertyReadState::VALUE ;
		observed.observation.node.statusFlags = 8U ;
		observed.observation.driverKey.state  = DevicePropertyReadState::VALUE ;
		observed.observation.driverPresence	  = DeviceDriverPresence::REGISTERED ;
		observed.name						  = L"Changed observed name" ;
		observed.deviceClassGuid			  = L"{4d36e96c-e325-11ce-bfc1-08002be10318}" ;
		observed.version					  = L"99.0.0.0" ;
		result.currentDevices.push_back( observed) ;
		deliver( window,
				WorkerEvent{.kind		   = WorkerEventKind::INSTALL_COMPLETED,
							.operationId   = install.operationId,
							.installResult = result},
				context) ;
		verifyInstallTreeView( window, before, context) ;
		const auto &row =
			window.treeRows_[window.candidateRowIndexes_[1]] ;	// 元同itemの現在列です。
		DRIVERCRATE_EXPECT( context, row.currentVersion == L"99.0.0.0" &&
										window.showRecommendedOnly_ == filter &&
										window.controller_.scanSessionId() == 0U &&
										window.checkedCandidateIndexes().empty() &&
										!window.selectDeviceCandidate( 3U)) ;
		DRIVERCRATE_EXPECT( context,
						   (TreeView_GetItemState( window.updateTree_, window.candidateItems_[1],
												  TVIS_STATEIMAGEMASK) >>
							12U) == 3U &&
							   (TreeView_GetItemState( window.updateTree_, window.candidateItems_[3],
													  TVIS_STATEIMAGEMASK) >>
								12U) == 4U) ;
		const auto nextScan = window.controller_.beginScan() ;	// 失効後は新scanが必要な元guardです。
		DRIVERCRATE_EXPECT( context, nextScan.accepted) ;
		event.operationId = nextScan.operationId ;
		event.scanResult.scanSessionId += 100U ;
		window.processWorkerEvent( event) ;
		DRIVERCRATE_EXPECT( context, window.preparationDisplayBindings_.empty() &&
										window.preparationDisplaySession_ == 0U &&
										window.controller_.scanSessionId() != 0U) ;
		const auto hidden = std::ranges::find(
			window.candidates_, L"view-current-47",
			&UpdateCandidate::identity) ;	// Append後も末尾位置をidentityの代用にしません。
		DRIVERCRATE_EXPECT( context, hidden != window.candidates_.end()) ;
		// 明示filter操作は新scanのSCAN_READYで従来どおり全行を再構成します。
		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK,
					 filter ? BST_UNCHECKED : BST_CHECKED, 0) ;
		window.handleRecommendedFilterChange() ;
		// 欠測を表示成功にせず、元opaque deviceだけの表示有無を比較します。
		if( hidden != window.candidates_.end()) {
			const auto hiddenIndex = static_cast<std::size_t>(
				hidden - window.candidates_.begin()) ;	// 同じ候補vector内の位置です。
			DRIVERCRATE_EXPECT( context,
							   (window.candidateItems_[hiddenIndex] != nullptr) == filter &&
								   window.showRecommendedOnly_ != filter &&
								   window.checkedCandidateIndexes().empty()) ;
		}
	}
	/**
	 * @brief 選択した二deviceの事後観測だけを元行へ反映し、元結果と失効を保持します。
	 * @param[in,out] window 先行する非通信表示試験を終えたWindowです。
	 * @param[in] event 同じworkerが発行した元導入終端です。
	 */
	static void deliverInstallCompleted( MainWindow &window, const WorkerEvent &event)
	{
		window.processWorkerEvent( event) ;
	}

	/**
	 * @brief 元結果の九条件で現在観測・個別結果・旧scan失効と元表示名を確認します。
	 * @param[in,out] window 非通信factoryを持つ所有Windowです。
	 * @param[in,out] context 原assertion集計先です。
	 * @param[in] deliver 元結果dialogを閉じる同期関数です。
	 */
	static void verifyPostInstallDisplay( MainWindow &window, test::TestContext &context,
										 void ( *deliver)( MainWindow &, const WorkerEvent &,
														 test::TestContext &))
	{
		// 九条件を独立したscanへ結合し、実deviceや実installを呼びません。
		for( unsigned mode = 0U; mode < 9U; ++mode) {
			const auto begin = window.controller_.beginScan() ;	// 前結果を失効させる正規入口です。
			DRIVERCRATE_EXPECT( context, begin.accepted) ;
			// 前提を失った条件に合成結果を流し込みません。
			if( !begin.accepted) {
				continue ;
			}

			const ScanSessionId session = 1000U + mode * 2U ;	// この条件だけの元結合です。
			WorkerEvent			scan{
						.kind		 = WorkerEventKind::SCAN_COMPLETED,
						.operationId = begin.operationId,
						.scanResult	 = {.succeeded	   = true,
										.scanSessionId = session,
										.outcome = OutcomeCode::SUCCESS}} ;	// 表示用の現在行と候補です。
			std::vector<std::wstring> selected ;							// 同名でも異なる二opaque deviceです。
			InstallResult			  result ;								// APIの結果と実観測を別に構成します。
			result.succeeded	   = mode != 1U ;
			result.downloadOutcome = OutcomeCode::SUCCESS ;
			result.installOutcome =
				mode == 1U ? OutcomeCode::SUCCEEDED_WITH_ERRORS : OutcomeCode::SUCCESS ;
			result.restorePointCreation.outcome	  = OutcomeCode::SUCCESS ;
			result.restorePointCompletion.outcome = OutcomeCode::SUCCESS ;
			// 元二deviceへ一候補ずつを作り、初回専用権限を偽造しません。
			for( unsigned device = 0U; device < 2U; ++device) {
				UpdateCandidate current ;	// 名称・classが変わる前の人工観測です。
				current.identity		  = L"display-current-" + std::to_wstring( device) ;
				current.deviceIdentity	  = L"display-device-" + std::to_wstring( device) ;
				current.model			  = L"Ethernet Controller" ;
				current.version			  = L"old-version" ;
				current.current			  = true ;
				current.providerId		  = DRIVER_STORE_PROVIDER_ID ;
				current.discoveryBasis	  = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
				current.audit			  = makeWindowsManagedCandidateAudit( true) ;
				current.deviceObservation = DeviceObservation{} ;
				current.deviceObservation->scanSessionId	= session ;
				current.deviceObservation->deviceIdentity	= current.deviceIdentity ;
				current.deviceObservation->node.read.state	= DevicePropertyReadState::VALUE ;
				current.deviceObservation->node.statusFlags = 0x400U ;
				current.deviceObservation->node.problemCode = 28U ;
				current.deviceObservation->driverPresence	= DeviceDriverPresence::NOT_INSTALLED ;
				// 現在代表のないProvider候補も、実観測から表示専用代表を作れます。
				if( mode != 8U || device != 1U) {
					scan.scanResult.candidates.push_back( current) ;
				}

				UpdateCandidate candidate ;	// 元選択の版とidentityは実観測で書き換えません。
				candidate.identity		 = L"display-candidate-" + std::to_wstring( device) ;
				candidate.deviceIdentity = current.deviceIdentity ;
				candidate.model			 = current.model ;
				candidate.version		 = L"1.9.74.0" ;
				candidate.providerId	 = DRIVER_STORE_PROVIDER_ID ;
				candidate.action		 = DriverAction::UPDATE ;
				candidate.installable	 = true ;
				candidate.recommended	 = true ;
				candidate.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
				candidate.audit			 = makeWindowsManagedCandidateAudit( false) ;
				selected.push_back( candidate.identity) ;
				scan.scanResult.candidates.push_back( candidate) ;
				UpdateExecutionResult execution ;	// 一件目の成功で二件目の失敗を隠しません。
				execution.identity		  = candidate.identity ;
				execution.downloadOutcome = OutcomeCode::SUCCESS ;
				execution.installOutcome =
					mode == 1U && device == 1U ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
				execution.installError =
					mode == 1U && device == 1U ? static_cast<NativeError>( E_ACCESSDENIED) : 0U ;
				execution.rebootRequired = mode == 2U && device == 0U ;
				result.updates.push_back( execution) ;
				PostInstallDeviceObservation observed ;	// 現在値は候補の成功flagから生成しません。
				observed.observation.scanSessionId			= session ;
				observed.observation.deviceIdentity			= current.deviceIdentity ;
				observed.observation.instanceIdentity.state = DevicePropertyReadState::VALUE ;
				observed.observation.friendlyName.state		= DevicePropertyReadState::VALUE ;
				observed.observation.driverKey.state		= DevicePropertyReadState::VALUE ;
				observed.observation.node.read.state		= DevicePropertyReadState::VALUE ;
				observed.observation.node.statusFlags		= 8U ;
				observed.observation.driverPresence			= DeviceDriverPresence::REGISTERED ;
				observed.name								= L"Installed fixture NIC" ;
				observed.driverClass						= L"Net" ;
				observed.deviceClassGuid = L"{4D36E972-E325-11CE-BFC1-08002BE10318}" ;
				observed.version		 = L"1.9.74.0" ;
				// API成功でも実観測が旧Code28なら、その状態と欠損版を保持します。
				if( mode == 7U || (mode == 1U && device == 1U)) {
					observed.observation = *current.deviceObservation ;
					observed.name		 = current.model ;
					observed.driverClass.clear() ;
					observed.deviceClassGuid.clear() ;
					observed.version.clear() ;
				}

				// 一部属性が読めてもnode不明なら問題解消を推測しません。
				if( mode == 6U) {
					observed.observation.node	   = {} ;
					observed.observation.node.read = {
						DevicePropertyReadState::FAILED,
						{DeviceDiagnosticDomain::CONFIGURATION_MANAGER, 5U}} ;
				}

				// 解決失敗は旧観測の現在扱いを拒否します。
				if( mode == 3U) {
					observed.error = static_cast<NativeError>( E_ACCESSDENIED) ;
				}

				// 旧sessionの実観測を新操作へ付け替えません。
				if( mode == 4U) {
					--observed.observation.scanSessionId ;
				}

				// 未選択deviceのDTOは同名であっても無視します。
				if( mode == 5U) {
					observed.observation.deviceIdentity = L"unselected-display-device" ;
				}

				result.currentDevices.push_back( std::move( observed)) ;
			}

			// 選択外の現在deviceは元filterのまま終端後も隠します。
			UpdateCandidate other ;
			other.identity		 = L"display-other-current" ;
			other.deviceIdentity = L"display-other-device" ;
			other.model			 = L"Other fixture" ;
			other.current		 = true ;
			other.providerId	 = DRIVER_STORE_PROVIDER_ID ;
			other.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
			other.audit			 = makeWindowsManagedCandidateAudit( true) ;
			scan.scanResult.candidates.push_back( other) ;
			window.showRecommendedOnly_ = true ;
			SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_CHECKED, 0) ;
			window.processWorkerEvent( scan) ;
			const auto install = window.controller_.beginInstall(
				session, selected,
				InstallConfirmation::CONFIRMED) ;	// workerを実行しない正規状態機械です。
			DRIVERCRATE_EXPECT( context, install.accepted) ;
			// 拒否された操作に描画を適用しません。
			if( !install.accepted) {
				continue ;
			}

			WorkerEvent completed{.kind			 = WorkerEventKind::INSTALL_COMPLETED,
								  .operationId	 = install.operationId,
								  .installResult = result} ;	// 正規操作の元終端です。
			auto		stale = completed ;						// 別operationの旧通知です。
			stale.operationId = install.operationId + 1U ;
			window.processInstallCompleted( stale) ;
			DRIVERCRATE_EXPECT( context, window.showRecommendedOnly_ &&
											SendMessageW( window.recommendedOnlyCheckbox_,
														 BM_GETCHECK, 0, 0) == BST_CHECKED &&
											window.controller_.scanSessionId() == session) ;
			deliver( window, completed, context) ;
			DRIVERCRATE_EXPECT( context, window.showRecommendedOnly_ &&
											SendMessageW( window.recommendedOnlyCheckbox_,
														 BM_GETCHECK, 0, 0) == BST_CHECKED) ;
			DRIVERCRATE_EXPECT( context, std::count_if( window.treeRows_.begin(),
													  window.treeRows_.end(), []( const auto &row) {
														  return row.kind ==
																 MainWindow::TreeRowKind::DEVICE ;
													  }) == 2) ;
			// 元二結果だけを検査し、同名別deviceを一行へ潰しません。
			for( unsigned device = 0U; device < 2U; ++device) {
				const auto identity =
					L"display-device-" + std::to_wstring( device) ;	// 元opaque照合です。
				const auto row = std::find_if(
					window.treeRows_.begin(), window.treeRows_.end(),
					[&window, &identity]( const auto &value) {
						return value.kind == MainWindow::TreeRowKind::DEVICE &&
							   window.candidates_[value.deviceIndex].deviceIdentity == identity ;
					}) ; // 再構築後の唯一の現在代表です。
				DRIVERCRATE_EXPECT( context, row != window.treeRows_.end()) ;
				// 行がない場合にiteratorを参照しません。
				if( row == window.treeRows_.end()) {
					continue ;
				}

				const bool unavailable = mode >= 3U && mode <= 5U ;					// 拒否/失敗観測です。
				const bool oldState = mode == 7U || (mode == 1U && device == 1U) ;	// 実Code28です。
				DRIVERCRATE_EXPECT( context, row->currentVersion ==
												(unavailable || oldState
													 ? window.loadString( IDS_VALUE_UNKNOWN)
													 : L"1.9.74.0")) ;
				DRIVERCRATE_EXPECT( context, row->primaryText == L"Ethernet Controller") ;
				const auto &current =
					window.candidates_[row->deviceIndex] ;	// 実分類だけを確認します。
				DRIVERCRATE_EXPECT( context, current.current && (current.deviceClassGuid.empty() ==
																(unavailable || oldState))) ;
				DRIVERCRATE_EXPECT(
					context,
					(row->status.find( L"28") != std::wstring::npos) == oldState &&
						(row->status.find( window.loadString( IDS_DEVICE_POST_INSTALL_UNKNOWN)) !=
						 std::wstring::npos) == (unavailable || mode == 6U) &&
						(row->status.find( window.loadString( IDS_DEVICE_POST_INSTALL_REBOOT)) !=
						 std::wstring::npos) == (mode == 2U && device == 0U)) ;
				const auto candidate =
					std::find_if( window.candidates_.begin(), window.candidates_.end(),
								 [&selected, device]( const auto &value) {
									 return value.identity == selected[device] ;
								 }) ; // 元候補版です。
				const auto index = static_cast<std::size_t>(
					// 元結果位置です。
					std::distance( window.candidates_.begin(), candidate)) ;
				DRIVERCRATE_EXPECT( context,
								   candidate != window.candidates_.end() &&
									   candidate->version == L"1.9.74.0" &&
									   window.candidateResultTexts_[index].find( window.loadString(
										   mode == 1U && device == 1U ? IDS_INSTALL_FAILED
																	  : IDS_INSTALL_SUCCEEDED)) !=
										   std::wstring::npos &&
									   !window.selectDeviceCandidate( index)) ;
			}

			DRIVERCRATE_EXPECT(
				context,
				window.checkedCandidateIndexes().empty() &&
					std::none_of( window.candidates_.begin(), window.candidates_.end(),
								 []( const auto &candidate) { return candidate.installable ; }) &&
					IsWindowEnabled( window.installButton_) == FALSE &&
					!window.controller_
						 .beginInstall( session, selected, InstallConfirmation::CONFIRMED)
						 .accepted) ;
		}
	}

	/**
	 * @brief 原scan・計画・承認を実controllerへ登録し、非空の合成終端を返します。
	 * @param[in,out] window 隠した本物Window。内部factoryだけを使用します。
	 * @param[in,out] context 前提の成否を記録する集計先。
	 * @param[in] sessionId 一試験ごとに異なる正の人工session。
	 * @return 同じ承認のtransferと有限索引summaryを所有する通知。
	 */
	static WorkerEvent prepareIndexFixture( MainWindow &window, test::TestContext &context,
										   const ScanSessionId sessionId)
	{
		const auto scan = window.controller_.beginScan() ;	// 本物の単調operation発行。
		DRIVERCRATE_EXPECT( context, scan.accepted) ;
		// 前提不成立を後続の添字操作へ伝播させません。
		if( !scan.accepted) {
			return {} ;
		}

		OfficialPreparationPlan plan{
			sessionId, sessionId, {4096U, 20480U, 20480U, 5U, 5U}, {}} ;	// 五件の原計画。
		// 元承認は索引四件と別Provider一件。最後のUNKNOWNは未選択です。
		for( std::size_t index = 0U; index < 5U; ++index) {
			OfficialPreparationTarget target ;	// URLや端末IDを持たない人工対象。
			target.identity = L"ui-index-target-" + std::to_wstring( index) ;
			target.providerId =
				index == 3U ? PROLIFIC_OFFICIAL_PROVIDER_ID : SIGNED_INDEX_PROVIDER_ID ;
			target.resourceId	   = L"ui-resource" ;
			target.releaseIdentity = L"ui-release-" + std::to_wstring( index) ;
			target.parserRevision  = 1U ;
			target.maximumBytes	   = 4096U ;
			target.deviceCount	   = 1U ;
			target.terms		   = index == 4U ? OfficialPreparationTerms::UNRESOLVED
												 : OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
			plan.targets.push_back( std::move( target)) ;
		}

		WorkerEvent scanEvent ;	// 本物のscan完了処理と計画公開を通る人工結果。
		scanEvent.kind					   = WorkerEventKind::SCAN_COMPLETED ;
		scanEvent.operationId			   = scan.operationId ;
		scanEvent.scanResult.succeeded	   = true ;
		scanEvent.scanResult.scanSessionId = sessionId ;
		scanEvent.scanResult.outcome	   = OutcomeCode::SUCCESS ;
		UpdateCandidate current ;	// 内容summaryから候補を発行しないことを確認する現在行。
		current.identity	   = L"ui-current" ;
		current.deviceIdentity = L"ui-device" ;
		current.title		   = L"Synthetic current driver" ;
		current.current		   = true ;
		current.version		   = L"1.0" ;
		scanEvent.scanResult.candidates.push_back( std::move( current)) ;
		scanEvent.preparationPlan							 = plan ;
		scanEvent.indexSummary.status						 = IndexScanStatus::PARTIAL ;
		scanEvent.indexSummary.totalRecords					 = 12U ;
		scanEvent.indexSummary.processedRecords				 = 12U ;
		scanEvent.indexSummary.undeterminedRelations		 = 7U ;
		scanEvent.indexPreparation.scanSessionId			 = sessionId ;
		scanEvent.indexPreparation.planId					 = plan.planId ;
		scanEvent.indexPreparation.plannedTargets			 = 4U ;
		scanEvent.indexPreparation.unavailableRelations		 = 7U ;
		scanEvent.indexPreparation.capacityRejectedRelations = 2U ;
		window.processWorkerEvent( scanEvent) ;
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::SCAN_READY) ;
		DRIVERCRATE_EXPECT( context, window.controller_.preparationPlan() != nullptr) ;
		DRIVERCRATE_EXPECT( context, window.preparationResultText_.find( window.loadString(
										IDS_INDEX_ROUTING_PENDING)) != std::wstring::npos) ;

		OfficialPreparationApproval approval{
			0U, sessionId, plan.planId, plan.limits, {}} ;	// 同計画の全判断。
		// 同じ原targetを全文保持し、UNKNOWNへの未選択を省略しません。
		for( std::size_t index = 0U; index < plan.targets.size(); ++index) {
			approval.decisions.push_back( {.target = plan.targets[index], .acquire = index != 4U}) ;
		}

		const auto begin = window.controller_.beginPreparation( approval) ;	// 実承認の全field照合。
		DRIVERCRATE_EXPECT( context, begin.accepted) ;
		// 実controllerが承認しなかった入力を有効結果として試験しません。
		if( !begin.accepted) {
			return {} ;
		}

		window.preparationApproval_	  = approval ;
		window.preparationTotal_	  = 4U ;
		window.preparationCompleted_  = 0U ;
		window.preparationResultText_ = L"Index result pending" ;
		window.setStatus( L"Index fixture preparing", true) ;
		window.updateCommandState() ;
		window.testSuppressPreparationResultDialog_ = true ;
		WorkerEvent completed ;	// 元承認と完全一致するtransfer、独立内容結果の人工通知。
		completed.kind							  = WorkerEventKind::PREPARATION_COMPLETED ;
		completed.operationId					  = begin.operationId ;
		completed.preparationResult.operationId	  = begin.operationId ;
		completed.preparationResult.scanSessionId = sessionId ;
		completed.preparationResult.planId		  = plan.planId ;
		completed.preparationResult.approvalError = OfficialPreparationError::NONE ;
		// 先行取得、拒否、取得後内容失敗、別Provider、未選択を区別します。
		for( std::size_t index = 0U; index < plan.targets.size(); ++index) {
			OfficialPreparationItem item ;	// 同じ原targetの確定取得状態。
			item.identity = plan.targets[index].identity ;
			item.result =
				index == 4U
					? OfficialPreparationTransferResult{OfficialPreparationItemState::NOT_SELECTED,
														0, 0U}
				: index == 1U
					? OfficialPreparationTransferResult{OfficialPreparationItemState::REJECTED,
														static_cast<NativeError>( E_ACCESSDENIED),
														0U}
					: OfficialPreparationTransferResult{
						  OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 1024U} ;
			completed.preparationResult.items.push_back( std::move( item)) ;
		}

		completed.indexPreparation			   = scanEvent.indexPreparation ;
		completed.indexPreparation.operationId = begin.operationId ;
		completed.indexPreparation.items	   = {
			  {.targetIdentity			  = plan.targets[0].identity,
				   .acquisition				  = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
				   .content					  = IndexedDriverInspectionState::INSPECTION_COMPLETED,
				   .firstInfRejection		  = static_cast<NativeError>( CRYPT_E_FILE_ERROR),
				   .inputBound				  = true,
				   .inventoryFileCount		  = 3U,
				   .infCount				  = 1U,
				   .parsedInfCount			  = 1U,
				   .signatureRejectedInfCount = 1U},
			  {.targetIdentity	 = plan.targets[1].identity,
				   .acquisition		 = OfficialAcquisitionState::REJECTED,
				   .acquisitionError = static_cast<NativeError>( E_ACCESSDENIED)},
			  {.targetIdentity = plan.targets[2].identity,
				   .acquisition	   = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
				   .content		   = IndexedDriverInspectionState::INSPECTION_FAILED,
				   .contentError   = static_cast<NativeError>( E_FAIL),
				   .inputBound	   = true}} ;
		return completed ;
	}

	/**
	 * @brief 正常非空結果と個別改変を、同じ本物画面の承認・終端処理へ渡します。
	 * @param[in,out] window 非通信factoryと隠した標準controlを所有するWindow。
	 * @param[in,out] context Assertionの集計先。
	 */
	static void verifyIndexSummaryCases( MainWindow &window, test::TestContext &context)
	{
		// 各番号はdesign.jsonの有限正常／改変群に対応し、判定値をrawへ保存します。
		for( unsigned mode = 0U; mode < 37U; ++mode) {
			auto event = prepareIndexFixture( window, context, 100U + mode) ;	// 別sessionの原承認。
			// 前提失敗を範囲外参照へ広げず、このfixture群を中止します。
			if( event.preparationResult.items.size() != 5U ||
			   event.indexPreparation.items.size() != 3U) {
				DRIVERCRATE_EXPECT( context, false) ;
				return ;
			}

			auto &first			= event.indexPreparation.items[0] ;	// 非空の構造解析と署名拒否。
			auto &failed		= event.indexPreparation.items[1] ;	// 取得拒否の元errorとstate。
			auto &contentFailed = event.indexPreparation.items[2] ;	// 取得成功後の独立内容失敗。
			// 一度に一条件だけ変え、正常結果との差を原rawへ結びます。
			switch( mode) {
				// 非空取得・構造解析・署名拒否とUNKNOWNを同時に保持する正例。
				case 0U:
					break ;

				// 取得成功後に入力結合を拒否した独立失敗は正当に表示します。
				case 1U:
					contentFailed.content	 = IndexedDriverInspectionState::INPUT_REJECTED ;
					contentFailed.inputBound = false ;
					break ;

				// 実byte検査の取消しを取得失敗へ上書きしません。
				case 2U:
					contentFailed.content = IndexedDriverInspectionState::CANCELLED ;
					contentFailed.contentError =
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
					break ;

				// Workerのnetwork同意待ち→executor FAILUREという現変換を維持します。
				case 3U:
					failed.acquisition = OfficialAcquisitionState::AWAITING_NETWORK_CONSENT ;
					event.preparationResult.items[1].result.state =
						OfficialPreparationItemState::FAILURE ;
					break ;

				// 取消し要求後も先行確定内容を保持する正当な同operation終端です。
				case 4U:
					DRIVERCRATE_EXPECT(
						context, window.controller_.markPreparationCancelling( event.operationId)) ;
					failed.acquisition = OfficialAcquisitionState::CANCELLED ;
					event.preparationResult.items[1].result.state =
						OfficialPreparationItemState::CANCELLED ;
					break ;

				// Summaryだけの別operationを全拒否します。
				case 5U:
					++event.indexPreparation.operationId ;
					break ;

				// Summaryだけの別scanを全拒否します。
				case 6U:
					++event.indexPreparation.scanSessionId ;
					break ;

				// Summaryだけの別planを全拒否します。
				case 7U:
					++event.indexPreparation.planId ;
					break ;

				// 元承認外のidentityを別対象へ割り当てません。
				case 8U:
					first.targetIdentity = L"ui-unapproved" ;
					break ;

				// 元の別Provider成功を索引結果へ偽装しません。
				case 9U:
					first.targetIdentity = event.preparationResult.items[3].identity ;
					break ;

				// UNKNOWN未選択対象へ結果を合成しません。
				case 10U:
					first = {.targetIdentity = event.preparationResult.items[4].identity} ;
					break ;

				// 元transferの欠落を成功で補完しません。
				case 11U:
					event.preparationResult.items.erase( event.preparationResult.items.begin() + 1) ;
					break ;

				// 重複した内容通知を二件として表示しません。
				case 12U:
					event.indexPreparation.items.push_back( first) ;
					break ;

				// Summaryの元取得HRESULT差替えを拒否します。
				case 13U:
					failed.acquisitionError = static_cast<NativeError>( E_FAIL) ;
					break ;

				// 元取得成功を別stateへ変更しません。
				case 14U:
					first.acquisition = OfficialAcquisitionState::FAILURE ;
					break ;

				// 失敗state間の差替えも元transferに完全対応させます。
				case 15U:
					failed.acquisition = OfficialAcquisitionState::CANCELLED ;
					break ;

				// 一計画256対象の表示上限を維持します。
				case 16U:
					event.indexPreparation.items.resize( 257U, first) ;
					break ;

				// 計画件数の上限超過を拒否します。
				case 17U:
					event.indexPreparation.plannedTargets = 257U ;
					break ;

				// 有限でも原承認の索引対象数と異なる申告を拒否します。
				case 18U:
					event.indexPreparation.plannedTargets = 5U ;
					break ;

				// 発見INFの通常上限を維持します。
				case 19U:
					first.infCount = 129U ;
					break ;

				// 発見していないINFの解析完了を合成しません。
				case 20U:
					first.parsedInfCount = 2U ;
					break ;

				// 未解析INFへ署名内容合格を発行しません。
				case 21U:
					first.acceptedInfCount = 2U ;
					break ;

				// 未解析INFへ署名拒否を合成しません。
				case 22U:
					first.signatureRejectedInfCount = 2U ;
					break ;

				// 解析済みINFの独立結果の完全和を維持します。
				case 23U:
					first.signatureRejectedInfCount = 0U ;
					break ;

				// 通常fileの実共通検査上限をUIでも維持します。
				case 24U:
					first.inventoryFileCount = 4097U ;
					break ;

				// 定義外の内容stateを未知の成功へ変換しません。
				case 25U:
					contentFailed.content = static_cast<IndexedDriverInspectionState>( 99) ;
					break ;

				// 定義外の取得stateを失敗stateとして受理しません。
				case 26U:
					failed.acquisition = static_cast<OfficialAcquisitionState>( 99) ;
					break ;

				// 全体検査未完了の個別INFを表示所有しません。
				case 27U:
					contentFailed.infCount = 1U ;
					break ;

				// 取得失敗へ未実施内容の通常file件数を混入させません。
				case 28U:
					failed.inventoryFileCount = 1U ;
					break ;

				// 全体検査完了と全体errorの矛盾を拒否します。
				case 29U:
					first.contentError = static_cast<NativeError>( E_FAIL) ;
					break ;

				// 失敗stateの診断欠損を成功値で補完しません。
				case 30U:
					contentFailed.contentError = 0 ;
					break ;

				// 元controllerがtransfer不正を拒否したら索引summaryも公開しません。
				case 31U:
					event.preparationResult.items[3].result.byteCount = 0U ;
					break ;

				// 元byte結合なしの内容完了を拒否します。
				case 32U:
					first.inputBound = false ;
					break ;

				// 通常file集合にないINFを発見件数へ合成しません。
				case 33U:
					first.inventoryFileCount = 0U ;
					break ;

				// 元resultの重複拒否後も正当な別summaryを残しません。
				case 34U:
					event.preparationResult.items[3] = event.preparationResult.items[0] ;
					break ;

				// 通常file4096・INF128の上限値そのものは正当に保持します。
				case 35U:
					first.inventoryFileCount		= 4096U ;
					first.infCount					= 128U ;
					first.parsedInfCount			= 128U ;
					first.signatureRejectedInfCount = 128U ;
					break ;

				// 全lookupの保持枠を越える未知関係件数を拒否します。
				case 36U:
					event.indexPreparation.unavailableRelations = 32769U ;
					break ;

				// 有限case集合外の入力を実行しません。
				default:
					DRIVERCRATE_EXPECT( context, false) ;
					return ;
			}

			const bool expected = mode <= 4U || mode == 35U ;	// 非空正例と実上限正例だけ受理します。
			window.processWorkerEvent( event) ;
			const bool accepted =
				!window.indexPreparationSummary_.items.empty() ;	// 実画面の所有状態。
			DRIVERCRATE_EXPECT( context, accepted == expected) ;
			DRIVERCRATE_EXPECT( context, window.controller_.state() ==
											((mode == 11U || mode == 31U || mode == 34U)
												 ? ApplicationState::FAILURE
												 : ApplicationState::SCAN_READY)) ;
			DRIVERCRATE_EXPECT( context, window.candidates_.size() == 1U &&
											!window.candidates_[0].installable) ;
			DRIVERCRATE_EXPECT( context, !window.candidateSelected_[0]) ;
			DRIVERCRATE_EXPECT( context, indexStatusText( window) ==
											window.loadString( window.controller_.state() ==
																	  ApplicationState::FAILURE
																  ? IDS_PREPARATION_FAILED
																  : IDS_INDEX_CONTENT_PARTIAL)) ;
			DRIVERCRATE_EXPECT( context, window.preparationResultText_.find( L"https://") ==
											std::wstring::npos) ;
			// 正当な結果だけで内容件数・元診断・未接続理由の表示を照合します。
			if( expected) {
				DRIVERCRATE_EXPECT( context, window.indexPreparationSummary_.items.size() == 3U) ;
				DRIVERCRATE_EXPECT(
					context, window.indexPreparationSummary_.unavailableRelations == 7U &&
								 window.indexPreparationSummary_.capacityRejectedRelations == 2U) ;
				DRIVERCRATE_EXPECT( context,
								   window.indexPreparationSummary_.items[0].acceptedInfCount == 0U) ;
				DRIVERCRATE_EXPECT( context, window.preparationResultText_.find(
												window.loadString( IDS_INDEX_CONTENT_COMPLETED)) !=
												std::wstring::npos) ;
				DRIVERCRATE_EXPECT( context,
								   window.preparationResultText_.find(
									   mode == 35U ? L"4096 / 128 / 128 / 128 / 0"
												   : L"3 / 1 / 1 / 1 / 0") != std::wstring::npos) ;
				DRIVERCRATE_EXPECT( context, window.preparationResultText_.find( L"80092003") !=
												std::wstring::npos) ;
				DRIVERCRATE_EXPECT( context, window.preparationResultText_.find( window.loadString(
												IDS_INDEX_ROUTING_PENDING)) != std::wstring::npos) ;
				DRIVERCRATE_EXPECT( context, window.preparationResultText_.find( L"80004005") !=
													std::wstring::npos ||
												mode == 2U) ;
				DRIVERCRATE_EXPECT( context, window.preparationApproval_.decisions[4].target.terms ==
													OfficialPreparationTerms::UNRESOLVED &&
												!window.preparationApproval_.decisions[4].acquire) ;
			} else {
				DRIVERCRATE_EXPECT( context, window.preparationResultText_.find(
												L"通常file / 発見INF / 構造解析完了INF") ==
												std::wstring::npos) ;
			}

			std::cout << "Index UI case: " << mode << ", expected accepted: " << expected
					  << ", observed accepted: " << accepted
					  << ", state: " << static_cast<unsigned>( window.controller_.state())
					  << ", retained candidates: " << window.candidates_.size()
					  << ", accepted INF: 0, nonempty content text: "
					  << (window.preparationResultText_.find(
							  mode == 35U ? L"4096 / 128 / 128 / 128 / 0" : L"3 / 1 / 1 / 1 / 0") !=
						  std::wstring::npos)
					  << '\n' ;
		}
	}

	/**
	 * @brief 本物の下部controlが保持するstatus本文を有限長で読みます。
	 * @param[in] window 試験が所有するWindow。
	 * @return 上限4,096文字以内のcontrol本文です。
	 */
	static std::wstring indexStatusText( const MainWindow &window)
	{
		std::array<wchar_t, 4097U> buffer{} ;	// 同process controlだけの有限出力。
		const int				   copied =		// 実controlから読み取った文字数。
			GetWindowTextW( window.status_, buffer.data(), static_cast<int>( buffer.size())) ;
		return copied > 0 ? std::wstring( buffer.data(), static_cast<std::size_t>( copied))
						  : std::wstring{} ;
	}

	/**
	 * @brief 部分内容合格でも候補を保持し、全件未接続や導入済みと表示しないことを確認します。
	 * @param[in] window 同じ通知から候補と部分summaryを受理した本物Window。
	 * @param[in,out] context 実controlと所有本文のassertion集計先。
	 */
	static void verifyPartialIndexPublication( const MainWindow &window, test::TestContext &context)
	{
		const auto status = indexStatusText( window) ;	// 実下部controlが保持する部分結果です。
		DRIVERCRATE_EXPECT( context, status == window.loadString( IDS_INDEX_CONTENT_PARTIAL)) ;
		DRIVERCRATE_EXPECT( context, status.find( L"拒否・不足") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, status.find( L"導入経路は未接続") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, status.find( L"候補ごとの導入可否") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, status.find( L"行の詳細") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, window.preparationResultText_.find( L"3 / 2 / 1 / 0 / 1") !=
										std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   window.preparationResultText_.find( L"80070032") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, window.preparationResultText_.find( window.loadString(
										IDS_PREPARATION_AUDIT_READY)) != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   std::ranges::count_if( window.candidates_, []( const auto &candidate) {
							   return candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
									  candidate.installable ;
						   }) == 1) ;
		DRIVERCRATE_EXPECT( context, !IsWindowEnabled( window.installButton_) &&
										window.checkedCandidateIndexes().empty()) ;
	}

	/**
	 * @brief 古い結果、逆行進捗、取消し終端、停止とWindow破棄後の通知を拒否します。
	 * @param[in,out] window 正常／拒否fixture後の隠したWindow。
	 * @param[in,out] context Assertionの集計先。
	 */
	static void verifyIndexDelays( MainWindow &window, test::TestContext &context)
	{
		auto completed = prepareIndexFixture( window, context, 200U) ;	// 同operationの確定予定結果。
		WorkerEvent progress ;											// 四件中一件だけ確定した本物progress入力。
		progress.kind				 = WorkerEventKind::PREPARATION_PROGRESS ;
		progress.operationId		 = completed.operationId ;
		progress.preparationProgress = {.total = 4U, .completed = 1U} ;
		window.processWorkerEvent( progress) ;
		DRIVERCRATE_EXPECT( context,
						   window.preparationCompleted_ == 1U && window.statusPercentage_ == 25U) ;
		const auto beforeText	= window.preparationResultText_ ;	// 未確定本文の保持基準。
		const auto beforeStatus = indexStatusText( window) ;		// 新しい画面の確定進捗文字列。
		// 元result tupleの各不一致を独立に注入し、処理中状態を保持します。
		for( unsigned mode = 0U; mode < 3U; ++mode) {
			auto stale = completed ;	// 一条件だけ差し替える遅延通知。
			// 元operationの不一致を拒否します。
			if( mode == 0U) {
				++stale.preparationResult.operationId ;
			}
			// 元sessionの不一致を拒否します。
			else if( mode == 1U) {
				++stale.preparationResult.scanSessionId ;
			} else {
				++stale.preparationResult.planId ;
			}

			window.processWorkerEvent( stale) ;
			DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::PREPARING &&
											window.preparationResultText_ == beforeText &&
											indexStatusText( window) == beforeStatus) ;
		}

		// 不正envelope・逆行・総数変更・上限超過・異kindを同じ現画面へ送ります。
		for( unsigned mode = 0U; mode < 6U; ++mode) {
			auto invalid = progress ;	// 独立した不正進捗。
			// 旧operationを新進捗へ適用しません。
			if( mode == 0U) {
				--invalid.operationId ;
			}
			// 確定値の逆行を拒否します。
			else if( mode == 1U) {
				invalid.preparationProgress.completed = 0U ;
			}
			// 元対象数の差替えを拒否します。
			else if( mode == 2U) {
				invalid.preparationProgress.total = 5U ;
			}
			// 処理済み件数の超過を拒否します。
			else if( mode == 3U) {
				invalid.preparationProgress.completed = 5U ;
			}
			// 定義外eventをdispatchしません。
			else if( mode == 4U) {
				invalid.kind = static_cast<WorkerEventKind>( 99) ;
			} else {
				invalid.kind		   = WorkerEventKind::PROGRESS ;
				invalid.progress.stage = ProviderStage::INSTALLING ;
			}

			window.processWorkerEvent( invalid) ;
			DRIVERCRATE_EXPECT( context, window.preparationCompleted_ == 1U &&
											window.statusPercentage_ == 25U &&
											indexStatusText( window) == beforeStatus &&
											window.preparationResultText_ == beforeText) ;
		}

		window.processWorkerEvent( completed) ;
		const auto retained		  = window.preparationResultText_ ;	// 正常非空結果の実本文。
		const auto retainedStatus = indexStatusText( window) ;		// 内容不足を保持した終端表示。
		window.processWorkerEvent( progress) ;
		window.processWorkerEvent( completed) ;
		DRIVERCRATE_EXPECT( context, window.preparationResultText_ == retained &&
										indexStatusText( window) == retainedStatus &&
										window.indexPreparationSummary_.items.size() == 3U) ;
		auto	   next = prepareIndexFixture( window, context, 201U) ;	// 新画面への旧通知の拒否。
		const auto nextText = window.preparationResultText_ ;			// 新しい処理中画面。
		window.processWorkerEvent( completed) ;
		window.processWorkerEvent( progress) ;
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::PREPARING &&
										window.preparationResultText_ == nextText &&
										window.indexPreparationSummary_.items.empty()) ;
		window.updateCommandState() ;
		DRIVERCRATE_EXPECT( context, IsWindowEnabled( window.scanButton_) != FALSE) ;
		SendMessageW( window.window_, WM_COMMAND, IDC_SCAN, 0) ;
		DRIVERCRATE_EXPECT( context,
						   window.controller_.state() == ApplicationState::CANCELLING_PREPARATION &&
							   IsWindowEnabled( window.scanButton_) == FALSE) ;
		SendMessageW( window.window_, WM_COMMAND, IDC_SCAN, 0) ;
		DRIVERCRATE_EXPECT( context, window.controller_.activeOperationId() == next.operationId) ;
		next.preparationResult.controlError =
			static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
		next.preparationResult.items.clear() ;
		next.indexPreparation.items.clear() ;
		window.processWorkerEvent( next) ;
		const auto cancelled = window.preparationResultText_ ;	// 正当な取消し終端の実表示。
		window.processWorkerEvent( next) ;
		window.processWorkerEvent( completed) ;
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::SCAN_READY &&
										window.preparationResultText_ == cancelled &&
										window.indexPreparationSummary_.items.empty()) ;
		auto retainedEvent =
			// 停止後も保持する非空確定結果。
			prepareIndexFixture( window, context, 202U) ;
		window.processWorkerEvent( retainedEvent) ;
		const auto retainedAfterStop = window.preparationResultText_ ;	// 最新の非空結果本文。
		DRIVERCRATE_EXPECT( context, window.indexPreparationSummary_.items.size() == 3U) ;
		window.controller_.stop() ;
		window.worker_->stop() ;
		DRIVERCRATE_EXPECT( context, !window.worker_->requestScan( 999U)) ;
		window.processWorkerEvent( next) ;
		window.processWorkerEvent( progress) ;
		window.processWorkerEvent( retainedEvent) ;
		DRIVERCRATE_EXPECT( context, window.controller_.state() == ApplicationState::STOPPING &&
										window.preparationResultText_ == retainedAfterStop &&
										window.indexPreparationSummary_.items.size() == 3U) ;
		const HWND handle = window.window_ ;	// 破棄後に再利用しない試験handle。
		SendMessageW( handle, WM_CLOSE, 0, 0) ;
		DRIVERCRATE_EXPECT( context, IsWindow( handle) == FALSE) ;
		window.processWorkerEvent( next) ;
		window.processWorkerEvent( progress) ;
		window.processWorkerEvent( retainedEvent) ;
		DRIVERCRATE_EXPECT( context, window.preparationResultText_ == retainedAfterStop &&
										window.indexPreparationSummary_.items.size() == 3U &&
										!window.controller_.beginScan().accepted &&
										window.worker_ == nullptr) ;
		std::cout
			<< "Index UI delayed: original tuple3, progress6, terminal replay, new operation, cancellation, stop, close; real I/O: 0\n" ;
	}
} ;

namespace test {
namespace {

/**
 * @brief UI試験だけに公開したaccess境界。通常利用者向けAPIを追加しない。
 */
using Access = MainWindowMetadataTestAccess ;

//------------------------------------------------------------------------------
/**
 * @brief 同processの標準control本文を有限長で取得する。
 * @param[in] window 本試験が作成したWindowまたはcontrol。
 * @return 所有本文。異常な長さの場合は空。
 */
//------------------------------------------------------------------------------
std::wstring windowText( const HWND window)
{
	const int length = GetWindowTextLengthW( window) ;	// 同process controlの文字数。
	// 不正handleと過大本文から無制限な割当てを行わない。
	if( length < 0 || length > 65536) {
		return {} ;
	}

	std::wstring result( static_cast<std::size_t>( length) + 1U, L'\0') ;		// 終端用一文字を含む容量。
	const int	 copied = GetWindowTextW( window, result.data(), length + 1) ;	// 実copy文字数。
	result.resize( static_cast<std::size_t>( std::max( 0, copied))) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief HWNDを破棄せず、有限待機中も通常messageをdispatchする。
 * @param[in] done 終了条件。UI threadでだけ同期実行する。
 * @return 五秒以内に条件を満たした場合true。
 */
//------------------------------------------------------------------------------
bool pumpUntil( const std::function<bool()> &done)
{
	const auto deadline =
		// 試験待機上限。
		std::chrono::steady_clock::now() + std::chrono::seconds( 5) ;
	// 外部APIを待つfakeは存在せず、五秒で必ず試験へ戻る。
	while( !done() && std::chrono::steady_clock::now() < deadline) {
		MSG message{} ;	// 一件ずつ取り出すUI通知。
		// 有限queueにあるmessageを処理し、試験Window間のWM_QUITだけはdispatchしない。
		while( PeekMessageW( &message, nullptr, 0U, 0U, PM_REMOVE) != FALSE) {
			// 直前の合成Window破棄による終了通知を次の試験へ持ち越さない。
			if( message.message != WM_QUIT) {
				TranslateMessage( &message) ;
				DispatchMessageW( &message) ;
			}
		}

		static_cast<void>(
			MsgWaitForMultipleObjectsEx( 0U, nullptr, 10U, QS_ALLINPUT, MWMO_INPUTAVAILABLE)) ;
	}

	return done() ;
}

/** @brief 内部撮影とtimerの自然発生順序だけを保持するUI thread限定の観測値です。 */
struct CaptureTelemetry {
	/// 実captureWindowと独立描画の入口数です。legacy名の再利用も含みます。
	unsigned calls{} ;
	/// 現在の撮影深さです。
	unsigned depth{} ;
	/// 実撮影の最大再入深さです。
	unsigned maxDepth{} ;
	/// 自然発生timerの入口数です。
	unsigned timerCalls{} ;
	/// timer callbackの現在深さです。
	unsigned timerDepth{} ;
	/// timer callbackの最大深さです。
	unsigned maxTimerDepth{} ;
	/// 撮影中に入った自然発生timer数です。
	unsigned timerDuringCapture{} ;
	/// 実詳細dialogのclose開始数です。
	unsigned closes{} ;
	/// 撮影中に始まった実close数です。
	unsigned closeDuringCapture{} ;
	/// 同UI thread上の観測順序です。
	unsigned sequence{} ;
	/// 人工試験のtimer入口数です。自然発生へ混ぜません。
	unsigned artificialCalls{} ;
	/// 人工のcapture中callbackを遮断した数です。
	unsigned artificialBlocks{} ;
	/// 自然発生のcapture中callbackを遮断した数です。
	unsigned naturalBlocks{} ;
	/// 生存や本文hashが撮影開始と一致しなかった段階数です。
	unsigned snapshotFailures{} ;
	/// 成功したGdiFlush数です。
	unsigned flushes{} ;
	/// 正しい撮影bitmapをDCから外した数です。
	unsigned detaches{} ;
	/// 描画完了または選択解除に失敗した数です。
	unsigned boundaryFailures{} ;
} ;

// 実fixtureだけの状態であり製品UIやworkerへは渡しません。
thread_local CaptureTelemetry captureTelemetry{} ;
// 決定的な人工callbackだけを自然発生計数から分離します。
thread_local bool			  artificialCaptureTimer{} ;
// 元画像と初観測画像を上書きせず区別する固定接頭辞です。
constexpr std::wstring_view	  CAPTURE_PHASE = L"uc-fixed-" ;
// 新限定入口だけで元fresh/cache四dialogの独立描画を有効にします。
thread_local bool			  independentRenderEvidence{} ;
// 新限定入口が実際に描いたbitmap数です。旧capture呼出しとは別に報告します。
thread_local unsigned		  independentRasterCaptures{} ;
// 新描画の保存境界assertionだけを元VUI分母と区別します。
thread_local std::size_t	  independentRenderAssertions{} ;

//------------------------------------------------------------------------------
/**
 * @brief 非機密な実edit本文の同一性を撮影前後だけで比較します。
 * @param[in] window 同fixtureのdialogまたは親Windowです。
 * @return UTF-16 code unit順の非暗号hashです。認証用途には使用しません。
 */
//------------------------------------------------------------------------------
std::uint64_t				  captureBodyHash( const HWND window)
{
	const auto text =
		// 同fixture本文だけです。
		windowText( GetDlgItem( window, IDC_METADATA_DETAIL_TEXT)) ;
	std::uint64_t result = 14695981039346656037ULL ;	// FNV-1aの非暗号比較値です。
	// 元全文を省略せず同順に比較し、本文そのものは共有logへ出しません。
	for( const auto unit : text) {
		result ^= static_cast<std::uint64_t>( unit) ;
		result *= 1099511628211ULL ;
	}

	return result ;
}

/** @brief 実captureの全return経路で生存/本文/幾何とdepthを観測します。 */
class CaptureObservation final {
public:
	/**
	 * @brief 同fixture所有HWNDの撮影開始を記録します。
	 * @param[in] window 撮影対象です。他アプリのhandleを渡しません。
	 * @param[in] name 呼出元が所有する固定ASCII basenameです。
	 */
	CaptureObservation( const HWND window, const std::wstring_view name)
		: window_( window), name_( name), initialHash_( captureBodyHash( window))
	{
		++captureTelemetry.calls ;
		++captureTelemetry.depth ;
		captureTelemetry.maxDepth = std::max( captureTelemetry.maxDepth, captureTelemetry.depth) ;
		record( "begin") ;
	}
	/**
	 * @brief 早期returnも含め実終了順序を記録してdepthを戻します。
	 */
	~CaptureObservation()
	{
		record( "end") ;
		--captureTelemetry.depth ;
	}
	/**
	 * @brief 同captureのWin32とWICの段階境界を記録します。
	 * @param[in] phase 固定ASCII段階名です。
	 */
	void record( const char *phase) const
	{
		RECT		bounds{} ;								// fixture HWNDのscreen座標だけです。
		RECT		owner{} ;								// 同fixture親のscreen座標だけです。
		MONITORINFO monitor{sizeof( monitor)} ;				// 選択されたmonitorのworkareaだけです。
		const bool	alive = IsWindow( window_) != FALSE ;	// 実handle生存です。
		const auto	hash  = captureBodyHash( window_) ;		// Win32 copyされた元本文の非暗号比較値です。
		// 内部snapshotを画像成功へ換算せず、変化だけを独立に失敗へ残します。
		if( !alive || hash != initialHash_) {
			++captureTelemetry.snapshotFailures ;
		}

		const bool geometry = GetWindowRect( window_, &bounds) != FALSE &&
							  GetMonitorInfoW( MonitorFromWindow( window_, MONITOR_DEFAULTTONEAREST),
											  &monitor) != FALSE ;	// 実矩形取得です。
		static_cast<void>( GetWindowRect( GetWindow( window_, GW_OWNER), &owner)) ;
		const bool inside =
			geometry && bounds.left >= monitor.rcWork.left && bounds.top >= monitor.rcWork.top &&
			bounds.right <= monitor.rcWork.right &&
			bounds.bottom <= monitor.rcWork.bottom ;	// workareaからの逸脱だけを分類します。
		std::string name ;								// 呼出元の固定basenameだけをASCII化します。
		// 端末IDや本文ではない有限の固定名だけを出力します。
		for( const auto unit : name_) {
			name.push_back( static_cast<char>( unit)) ;
		}

		std::cout << "CAPTURE_EVENT seq=" << ++captureTelemetry.sequence << " phase=" << phase
				  << " name=" << name << " calls=" << captureTelemetry.calls
				  << " depth=" << captureTelemetry.depth
				  << " timerDepth=" << captureTelemetry.timerDepth << " alive=" << alive
				  << " bodyHash=" << hash << " rect=" << bounds.left << ',' << bounds.top << ','
				  << bounds.right << ',' << bounds.bottom << " owner=" << owner.left << ','
				  << owner.top << ',' << owner.right << ',' << owner.bottom
				  << " work=" << monitor.rcWork.left << ',' << monitor.rcWork.top << ','
				  << monitor.rcWork.right << ',' << monitor.rcWork.bottom << " inside=" << inside
				  << '\n' ;
	}

private:
	/// 同capture呼出し中だけ借用するfixture HWNDです。
	HWND			  window_{} ;
	/// 同呼出し中だけ生存する固定basenameです。
	std::wstring_view name_ ;
	/// 実capture開始時に観測した同本文の非暗号hashです。
	std::uint64_t	  initialHash_{} ;
} ;

/** @brief timerの自然発生再入を全return経路で計測します。 */
class CaptureTimerObservation final {
public:
	/**
	 * @brief capture中のcallback数と最大depthだけを実測します。
	 */
	CaptureTimerObservation() : artificial_( artificialCaptureTimer)
	{
		// 人工callbackを自然発生の証拠へ足しません。
		if( artificial_) {
			++captureTelemetry.artificialCalls ;
		} else {
			++captureTelemetry.timerCalls ;
		}

		++captureTelemetry.timerDepth ;
		// 自然発生の最大depthだけを保持します。
		if( !artificial_) {
			captureTelemetry.maxTimerDepth =
				std::max( captureTelemetry.maxTimerDepth, captureTelemetry.timerDepth) ;
		}

		// 通常tickを大量dumpせず、撮影中の入口だけを順序付きで残します。
		if( captureTelemetry.depth != 0U && !artificial_) {
			++captureTelemetry.timerDuringCapture ;
			std::cout << "TIMER_CAPTURE seq=" << ++captureTelemetry.sequence
					  << " depth=" << captureTelemetry.timerDepth
					  << " captureDepth=" << captureTelemetry.depth << '\n' ;
		}
	}
	/**
	 * @brief callbackの所有scopeを抜けた場合だけdepthを戻します。
	 */
	~CaptureTimerObservation()
	{
		--captureTelemetry.timerDepth ;
	}

private:
	/// この入口が人工callbackかをscopeへ固定します。
	bool artificial_{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 自然発生の実call数をunique画像数と区別して報告します。
 */
//------------------------------------------------------------------------------
void printCaptureTelemetry()
{
	std::cout << "CAPTURE_SUMMARY calls=" << captureTelemetry.calls
			  << " maxDepth=" << captureTelemetry.maxDepth
			  << " timerCalls=" << captureTelemetry.timerCalls
			  << " maxTimerDepth=" << captureTelemetry.maxTimerDepth
			  << " timerDuringCapture=" << captureTelemetry.timerDuringCapture
			  << " closes=" << captureTelemetry.closes
			  << " closeDuringCapture=" << captureTelemetry.closeDuringCapture
			  << " naturalBlocks=" << captureTelemetry.naturalBlocks
			  << " artificialCalls=" << captureTelemetry.artificialCalls
			  << " artificialBlocks=" << captureTelemetry.artificialBlocks
			  << " snapshotFailures=" << captureTelemetry.snapshotFailures
			  << " flushes=" << captureTelemetry.flushes
			  << " detaches=" << captureTelemetry.detaches
			  << " boundaryFailures=" << captureTelemetry.boundaryFailures << '\n' ;
}

/** @brief 試験WindowだけをcaptureするGDI resource所有者。 */
struct CaptureSurface {
	/// Screen DCから作るmemory DC。Desktop画素は読まない。
	HDC		dc{} ;
	/// 当該Windowだけを描くbitmap。
	HBITMAP bitmap{} ;
	/// Memory DCへ元々選択されていた非所有object。
	HGDIOBJ previous{} ;
	/**
	 * @brief Bitmap選択を戻してGDI resourceを解放する。
	 */
	~CaptureSurface()
	{
		// 選択中bitmapをDeleteObjectへ渡さない。
		if( dc != nullptr && previous != nullptr) {
			SelectObject( dc, previous) ;
		}

		// このscopeで確保したbitmapだけを解放する。
		if( bitmap != nullptr) {
			DeleteObject( bitmap) ;
		}

		// このscopeで確保したmemory DCだけを解放する。
		if( dc != nullptr) {
			DeleteDC( dc) ;
		}
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief 合成WindowをPNGへ保存し、実desktopや端末情報をcaptureしない。
 * @param[in] window 本試験で作成したWindow。
 * @param[in] name Build配下の固定basename。
 * @param[in] visibleFrameOnly trueならREADME用に可視captionとclient左右下端を保存します。
 * @return PrintWindowとPNG保存の全段階が成功した場合true。
 */
//------------------------------------------------------------------------------
bool captureWindow( const HWND window, const std::wstring_view name,
				   const bool visibleFrameOnly = false)
{
	CaptureObservation observation( window, name) ;	// 初観測ではguardやgeometryを変更しません。
	RECT			   bounds{} ;					// 合成Window全体の有限pixel範囲。
	// 画面のないhandleや過大領域をcaptureしない。
	if( GetWindowRect( window, &bounds) == FALSE || bounds.right <= bounds.left ||
	   bounds.bottom <= bounds.top || bounds.right - bounds.left > 4096 ||
	   bounds.bottom - bounds.top > 4096) {
		return false ;
	}

	const int width	 = bounds.right - bounds.left ;	// Pixel幅。
	const int height = bounds.bottom - bounds.top ;	// Pixel高さ。
	WICRect	  encoded{0, 0, width, height} ;		// 既定は元bitmap全体の寸法を維持します。
	// README撮影だけは不可視resize枠を含まない同じ物理pixel範囲を選びます。
	if( visibleFrameOnly) {
		RECT visible{} ;	// 当該fixture WindowのDWM可視枠です。
		RECT client{} ;		// 左右下端の未描画外周を除く当該Windowのclient範囲です。
		// DPI座標の不一致や取得失敗を旧範囲での撮影成功へ読み替えません。
		if( FAILED( DwmGetWindowAttribute( window, DWMWA_EXTENDED_FRAME_BOUNDS, &visible,
										sizeof( visible))) ||
		   GetClientRect( window, &client) == FALSE) {
			return false ;
		}

		POINT clientStart{client.left, client.top} ;	// 同じscreen座標へ変換するclient左上です。
		POINT clientEnd{client.right, client.bottom} ;	// 右下は矩形外側の境界です。
		// Captionの上端を保ったままclientの左右下端を同じ物理pixelへ結びます。
		if( ClientToScreen( window, &clientStart) == FALSE ||
		   ClientToScreen( window, &clientEnd) == FALSE) {
			return false ;
		}

		visible.left   = std::max( visible.left, clientStart.x) ;
		visible.right  = std::min( visible.right, clientEnd.x) ;
		visible.bottom = std::min( visible.bottom, clientEnd.y) ;
		// 可視領域が元bitmapに収まる場合だけ保存し、拡大や補間は行いません。
		if( visible.left < bounds.left || visible.top < bounds.top || visible.right > bounds.right ||
		   visible.bottom > bounds.bottom || visible.right <= visible.left ||
		   visible.bottom <= visible.top) {
			return false ;
		}

		encoded = {static_cast<INT>( visible.left - bounds.left),
				   static_cast<INT>( visible.top - bounds.top),
				   static_cast<INT>( visible.right - visible.left),
				   static_cast<INT>( visible.bottom - visible.top)} ;
		std::cout << "CAPTURE_VISIBLE_FRAME source=" << width << ',' << height
				  << " region=" << encoded.X << ',' << encoded.Y << ',' << encoded.Width << ','
				  << encoded.Height << " dpi=" << GetDpiForWindow( window) << '\n' ;
	}

	const HDC screen = GetDC( window) ;	// Pixel形式取得だけの非所有Window DC。
	// DC取得失敗ではbitmapを作らない。
	if( screen == nullptr) {
		return false ;
	}

	CaptureSurface surface ;	// 一度だけ解放するcapture用GDI資源。
	surface.dc	   = CreateCompatibleDC( screen) ;
	surface.bitmap = CreateCompatibleBitmap( screen, width, height) ;
	ReleaseDC( window, screen) ;
	// 全resourceを確保できた後にだけWindowを描画させる。
	if( surface.dc == nullptr || surface.bitmap == nullptr) {
		return false ;
	}

	surface.previous = SelectObject( surface.dc, surface.bitmap) ;
	// Modal timer直後も全childの初回描画を完了してから試験Windowをcaptureする。
	RedrawWindow( window, nullptr, nullptr,
				 RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME) ;
	observation.record( "after-redraw") ;
	// PrintWindowは指定Windowのclientと非clientだけを描く。
	if( PrintWindow( window, surface.dc, PW_RENDERFULLCONTENT) == FALSE) {
		return false ;
	}

	observation.record( "after-print") ;
	const bool flushed = GdiFlush() != FALSE ;	// 当該UI threadの描画batchの完了を明示します。
	// 描画失敗を未完bitmapの正常保存へ読み替えません。
	if( !flushed) {
		++captureTelemetry.boundaryFailures ;
		return false ;
	}

	++captureTelemetry.flushes ;
	const auto detached = SelectObject( surface.dc, surface.previous) ;	// 元DC objectへ復帰します。
	const bool exactBitmap = detached == surface.bitmap ;				// 外したobjectが所有bitmapかを確認します。
	std::cout << "CAPTURE_BOUNDARY seq=" << ++captureTelemetry.sequence << " flushed=" << flushed
			  << " exactBitmap=" << exactBitmap << '\n' ;
	// 外部bitmap読出し前に、撮影した所有bitmapの選択解除成功を必要とします。
	if( !exactBitmap) {
		++captureTelemetry.boundaryFailures ;
		return false ;
	}

	++captureTelemetry.detaches ;
	// 成功した復帰をRAII destructorで二重に行いません。
	surface.previous = nullptr ;
	observation.record( "after-boundary") ;

	Microsoft::WRL::ComPtr<IWICImagingFactory>	  factory ;	// PNG encoder生成元。
	Microsoft::WRL::ComPtr<IWICBitmap>			  bitmap ;	// GDI bitmapを読むCOM view。
	Microsoft::WRL::ComPtr<IWICStream>			  stream ;	// 固定test成果物の出力。
	Microsoft::WRL::ComPtr<IWICBitmapEncoder>	  encoder ;	// PNG encoder。
	Microsoft::WRL::ComPtr<IWICBitmapFrameEncode> frame ;	// 一枚だけのPNG frame。
	// 全COM段階を検証し、途中失敗を正常画像にしない。
	if( FAILED( CoCreateInstance( CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
							   IID_PPV_ARGS( &factory))) ||
	   FAILED( factory->CreateBitmapFromHBITMAP( surface.bitmap, nullptr, WICBitmapIgnoreAlpha,
											   &bitmap)) ||
	   FAILED( factory->CreateStream( &stream))) {
		return false ;
	}

	observation.record( "after-bitmap-copy") ;

	const auto directory =
		// Repository内の内部試験成果物。
		privateCaptureRoot ;
	std::filesystem::create_directories( directory) ;
	const auto outputName =
		name.starts_with( L"complete-index-")
			? std::wstring( CAPTURE_PHASE) +
				  std::wstring( name.substr( std::wstring_view{L"complete-index-"}.size()))
			: std::wstring( name) ;							// 新位相だけ別名にしlegacy名は再利用します。
	const auto path = directory / (outputName + L".png") ;	// 呼出し側の固定名だけを使用する。
	// StreamとPNG frameを有限bitmap寸法で初期化する。
	if( FAILED( stream->InitializeFromFilename( path.c_str(), GENERIC_WRITE)) ||
	   FAILED( factory->CreateEncoder( GUID_ContainerFormatPng, nullptr, &encoder)) ||
	   FAILED( encoder->Initialize( stream.Get(), WICBitmapEncoderNoCache)) ||
	   FAILED( encoder->CreateNewFrame( &frame, nullptr)) || FAILED( frame->Initialize( nullptr)) ||
	   FAILED(
		   frame->SetSize( static_cast<UINT>( encoded.Width), static_cast<UINT>( encoded.Height)))) {
		return false ;
	}

	WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGR ;	// Alphaを持たないWindow capture。
	return SUCCEEDED( frame->SetPixelFormat( &format)) &&
		   SUCCEEDED( frame->WriteSource( bitmap.Get(), visibleFrameOnly ? &encoded : nullptr)) &&
		   SUCCEEDED( frame->Commit()) && SUCCEEDED( encoder->Commit()) ;
}

/** @brief 原描画を上から順に保持する24bppBGRの有限pixel列です。 */
struct RenderRaster {
	/// Pixel幅です。4096以下です。
	UINT			  width{} ;
	/// Pixel高さです。4096以下です。
	UINT			  height{} ;
	/// DWORD境界に合わせた一行のbyte数です。
	UINT			  stride{} ;
	/// paddingも含む原copyです。比較時は実RGBだけを使用します。
	std::vector<BYTE> bytes ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 寸法と16MiB上限を検証し、原pixel保存先を初期化します。
 * @param[in] width Pixel幅です。
 * @param[in] height Pixel高さです。
 * @param[out] raster 成功時の有限保存先です。
 * @return 正の有限寸法を受理した場合trueです。
 */
//------------------------------------------------------------------------------
bool initializeRenderRaster( const UINT width, const UINT height, RenderRaster &raster)
{
	// 計算前に寸法を制限し、乗算とUINTへの切詰めを防ぎます。
	if( width == 0U || height == 0U || width > 4096U || height > 4096U) {
		return false ;
	}

	const UINT		  stride = (width * 3U + 3U) & ~3U ;					// DWORD境界を含む原行幅です。
	const std::size_t size	 = static_cast<std::size_t>( stride) * height ;	// 保存byte数です。
	// 画像寸法上限とは別に単artifact上限を守ります。
	if( size > 16U * 1024U * 1024U) {
		return false ;
	}

	raster.width  = width ;
	raster.height = height ;
	raster.stride = stride ;
	raster.bytes.assign( size, BYTE{}) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同fixtureのWIC sourceを比較用BGR形式へcopyします。
 * @param[in] factory 同UI threadの非null factoryです。
 * @param[in] source 同captureが所有する非null sourceです。
 * @param[out] raster 成功時の原copyです。失敗時は比較に使用しません。
 * @return 変換と全文copyが成功した場合trueです。
 * @note decode形式を揃えるだけで文字の追加や画像の補填をしません。
 */
//------------------------------------------------------------------------------
bool copyRenderWicPixels( IWICImagingFactory *factory, IWICBitmapSource *source,
						 RenderRaster &raster)
{
	UINT										width{} ;	// 実source幅です。
	UINT										height{} ;	// 実source高さです。
	Microsoft::WRL::ComPtr<IWICFormatConverter> converter ;	// 同scopeの比較用viewです。
	// source寸法と変換結果の両方を検査し、未取得pixelを正常値へ補完しません。
	if( FAILED( source->GetSize( &width, &height)) || !initializeRenderRaster( width, height, raster) ||
	   FAILED( factory->CreateFormatConverter( &converter)) ||
	   FAILED( converter->Initialize( source, GUID_WICPixelFormat24bppBGR, WICBitmapDitherTypeNone,
									nullptr, 0.0, WICBitmapPaletteTypeCustom))) {
		return false ;
	}

	return SUCCEEDED( converter->CopyPixels(
		nullptr, raster.stride, static_cast<UINT>( raster.bytes.size()), raster.bytes.data())) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自fixtureの原pixelを新しい一fileへ保存します。
 * @param[in] path 新限定入口の固定出力名です。
 * @param[in] raster 保存する原copyです。
 * @return 上書きせず全文保存できた場合trueです。
 */
//------------------------------------------------------------------------------
bool saveRenderRaw( const std::filesystem::path &path, const RenderRaster &raster)
{
	// 元の失敗artifactと同名の再実行結果を上書きしません。
	if( std::filesystem::exists( path) || raster.bytes.size() > 16U * 1024U * 1024U) {
		return false ;
	}

	std::ofstream output( path, std::ios::binary) ;	// このscopeだけが新fileを所有します。
	// file I/O境界でBYTEの所有領域を同じ長さのchar列として借用し、解釈や変更をしません。
	output.write( reinterpret_cast<const char *>( raster.bytes.data()),
				 static_cast<std::streamsize>( raster.bytes.size())) ;
	output.close() ;
	return !output.fail() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの原pixel矩形のRGB不一致画素数を計算します。
 * @param[in] first 最初の原copyです。
 * @param[in] second 比較する原copyです。
 * @param[in] firstRect 最初のcopy内の半開pixel矩形です。
 * @param[in] secondRect 比較copy内の同寸法矩形です。
 * @return 不一致pixel数です。不正矩形はsize_t最大値です。
 */
//------------------------------------------------------------------------------
std::size_t renderPixelDifferences( const RenderRaster &first, const RenderRaster &second,
								   const RECT &firstRect, const RECT &secondRect)
{
	const LONG width  = firstRect.right - firstRect.left ;	// 比較幅です。
	const LONG height = firstRect.bottom - firstRect.top ;	// 比較高さです。
	// 異なる領域や範囲外を一致へ読み替えません。
	if( width <= 0 || height <= 0 || firstRect.left < 0 || firstRect.top < 0 ||
	   secondRect.left < 0 || secondRect.top < 0 || width != secondRect.right - secondRect.left ||
	   height != secondRect.bottom - secondRect.top ||
	   firstRect.right > static_cast<LONG>( first.width) ||
	   firstRect.bottom > static_cast<LONG>( first.height) ||
	   secondRect.right > static_cast<LONG>( second.width) ||
	   secondRect.bottom > static_cast<LONG>( second.height)) {
		return std::numeric_limits<std::size_t>::max() ;
	}

	std::size_t differences{} ;	// RGBいずれかが異なる画素だけを一回数えます。
	// 有限矩形の各行を上から比較します。
	for( LONG y{}; y < height; ++y) {
		// 各画素の三色だけを比較し、行paddingは成功条件へ含めません。
		for( LONG x{}; x < width; ++x) {
			const auto firstOffset = static_cast<std::size_t>( firstRect.top + y) * first.stride +
									 // 最初のRGB位置です。
									 static_cast<std::size_t>( firstRect.left + x) * 3U ;
			const auto secondOffset = static_cast<std::size_t>( secondRect.top + y) * second.stride +
									  // 比較先のRGB位置です。
									  static_cast<std::size_t>( secondRect.left + x) * 3U ;
			differences += std::equal( first.bytes.begin() + firstOffset,
									  first.bytes.begin() + firstOffset + 3U,
									  second.bytes.begin() + secondOffset)
							   ? 0U
							   : 1U ;
		}
	}

	return differences ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同fixtureだけを一回描画し、GDI/WIC/PNGの原copyを全て保持します。
 * @param[in] popup 同scopeの生存詳細dialogです。
 * @param[in] target 同dialogまたはそのread-only editです。
 * @param[in] name 事前固定したASCII basenameです。
 * @param[in] directClient WM_PRINTCLIENTでedit clientだけを描く場合trueです。
 * @param[out] original GDI段階の原copyです。正常保存後だけ比較に使用します。
 * @return 保存と全RGB境界比較が成功した場合trueです。
 * @note 固定sleep・再試行・desktop読出し・他画像による補填は行いません。
 */
//------------------------------------------------------------------------------
bool captureRenderRaster( const HWND popup, const HWND target, const std::wstring_view name,
						 const bool directClient, RenderRaster &original)
{
	CaptureObservation observation( popup, name) ;	// 同本文とclose境界を両描画へ結びます。
	RECT			   bounds{} ;					// 全dialogまたはedit clientの原寸法です。
	// 失敗時も固定16描画を超えて別画像を生成しません。
	if( independentRasterCaptures >= 16U) {
		return false ;
	}

	const bool geometry =
		directClient ? GetClientRect( target, &bounds) != FALSE
					 : GetWindowRect( target, &bounds) != FALSE ;	// 描画方式ごとの実範囲です。
	// 未取得・過大・負の矩形からbitmapを作りません。
	if( !geometry || bounds.right <= bounds.left || bounds.bottom <= bounds.top ||
	   !initializeRenderRaster( static_cast<UINT>( bounds.right - bounds.left),
							   static_cast<UINT>( bounds.bottom - bounds.top), original)) {
		return false ;
	}

	const HDC reference = GetDC( target) ;	// Pixel形式だけを借用し、画面byteを読みません。
	// 非所有DCを取得できなければ他のWindowへfallbackしません。
	if( reference == nullptr) {
		return false ;
	}

	CaptureSurface surface ;	// 旧captureと同じDDBとmemory DCを一度だけ解放します。
	surface.dc	   = CreateCompatibleDC( reference) ;
	surface.bitmap = CreateCompatibleBitmap( reference, static_cast<int>( original.width),
											static_cast<int>( original.height)) ;
	ReleaseDC( target, reference) ;
	// 両resourceを所有できた後だけ同期描画します。
	if( surface.dc == nullptr || surface.bitmap == nullptr) {
		return false ;
	}

	surface.previous   = SelectObject( surface.dc, surface.bitmap) ;
	const bool redrawn = RedrawWindow( target, nullptr, nullptr,
									  RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN |
										  RDW_FRAME) != FALSE ;	// 元の有限同期です。
	observation.record( "render-after-redraw") ;
	LRESULT messageResult{} ;	// WM_PRINTCLIENTは戻り値だけで描画成功と判定しません。
	bool	printed = true ;	// PrintWindowだけのBOOL結果です。
	// 独立control描画は別bitmapへ直接送り、全体画像を補填しません。
	if( directClient) {
		// Win32 message境界で同scopeのHDCを整数幅のWPARAMへ渡します。
		messageResult = SendMessageW( target, WM_PRINTCLIENT, reinterpret_cast<WPARAM>( surface.dc),
									 PRF_CLIENT | PRF_ERASEBKGND) ;
	} else {
		printed = PrintWindow( target, surface.dc, PW_RENDERFULLCONTENT) != FALSE ;
	}

	++independentRasterCaptures ;
	observation.record( "render-after-print") ;
	const bool flushed	   = GdiFlush() != FALSE ;							// 全描画batchを原copy前に確定します。
	const auto detached	   = SelectObject( surface.dc, surface.previous) ;	// 所有DDBを外します。
	const bool exactBitmap = detached == surface.bitmap ;					// 正しい所有者から外れた実観測です。
	// 成功した復帰だけを二重に行わないようRAIIへ反映します。
	if( exactBitmap) {
		surface.previous = nullptr ;
	}

	std::string asciiName ;	// 固定ASCII名だけを明示変換して出力します。
	// 呼出し側の固定basenameを一文字ずつ変換し、暗黙の切詰めを行いません。
	for( const auto unit : name) {
		asciiName.push_back( static_cast<char>( unit)) ;
	}

	std::cout << "RENDER_DRAW name=" << asciiName << " direct=" << directClient
			  << " redraw=" << redrawn << " print=" << printed << " message=" << messageResult
			  << " flushed=" << flushed << " detached=" << exactBitmap << '\n' ;
	// 描画または選択解除失敗を正常な原copyへ進めません。
	if( !redrawn || !printed || !flushed || !exactBitmap) {
		return false ;
	}

	BITMAPINFO info{} ;	// 上から並ぶ24bppの独立GDI読取り形式です。
	info.bmiHeader.biSize		 = sizeof( BITMAPINFOHEADER) ;
	info.bmiHeader.biWidth		 = static_cast<LONG>( original.width) ;
	info.bmiHeader.biHeight		 = -static_cast<LONG>( original.height) ;
	info.bmiHeader.biPlanes		 = 1U ;
	info.bmiHeader.biBitCount	 = 24U ;
	info.bmiHeader.biCompression = BI_RGB ;
	const int lines =
		GetDIBits( surface.dc, surface.bitmap, 0U, original.height, original.bytes.data(), &info,
				  DIB_RGB_COLORS) ;	// 選択解除後の原ラスタです。
	const auto directory =
		privateCaptureRoot / L"independent-render-evidence" ;	// 新限定入口の成果物だけです。
	std::filesystem::create_directories( directory) ;
	const auto base = directory / std::wstring( name) ;	// 事前固定した位相名です。
	const bool rawSaved =
		// 原失敗も保持します。
		saveRenderRaw( base.wstring() + L".gdi.bgr", original) ;
	std::cout << "RENDER_GDI name=" << asciiName << " width=" << original.width
			  << " height=" << original.height << " stride=" << original.stride
			  << " lines=" << lines << " saved=" << rawSaved << '\n' ;
	// 部分copyでも原byteは残し、残りを成功へ数えません。
	if( lines != static_cast<int>( original.height) || !rawSaved) {
		return false ;
	}

	Microsoft::WRL::ComPtr<IWICImagingFactory>	  factory ;		// 元captureと同じfactoryです。
	Microsoft::WRL::ComPtr<IWICBitmap>			  bitmap ;		// 同DDBから作る元WIC sourceです。
	Microsoft::WRL::ComPtr<IWICStream>			  stream ;		// PNG出力だけを所有します。
	Microsoft::WRL::ComPtr<IWICBitmapEncoder>	  encoder ;		// 一frame PNGです。
	Microsoft::WRL::ComPtr<IWICBitmapFrameEncode> frame ;		// 元WriteSource方式です。
	RenderRaster								  wicPixels ;	// WIC段階の独立copyです。
	// 元CreateBitmapFromHBITMAPを通った時点のpixelを保存します。
	if( FAILED( CoCreateInstance( CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
							   IID_PPV_ARGS( &factory))) ||
	   FAILED( factory->CreateBitmapFromHBITMAP( surface.bitmap, nullptr, WICBitmapIgnoreAlpha,
											   &bitmap)) ||
	   !copyRenderWicPixels( factory.Get(), bitmap.Get(), wicPixels) ||
	   !saveRenderRaw( base.wstring() + L".wic.bgr", wicPixels)) {
		return false ;
	}

	observation.record( "render-after-wic") ;
	const auto pngPath = std::filesystem::path( base.wstring() + L".png") ;	// 原PNGの固定名です。
	// 原画像を上書きせず、旧captureと同じencoder契約を通します。
	if( std::filesystem::exists( pngPath) || FAILED( factory->CreateStream( &stream)) ||
	   FAILED( stream->InitializeFromFilename( pngPath.c_str(), GENERIC_WRITE)) ||
	   FAILED( factory->CreateEncoder( GUID_ContainerFormatPng, nullptr, &encoder)) ||
	   FAILED( encoder->Initialize( stream.Get(), WICBitmapEncoderNoCache)) ||
	   FAILED( encoder->CreateNewFrame( &frame, nullptr)) || FAILED( frame->Initialize( nullptr)) ||
	   FAILED( frame->SetSize( original.width, original.height))) {
		return false ;
	}

	WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGR ;	// 元PNGの要求形式です。
	// 原WIC sourceをそのまま保存し、独立描画や文字列を重ねません。
	if( FAILED( frame->SetPixelFormat( &format)) ||
	   FAILED( frame->WriteSource( bitmap.Get(), nullptr)) || FAILED( frame->Commit()) ||
	   FAILED( encoder->Commit())) {
		return false ;
	}

	frame.Reset() ;
	encoder.Reset() ;
	stream.Reset() ;
	// 保存上限超過の原fileは残し、その結果を正常とは扱いません。
	if( std::filesystem::file_size( pngPath) > 16U * 1024U * 1024U) {
		return false ;
	}

	Microsoft::WRL::ComPtr<IWICBitmapDecoder>	  decoder ;		// 保存fileを新しく読むdecoderです。
	Microsoft::WRL::ComPtr<IWICBitmapFrameDecode> decoded ;		// 実PNGの第一frameです。
	RenderRaster								  pngPixels ;	// 保存後readbackの原copyです。
	// fileから実decodeし、encoderの成功値だけで保存を受け入れません。
	if( FAILED( factory->CreateDecoderFromFilename( pngPath.c_str(), nullptr, GENERIC_READ,
												 WICDecodeMetadataCacheOnLoad, &decoder)) ||
	   FAILED( decoder->GetFrame( 0U, &decoded)) ||
	   !copyRenderWicPixels( factory.Get(), decoded.Get(), pngPixels) ||
	   !saveRenderRaw( base.wstring() + L".png-readback.bgr", pngPixels)) {
		return false ;
	}

	const RECT whole{0, 0, static_cast<LONG>( original.width),
					 // 全画素です。
					 static_cast<LONG>( original.height)} ;
	const auto gdiWic = renderPixelDifferences( original, wicPixels, whole, whole) ;	// WIC境界です。
	const auto wicPng =
		// 保存境界です。
		renderPixelDifferences( wicPixels, pngPixels, whole, whole) ;
	std::cout << "RENDER_STAGE name=" << asciiName << " gdiWicMismatch=" << gdiWic
			  << " wicPngMismatch=" << wicPng
			  << " pixels=" << static_cast<std::size_t>( original.width) * original.height << '\n' ;
	observation.record( "render-after-readback") ;
	return gdiWic == 0U && wicPng == 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元fresh/cacheの同位相で全体と独立editの原矩形を比較します。
 * @param[in] popup 同fixtureが所有する生存詳細dialogです。
 * @param[in] stage 元fresh/cacheの前後を示す固定ASCII名です。
 * @param[in,out] context 新描画の保存境界結果を集計します。
 * @note 比較画像をcrop・合成せず、差と未知を元のまま報告します。
 */
//------------------------------------------------------------------------------
void captureIndependentRefreshEvidence( const HWND popup, const char *stage, TestContext &context)
{
	const auto before = context.assertionCount() ;						// 新描画assertionだけの開始分母です。
	const HWND edit	  = GetDlgItem( popup, IDC_METADATA_DETAIL_TEXT) ;	// 元read-only editです。
#if defined( _DEBUG)
	const std::wstring configuration = L"Debug" ;	// 新入口の固定構成名です。
#else
	const std::wstring configuration = L"Release" ;	// 新入口の固定構成名です。
#endif
	std::wstring phase ;	// 固定ASCII名だけをUTF-16へ変換します。
	// 呼出し元の固定位相名を一回だけ変換します。
	for( const char *unit = stage; *unit != '\0'; ++unit) {
		phase.push_back( static_cast<wchar_t>( *unit)) ;
	}

	const auto	 basename = L"f4a-" + configuration + L"-" + phase ;	// 計八位相の一つです。
	RenderRaster printed ;												// PrintWindow全体の原pixelです。
	RenderRaster independent ;											// WM_PRINTCLIENTの独立した原pixelです。
	const bool	 printSaved =
		// 一回だけです。
		captureRenderRaster( popup, popup, basename + L"-print", false, printed) ;
	const bool clientSaved = captureRenderRaster( popup, edit, basename + L"-client", true,
												 independent) ;	// 別bitmap一回です。
	DRIVERCRATE_EXPECT( context, printSaved) ;
	DRIVERCRATE_EXPECT( context, clientSaved) ;
	RECT  popupBounds{} ;	// 全体ラスタ原点を与える実screen矩形です。
	RECT  editClient{} ;	// 独立ラスタの比較範囲です。
	POINT origin{} ;		// edit client原点をscreen座標へ変換します。
	SetLastError( ERROR_SUCCESS) ;
	const int mapped = MapWindowPoints( edit, nullptr, &origin, 1U) ;	// 他Windowのpixelは読みません。
	const DWORD mapError = GetLastError() ;								// 0変位と変換失敗を区別します。
	const bool	geometry = GetWindowRect( popup, &popupBounds) != FALSE &&
						  GetClientRect( edit, &editClient) != FALSE &&
						  (mapped != 0 || mapError == ERROR_SUCCESS) ;	// 実矩形です。
	origin.x -= popupBounds.left ;
	origin.y -= popupBounds.top ;
	const RECT printClient{origin.x, origin.y, origin.x + editClient.right,
						   origin.y + editClient.bottom} ;	// 全体ラスタ内のedit clientだけです。
	DRIVERCRATE_EXPECT( context, geometry && printSaved && clientSaved && printed.width != 0U &&
									independent.width == static_cast<UINT>( editClient.right) &&
									independent.height == static_cast<UINT>( editClient.bottom)) ;
	const auto differences =
		geometry && printSaved && clientSaved
			? renderPixelDifferences( printed, independent, printClient, editClient)
			: std::numeric_limits<std::size_t>::max() ;	// 未取得は一致へ換算しません。
	std::cout << "RENDER_PAIR phase=" << stage << " printRect=" << printClient.left << ','
			  << printClient.top << ',' << printClient.right << ',' << printClient.bottom
			  << " clientRect=" << editClient.left << ',' << editClient.top << ','
			  << editClient.right << ',' << editClient.bottom << " mismatch=" << differences
			  << " dpi=" << GetDpiForWindow( popup) << '\n' ;
	const auto									text = windowText( edit) ;	// 同phaseの元本文です。
	constexpr std::array<std::wstring_view, 6U> LABELS{
		L"HTTP:",		L"元通信診断:",	  L"更新診断:",
		L"commit区分:", L"manifest世代:", L"保存世代:"} ;	// 六事実を別pixel帯へ結びます。
	LONG previousY{} ;								// 最終行の高さだけを直前の実行間隔から得ます。
	// 六fieldを元順に一回だけ比較し、不明な帯も分母へ残します。
	for( std::size_t index{}; index < LABELS.size(); ++index) {
		const auto offset	  = text.find( LABELS[index]) ;	// 元本文における実field位置です。
		const auto position	  = offset == std::wstring::npos
									? -1
									: SendMessageW( edit, EM_POSFROMCHAR, static_cast<WPARAM>( offset),
												   0) ;						// 実client座標です。
		const LONG y		  = static_cast<short>( HIWORD( position)) ;	// 実行の開始Yです。
		const auto nextOffset = index + 1U < LABELS.size() ? text.find( LABELS[index + 1U])
														   : std::wstring::npos ;	// 次fieldです。
		const auto nextPosition =
			nextOffset == std::wstring::npos
				? -1
				: SendMessageW( edit, EM_POSFROMCHAR, static_cast<WPARAM>( nextOffset),
							   0) ;	// 次行座標です。
		const LONG bandHeight = nextPosition != -1 ? static_cast<short>( HIWORD( nextPosition)) - y
												   : y - previousY ;	// 実行間隔です。
		const RECT clientBand{0, y, editClient.right, y + bandHeight} ;	// 原clientの一行帯です。
		const RECT printBand{origin.x, origin.y + y, origin.x + editClient.right,
							 origin.y + y + bandHeight} ;	// 対応する全体内の同寸法帯です。
		const auto bandDifferences =
			geometry && printSaved && clientSaved && position != -1 && bandHeight > 0
				? renderPixelDifferences( printed, independent, printBand, clientBand)
				: std::numeric_limits<std::size_t>::max() ;	// 未観測を0差にしません。
		std::cout << "RENDER_BAND phase=" << stage << " field=" << index << " y=" << y
				  << " height=" << bandHeight << " mismatch=" << bandDifferences << '\n' ;
		previousY = y ;
	}

	independentRenderAssertions += context.assertionCount() - before ;
}

/** @brief 操作するdialog種別。全て本試験のWindowが所有するものだけ。 */
enum class DialogMode {
	/// 元取得dialogの全文と条件を明示確認します。
	INDEX_PREPARATION_ACCEPT,
	/// 最初の対象一覧で取得確認全体を取り消します。
	INDEX_PREPARATION_OVERVIEW_CANCEL,
	/// 規約同意後、対象別の取得確認全体を取り消します。
	INDEX_PREPARATION_TARGET_CANCEL,
	/// 全文規約だけを拒否し0grantを確認します。
	INDEX_PREPARATION_CANCEL,
	/// 規約同意後の対象別取得だけを明示NOにします。
	INDEX_PREPARATION_TARGET_NO,
	/// 規約と対象取得判断の後、最終件数確認だけを明示NOにします。
	INDEX_PREPARATION_FINAL_NO,
	/// 一件の情報検索を明示選択する。
	ACCEPT,
	/// 未選択のままdialogを閉じる。
	CANCEL,
	/// 情報検索の非機密結果を読み取る。
	DETAILS,
	/// Fake操作の取消しとWindow終了待ちに同意する。
	CLOSE,
	/// 元candidate選択と復旧警告を読む実確認へ明示YESを送ります。
	INDEX_INSTALL_ACCEPT,
	/// 同じ確認本文を読む実確認へ明示NOを送ります。
	INDEX_INSTALL_CANCEL,
	/// 本体が確定した個別導入結果を案内する標準dialogを読みます。
	INDEX_INSTALL_RESULT,
	/// 旧候補の導入commandが出した対象再選択案内を読みます。
	INDEX_INSTALL_SELECTION_REQUIRED,
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同scopeが通常取得dialogを操作するmodeだけを判定します。
 * @param[in] mode 一つの事前固定したdialog判断です。
 * @return 本物の取得確認dialogを操作するmodeならtrueです。
 */
//------------------------------------------------------------------------------
bool isPreparationDialogMode( const DialogMode mode) noexcept
{
	return mode == DialogMode::INDEX_PREPARATION_ACCEPT ||
		   mode == DialogMode::INDEX_PREPARATION_OVERVIEW_CANCEL ||
		   mode == DialogMode::INDEX_PREPARATION_TARGET_CANCEL ||
		   mode == DialogMode::INDEX_PREPARATION_CANCEL ||
		   mode == DialogMode::INDEX_PREPARATION_TARGET_NO ||
		   mode == DialogMode::INDEX_PREPARATION_FINAL_NO ;
}

/** @brief 同期dialog内のtimerが借用する、UI thread限定の操作状態。 */
struct DialogState {
	/// 検索後の実確認中にcommand再入だけを検査する同scopeの非所有Windowです。
	MainWindow		  *searchWindow{} ;
	/// 本体がpostした元通知のcopyです。確認中に一度だけ同通知を再送します。
	std::optional<MSG> searchReplay ;
	/// 同確認中の検索・準備・重複通知の再入拒否を観測済みの場合trueです。
	bool			   searchReentryChecked{} ;
	/// 原HTML文書から抽出される固定title付き全文を照合する場合trueです。
	bool			   htmlTerms{} ;
	/// 原対象別TaskDialogへの明示取得判断数です。
	unsigned		   acquisitionDecisionDialogs{} ;
	/// 原最終件数MessageBoxへの明示判断数です。
	unsigned		   finalConfirmationDialogs{} ;
	/// 第二EULAだけの元署名source subject差を固定期待へ結びます。
	bool			   secondTermsSubject{} ;
	/// 第二EULAだけの元署名公開revision差を固定期待へ結びます。
	bool			   secondTermsRevision{} ;
	/// 実EULA全文controlを読んだ回数です。
	unsigned		   eulaDialogs{} ;
	/// 最初の所有dialogの低位control構成を一度だけ観測します。
	unsigned		   popupObservations{} ;
	/// 元MainWindowが順序固定で表示するTaskDialog数です。
	unsigned		   preparationTaskDialogs{} ;
	/// 原全文・出典・改訂の表示が一致した場合trueです。
	bool			   eulaValid{true} ;
	/// Assertionの集計先。Timerより長く生存する。
	TestContext		  *context{} ;
	/// 本試験が所有するMainWindow。
	HWND			   owner{} ;
	/// 今回操作するdialog種別。
	DialogMode		   mode{DialogMode::ACCEPT} ;
	/// 初期選択空を検査済みの場合true。
	bool			   handled{} ;
	/// Queue拒否に伴う固定error dialogを期待する場合true。
	bool			   allowError{} ;
	/// 期待されたerror dialog数。
	unsigned		   errors{} ;
	/// Timer tick数。250回でdialog待ちを打ち切る。
	unsigned		   ticks{} ;
	/// Timeoutまたはcallback例外を検出した場合true。
	bool			   failed{} ;
	/// 読取り専用詳細本文。
	std::wstring	   details ;
	/// 合成画像だけの固定出力名。
	std::wstring	   captureName{L"details"} ;
	/// 二段階の通常導線で汎用取得dialogが一つでも出たら失敗にする場合trueです。
	bool			   twoStep{} ;
	/// 通常SearchでEULAが表示された場合も自動同意せず拒否する場合trueです。
	bool			   rejectEula{} ;
	/// この有限caseで画像を保存する場合trueです。Release回帰はcontrol検査だけを行えます。
	bool			   captureDetails{true} ;
	/// 任意規約の閲覧で同意button不在と偽装IDYESの非実行を確認する場合trueです。
	bool			   inlineTermsView{} ;
	/// 実際にdialogへ渡した生成本文を比較する同scopeの非所有Windowです。
	MainWindow		  *refreshWindow{} ;
	/// 元freshならtrue、元503/E_FAIL cacheならfalseです。
	bool			   refreshFresh{} ;
	/// 修正後の具体値と閲覧座標を独立期待へassertする場合trueです。
	bool			   refreshStrict{} ;
	/// 原probeと前後を区別する固定ASCII観測名です。
	const char		  *refreshStage{"none"} ;
	/// 五列/原順/通知/ordinal境界を実tableで確認する場合trueです。
	bool			   historyTableProbe{} ;
	/// 表示集約後のordinal・連番・非選択hoverだけを照合する場合trueです。
	bool			   detailDisplayProbe{} ;
	/// 同表示で残した別情報のsuffix/tipを期待する場合trueです。
	bool			   detailDistinctInformation{} ;
	/// 初期highlightなしで閲覧可能かを元実controlで確認します。
	bool			   detailExpectNoInitial{} ;
	/// 自作画像fixtureの初回描画がmessage loopを一巡した場合trueです。
	bool			   historyCaptureReady{} ;
	/// 狭幅の実dialogへresizeする場合trueです。
	bool			   detailNarrow{} ;
	/// 非負なら元choiceの初期highlightを照合します。
	int				   detailInitialEntry{-1} ;
	/// Enterで閲覧終了する場合trueです。候補を適用しません。
	bool			   detailEnterClose{} ;
	/// 明示選択buttonへAlt+Sを送る場合trueです。
	bool			   detailApplyAccessKey{} ;
	/// 明示選択buttonへSpaceを送る場合trueです。
	bool			   detailApplySpace{} ;
	/// Device詳細の標準tableで閲覧するentry。負値なら初期表示を維持する。
	int				   detailEntry{-1} ;
	/// この候補を選択buttonを明示操作する場合true。
	bool			   chooseDetailCandidate{} ;
	/// 現在構成・失効候補の選択拒否を確認する場合false。
	bool			   detailSelectable{true} ;
	/// 非0なら同deviceの全観測・候補entry数を照合する。
	unsigned		   detailEntryCount{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同threadかつ同dialogが所有するtooltipだけを探す。
 * @param[in] dialog Fixture自身のdialog。
 * @return 実tooltip、存在しなければnullptr。
 */
//------------------------------------------------------------------------------
HWND deviceTipWindow( const HWND dialog)
{
	struct Search {
		/// 同fixtureの借用ownerと検索結果だけを保持します。
		HWND owner{}, result{} ;
	} search{dialog, nullptr} ; // 外部windowの本文は読みません。
	EnumThreadWindows(
		GetCurrentThreadId(),
		[]( HWND window, LPARAM parameter) -> BOOL {
			auto &match =
				*reinterpret_cast<Search *>( parameter) ;	// この列挙呼出し中だけ借用します。
			wchar_t name[64]{} ;							// Native classだけを確認します。
			GetClassNameW( window, name, 64) ;
			// 実fixtureの所有HWND以外は採用しません。
			if( GetWindow( window, GW_OWNER) == match.owner &&
			   std::wstring_view( name) == TOOLTIPS_CLASSW) {
				match.result = window ;
				return FALSE ;
			}

			return TRUE ;
		},
		reinterpret_cast<LPARAM>( &search)) ;
	return search.result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 可視の実native tooltipから現在の短文を読む。
 * @param[in] dialog Fixture所有dialog。
 * @return 実表示文。非表示なら空文字。
 */
//------------------------------------------------------------------------------
std::wstring deviceTipText( const HWND dialog)
{
	const HWND tip = deviceTipWindow( dialog) ;	// 別windowのtooltipを読みません。
	// 非表示の古い借用文字列を表示成功に数えません。
	if( tip == nullptr || !IsWindowVisible( tip)) {
		return {} ;
	}

	TTTOOLINFOW tool{sizeof( tool)} ;	// tool識別子も実controlから読みます。
	// Tool不存在では文字列を補完しません。
	if( !SendMessageW( tip, TTM_ENUMTOOLSW, 0, reinterpret_cast<LPARAM>( &tool))) {
		return {} ;
	}

	wchar_t text[512]{} ;	// 製品の短文上限より大きい有限copyです。
	tool.lpszText = text ;
	SendMessageW( tip, TTM_GETTEXTW, 512U, reinterpret_cast<LPARAM>( &tool)) ;
	return text ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自分のnative tooltipの退場だけを有限時間観測します。
 * @param[in] dialog Fixtureが所有するdialogです。
 * @return 500ms以内に実tooltipが非表示になった場合trueです。
 */
//------------------------------------------------------------------------------
bool waitDeviceTipHidden( const HWND dialog)
{
	const HWND tip		= deviceTipWindow( dialog) ;	// 他のdialogの通知は処理しません。
	const auto deadline = std::chrono::steady_clock::now() +
						  // Fade完了の有限上限です。
						  std::chrono::milliseconds( 500) ;
	// Tooltip自身の描画/タイマーだけを処理し、DialogDriverの監視を再入させません。
	while( !deviceTipText( dialog).empty() && std::chrono::steady_clock::now() < deadline) {
		MSG message{} ;	// 当該native controlのqueueだけです。
		// 当該tooltipへ届いた通知を順に処理します。
		while( tip != nullptr && PeekMessageW( &message, tip, 0U, 0U, PM_REMOVE)) {
			TranslateMessage( &message) ;
			DispatchMessageW( &message) ;
		}

		static_cast<void>(
			MsgWaitForMultipleObjectsEx( 0U, nullptr, 10U, QS_ALLINPUT, MWMO_INPUTAVAILABLE)) ;
	}

	return deviceTipText( dialog).empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択を変更せず実cellの文字へmouse hoverをreplayする。
 * @param[in] dialog Fixture所有dialog。
 * @param[in] row 実row。
 * @param[in] column 実column。
 * @return 実tooltipの表示文。
 */
//------------------------------------------------------------------------------
std::wstring hoverDeviceCell( const HWND dialog, const int row, const int column)
{
	const HWND table = GetDlgItem( dialog, IDC_DEVICE_DETAIL_CANDIDATES) ;	// 実tableです。
	RECT	   cell{}, heading{} ;											// 独立した実row/header座標です。
	const HWND header = ListView_GetHeader( table) ;						// 実列幅を使います。
	// 読めないcellを先頭の成功へ補完しません。
	if( !ListView_GetSubItemRect( table, row, column, LVIR_BOUNDS, &cell) ||
	   !Header_GetItemRect( header, column, &heading)) {
		return {} ;
	}

	MapWindowPoints( header, table, reinterpret_cast<POINT *>( &heading), 2U) ;
	const int x = heading.left +
				  // 文字始端の内側です。
				  MulDiv( 9, static_cast<int>( GetDpiForWindow( table)), 96) ;
	const int y = (cell.top + cell.bottom) / 2 ;	// 行内の文字高さです。
	SendMessageW( table, WM_MOUSEMOVE, 0, MAKELPARAM( x, y)) ;
	SendMessageW( table, WM_MOUSEHOVER, 0, MAKELPARAM( x, y)) ;
	return deviceTipText( dialog) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 説明を持たないcellへ移動した後の実tooltip退場を確認します。
 * @param[in] dialog Fixtureが所有するdialogです。
 * @param[in] row 退場条件を試す元rowです。
 * @param[in] column 同じtableの元columnです。
 * @return 実tooltipが非表示になった場合trueです。
 */
//------------------------------------------------------------------------------
bool emptyDeviceTipAfterHover( const HWND dialog, const int row, const int column)
{
	static_cast<void>( hoverDeviceCell( dialog, row, column)) ;
	return waitDeviceTipHidden( dialog) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非機密な通信説明だけをUTF-16 code unitのASCII列へ変換します。
 * @param[in] value 本有限fixtureの通信本文です。端末ID/URLを渡しません。
 * @return NULを省略しない一unit四桁のhex列です。
 */
//------------------------------------------------------------------------------
std::string refreshTextHex( const std::wstring_view value)
{
	constexpr char DIGITS[] = "0123456789abcdef" ;	// Code unitを欠落なく残す固定文字です。
	std::string	   result ;							// 所有する非機密な原文字列観測です。
	// NULも含め全code unitを元順に記録します。
	for( const wchar_t unit : value) {
		// 一つのUTF-16 unitの四桁を上位から追加します。
		for( unsigned shift = 16U; shift != 0U; shift -= 4U) {
			result.push_back( DIGITS[(static_cast<unsigned>( unit) >> (shift - 4U)) & 15U]) ;
		}
	}

	return result ;
}

// 旧六入力と追加exact-fieldsの分母を同UI threadで分離します。
thread_local std::size_t refreshExactAssertions{} ;
// 実fresh/cacheの前後dialog到達数を旧入力数へ混ぜません。
thread_local unsigned	 refreshDetailObservations{} ;

//------------------------------------------------------------------------------
/**
 * @brief 実本文と実可視editのcopy/geometry/独立数値を同じdialogで分離観測します。
 * @param[in] edit 同fixture所有の実read-only editです。
 * @param[in,out] state 同UI threadが保持する元fresh/cache入力と観測先です。
 */
//------------------------------------------------------------------------------
void					 inspectRefreshDetail( const HWND edit, DialogState &state)
{
	const auto before =
		// 旧6caseと別に加算するexact-fields件数です。
		state.context->assertionCount() ;
	const auto generated = Access::refreshDetailGenerated( *state.refreshWindow) ;	// 実生成本文です。
	const int  reported	 = GetWindowTextLengthW( edit) ;							// 実editが保持する終端を除く長さです。
	std::wstring actual( static_cast<std::size_t>( std::max( 0, reported)) + 1U,
						L'\0') ;	// 終端込み容量です。
	const int	 copied = GetWindowTextW( edit, actual.data(),
										 // 同processの実copy長です。
										 static_cast<int>( actual.size())) ;
	actual.resize( static_cast<std::size_t>( std::max( 0, copied))) ;
	const auto nuls =
		// 生成段階の埋込NUL数です。
		std::count( generated.begin(), generated.end(), L'\0') ;
	const auto cStringLength =
		std::char_traits<wchar_t>::length( generated.c_str()) ;					// Win32が参照する先頭区間です。
	const auto style = GetWindowLongPtrW( edit, GWL_STYLE) ;					// 実可視controlのstyleです。
	RECT	   client{} ;														// 実edit内で文字を閲覧できるpixel範囲です。
	const bool hasClient = GetClientRect( edit, &client) != FALSE ;				// 実geometry取得結果です。
	const auto lineCount = SendMessageW( edit, EM_GETLINECOUNT, 0, 0) ;			// Wrap後の実行数です。
	const auto firstLine = SendMessageW( edit, EM_GETFIRSTVISIBLELINE, 0, 0) ;	// 実閲覧開始位置です。
	SCROLLINFO scroll{sizeof( scroll), SIF_ALL} ;								// 実垂直scrollの範囲とpageです。
	const bool hasScroll =
		// scroll情報の取得状態です。
		GetScrollInfo( edit, SB_VERT, &scroll) != FALSE ;
	const auto lastIndex =
		// 終端NULを文字位置へ渡しません。
		actual.empty() ? 0U : actual.size() - 1U ;
	const auto position =
		// 実最終文字です。
		SendMessageW( edit, EM_POSFROMCHAR, static_cast<WPARAM>( lastIndex), 0) ;
	const int  x		   = static_cast<short>( LOWORD( position)) ;	// Win32の符号付きpixel位置です。
	const int  y		   = static_cast<short>( HIWORD( position)) ;	// Win32の符号付きpixel位置です。
	const bool lastVisible = hasClient && position != -1 && x >= client.left && x < client.right &&
							 y >= client.top &&
							 y < client.bottom ;	// 元viewport内の最終文字開始位置です。
	const std::wstring_view expectedTail =
		state.refreshFresh ? L"保存世代: 7" : L"保存世代: —" ;	// 元固定数値期待です。
	const bool generatedTail =
		// 私有段階だけの観測です。
		generated.find( expectedTail) != std::wstring::npos ;
	const bool actualTail =
		// 実editへcopyされた元末尾です。
		actual.find( expectedTail) != std::wstring::npos ;
	unsigned fieldMask{} ;	// 具体値と実座標の双方を満たしたfieldだけのbitです。
	// 原probeは不明な欠損を成功へ数えず、修正後に独立具体値を追加照合します。
	if( state.refreshStrict) {
		DRIVERCRATE_EXPECT( *state.context,
						   nuls == 0 && cStringLength == generated.size() &&
							   static_cast<std::size_t>( copied) == generated.size() &&
							   reported == copied && actual == generated) ;
		DRIVERCRATE_EXPECT( *state.context, actual.ends_with( expectedTail) && hasClient &&
											   lastVisible && firstLine == 0) ;
		constexpr LONG_PTR REQUIRED_STYLE = ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY |
											WS_VSCROLL ;	// 実閲覧controlの必要条件です。
		DRIVERCRATE_EXPECT(
			*state.context,
			(style & REQUIRED_STYLE) == REQUIRED_STYLE && IsWindowVisible( edit) != FALSE &&
				IsWindowEnabled( edit) != FALSE && lineCount == 7 && hasScroll && scroll.nPos == 0 &&
				static_cast<unsigned>( scroll.nMax - scroll.nMin + 1) <= scroll.nPage) ;
		const std::array<std::wstring_view, 6U> expectedFields =
			state.refreshFresh
				? std::array<std::wstring_view, 6U>{L"HTTP: 0\r\n",
													L"元通信診断: 0x00000000",
													L"更新診断: 0x00000000",
													L"commit区分: 1\r\n",
													L"manifest世代: 7\r\n",
													L"保存世代: 7"}
				: std::array<std::wstring_view, 6U>{
					  L"HTTP: 503\r\n",		   L"元通信診断: 0x80004005",
					  L"更新診断: 0x80004005", L"commit区分: 0\r\n",
					  L"manifest世代: —\r\n",  L"保存世代: —"} ;	// 元入力から独立して固定します。
		// 各fieldを実edit全文に探し、実control内での閲覧位置も個別に確認します。
		for( std::size_t index{}; index < expectedFields.size(); ++index) {
			const auto offset =
				// formatter自己比較ではない具体値です。
				actual.find( expectedFields[index]) ;
			DRIVERCRATE_EXPECT( *state.context, offset != std::wstring::npos) ;
			const auto fieldPosition =
				offset == std::wstring::npos
					? -1
					: SendMessageW( edit, EM_POSFROMCHAR, static_cast<WPARAM>( offset),
								   0) ;	// 実field開始座標です。
			const int fieldX =
				// Win32符号付きpixelです。
				static_cast<short>( LOWORD( fieldPosition)) ;
			const int fieldY =
				// Win32符号付きpixelです。
				static_cast<short>( HIWORD( fieldPosition)) ;
			const bool visible = hasClient && fieldPosition != -1 && fieldX >= client.left &&
								 fieldX < client.right && fieldY >= client.top &&
								 fieldY < client.bottom ;	// 実viewport条件です。
			DRIVERCRATE_EXPECT( *state.context, visible) ;
			// 文字列と座標の両方を得たfieldだけを成功maskへ残します。
			if( offset != std::wstring::npos && visible) {
				fieldMask |= 1U << static_cast<unsigned>( index) ;
			}
		}
	}

	refreshExactAssertions += state.context->assertionCount() - before ;
	++refreshDetailObservations ;
	std::cout << "DETAIL_PROBE stage=" << state.refreshStage << " strict=" << state.refreshStrict
			  << " fresh=" << state.refreshFresh << " generated=" << generated.size()
			  << " nul=" << nuls << " cstr=" << cStringLength << " reported=" << reported
			  << " copied=" << copied << " generatedTail=" << generatedTail
			  << " actualTail=" << actualTail << " style=" << static_cast<std::uint64_t>( style)
			  << " client=" << client.left << ',' << client.top << ',' << client.right << ','
			  << client.bottom << " lines=" << lineCount << " first=" << firstLine
			  << " scroll=" << hasScroll << ',' << scroll.nMin << ',' << scroll.nMax << ','
			  << scroll.nPage << ',' << scroll.nPos << " last=" << x << ',' << y
			  << " lastVisible=" << lastVisible << " fieldMask=" << fieldMask
			  << " extraAssertions=" << state.context->assertionCount() - before
			  << " generatedHex=" << refreshTextHex( generated)
			  << " actualHex=" << refreshTextHex( actual) << '\n' ;
}

// 全dialog操作は単一UI threadで直列に行う。製品global hookは使わない。
thread_local DialogState *activeDialog{} ;

//------------------------------------------------------------------------------
/**
 * @brief Metadata dialogの初期状態・keyboard選択・未対応拒否を確認する。
 * @param[in] dialog 本試験Windowが所有する同期dialog。
 * @param[in,out] state Timerの借用状態。
 */
//------------------------------------------------------------------------------
void					  exerciseSelectionDialog( const HWND dialog, DialogState &state)
{
	auto	  &context		  = *state.context ;									// Assertionの参照先。
	const HWND list			  = GetDlgItem( dialog, IDC_METADATA_PROVIDER_LIST) ;	// 実標準ListView。
	const auto descriptors	  = builtInProviderDescriptors() ;						// 全Providerの唯一の正本。
	const auto supportedCount =														// 専用dialogのcheck対象数。
		std::count_if( descriptors.begin(), descriptors.end(), isMetadataSearchProvider) ;
	const int rowCount		= static_cast<int>( descriptors.size()) ;	// UI上限64件以内の登録総数。
	const int supportedRows = static_cast<int>( supportedCount) ;		// 安定整列後の対応行数。
	DRIVERCRATE_EXPECT( context, ListView_GetItemCount( list) == rowCount) ;
	DRIVERCRATE_EXPECT( context, IsWindowEnabled( GetDlgItem( dialog, IDYES)) == FALSE) ;
	DRIVERCRATE_EXPECT( context,
					   IsDlgButtonChecked( dialog, IDC_METADATA_NETWORK_APPROVAL) == BST_UNCHECKED) ;
	// 空集合への合成開始commandでもdialogを閉じない。
	SendMessageW( dialog, WM_COMMAND, IDYES, 0) ;
	DRIVERCRATE_EXPECT( context, IsWindow( dialog) != FALSE) ;
	// 対応行はunchecked、未対応行はcheckboxなしで表示する。
	for( int row = 0; row < rowCount; ++row) {
		DRIVERCRATE_EXPECT( context, ListView_GetItemState( list, row, LVIS_STATEIMAGEMASK) ==
										(row < supportedRows ? INDEXTOSTATEIMAGEMASK( 1) : 0U)) ;
	}

	DRIVERCRATE_EXPECT( context, supportedRows >= 0 && supportedRows < rowCount) ;
	// 最初の未対応行へcheckを注入しても状態を復活させない。
	if( supportedRows >= 0 && supportedRows < rowCount) {
		ListView_SetItemState( list, supportedRows, INDEXTOSTATEIMAGEMASK( 2), LVIS_STATEIMAGEMASK) ;
		DRIVERCRATE_EXPECT( context,
						   ListView_GetItemState( list, supportedRows, LVIS_STATEIMAGEMASK) == 0U) ;
	}

	// Escape相当の取消しではrequestを作らない。
	if( state.mode == DialogMode::CANCEL) {
		state.handled = true ;
		SendMessageW( dialog, WM_COMMAND, IDCANCEL, 0) ;
		return ;
	}

	const auto descriptor =
		std::find_if( descriptors.begin(), descriptors.end(), []( const auto &entry) {
			return entry.id == PROLIFIC_OFFICIAL_PROVIDER_ID ;
		}) ;			   // 選択する正本名。
	int selected = -1 ;	// 対象行が見つからなければ開始しない。
	// 専用能力行だけからstable IDに対応するProlific表示名を探す。
	for( int row = 0; row < supportedRows; ++row) {
		std::array<wchar_t, 256> title{} ;	// 固定上限内のListView表示名。
		ListView_GetItemText( list, row, 0, title.data(), static_cast<int>( title.size())) ;
		// 正本のProvider表示名が一致した行だけを操作する。
		if( descriptor != descriptors.end() && descriptor->displayName == title.data()) {
			selected = row ;
		}
	}

	DRIVERCRATE_EXPECT( context, selected >= 0) ;
	// 未検出を任意の先頭Providerへ補完しない。
	if( selected < 0) {
		state.failed = true ;
		SendMessageW( dialog, WM_COMMAND, IDCANCEL, 0) ;
		return ;
	}

	SetFocus( list) ;
	ListView_SetItemState( list, selected, LVIS_SELECTED | LVIS_FOCUSED,
						  LVIS_SELECTED | LVIS_FOCUSED) ;
	SendMessageW( list, WM_KEYDOWN, VK_SPACE, 0) ;
	SendMessageW( list, WM_KEYUP, VK_SPACE, 0) ;
	DRIVERCRATE_EXPECT( context, ListView_GetItemState( list, selected, LVIS_STATEIMAGEMASK) ==
									INDEXTOSTATEIMAGEMASK( 2)) ;
	DRIVERCRATE_EXPECT( context, IsWindowEnabled( GetDlgItem( dialog, IDYES)) != FALSE) ;
	DRIVERCRATE_EXPECT( context,
					   windowText( GetDlgItem( dialog, IDC_METADATA_SELECTION_STATUS)).find( L"1") !=
						   std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, captureWindow( dialog, L"selection")) ;
	state.handled = true ;
	SendMessageW( dialog, WM_COMMAND, IDYES, 0) ;
}

/** @brief 原dialogの子孫から一意のcontrol IDだけを検索する短命状態です。 */
struct DialogControlLookup {
	/// 検索する元dialogのcontrol IDです。
	int	 identity{} ;
	/// 元dialogの子孫として観測した非所有handleです。
	HWND found{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief EnumChildWindows境界内で元control IDを照合します。
 * @param[in] child 原所有dialogの子孫controlです。
 * @param[in] parameter 同期列挙中だけ生存する検索状態への非所有pointerです。
 * @return 一致を観測した場合FALSE、未一致なら列挙継続のTRUEです。
 * @note Win32 callbackのLPARAM境界でだけpointerを復元し、例外を漏らしません。
 */
//------------------------------------------------------------------------------
BOOL CALLBACK findDialogControlCallback( const HWND child, const LPARAM parameter) noexcept
{
	// Win32同期callbackが借用する同scopeの検索状態です。
	auto &lookup = *reinterpret_cast<DialogControlLookup *>( parameter) ;
	// 一致した元controlだけで列挙を止め、名称や本文から権限を推測しません。
	if( GetDlgCtrlID( child) == lookup.identity) {
		lookup.found = child ;
		return FALSE ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief TaskDialog内部paneを含む元dialogの子孫controlを取得します。
 * @param[in] dialog 同試験所有popupです。Desktopや他windowは列挙しません。
 * @param[in] identity 元dialog定義のcontrol IDです。
 * @return 元dialogの子孫で一致した非所有handle。未存在ならnullptrです。
 */
//------------------------------------------------------------------------------
HWND findDialogControl( const HWND dialog, const int identity) noexcept
{
	// 同期Win32列挙中だけ生存する検索状態です。
	DialogControlLookup lookup{identity, nullptr} ;
	EnumChildWindows( dialog, &findDialogControlCallback, reinterpret_cast<LPARAM>( &lookup)) ;
	return lookup.found ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同期dialogのmessage loopから、本試験所有Windowだけを操作する。
 * @param[in] window Timerの未使用Window。
 * @param[in] message 未使用のtimer message。
 * @param[in] timer 未使用のtimer ID。
 * @param[in] ticks 未使用のsystem tick。
 */
//------------------------------------------------------------------------------
void CALLBACK dialogTimer( HWND window, UINT message, UINT_PTR timer, DWORD ticks) noexcept
{
	CaptureTimerObservation timerObservation ;	// 本callbackの実depthを例外経路でも戻します。
	// 撮影中だけ再入callbackを遮断し、多段同意のhandled済み状態はguardに使いません。
	if( captureTelemetry.depth != 0U) {
		// 人工と自然発生の遮断を別々の分母へ保持します。
		if( artificialCaptureTimer) {
			++captureTelemetry.artificialBlocks ;
		} else {
			++captureTelemetry.naturalBlocks ;
		}

		return ;
	}

	static_cast<void>( window) ;
	static_cast<void>( message) ;
	static_cast<void>( timer) ;
	static_cast<void>( ticks) ;
	// RAII scope外の遅延通知では借用状態を参照しない。
	if( activeDialog == nullptr) {
		return ;
	}

	auto	  &state = *activeDialog ;						// 単一UI threadの現在scope。
	const HWND popup = GetLastActivePopup( state.owner) ;	// この試験の所有dialogだけを探す。
	// 原取得dialogの識別失敗を有限なcontrol IDだけで診断し、本文は出力しません。
	if( isPreparationDialogMode( state.mode) && popup != nullptr && popup != state.owner &&
	   IsWindowVisible( popup) && state.popupObservations++ == 0U) {
		std::cout << "FORMAT_DIALOG owner=" << (GetWindow( popup, GW_OWNER) == state.owner)
				  << " ids=" ;
		// 当該popupの有限childだけを読み、他windowや実端末情報を出力しません。
		for( HWND child = GetWindow( popup, GW_CHILD); child != nullptr;
			child	   = GetWindow( child, GW_HWNDNEXT)) {
			std::cout << GetDlgCtrlID( child) << ',' ;
		}

		std::cout << '\n' ;
	}

	// Popup生成前のtickでは何も操作しない。
	if( popup == nullptr || popup == state.owner || GetWindow( popup, GW_OWNER) != state.owner ||
	   IsWindowVisible( popup) == FALSE) {
		return ;
	}

	try {
		// 五秒を超える未処理dialogを残さず、試験失敗として閉じる。
		if( ++state.ticks > 250U) {
			state.failed = true ;
			SendMessageW( popup, WM_COMMAND, IDCANCEL, 0) ;
			return ;
		}

		// 取得同意は元本物dialogの標準controlとTaskDialogだけを操作します。
		if( isPreparationDialogMode( state.mode)) {
			// 同意画面の入れ子や別scanを作らず、確認中の三つの再入要求を拒否します。
			if( state.searchWindow != nullptr && !state.searchReentryChecked) {
				state.searchReentryChecked = true ;
				const auto operation	   = Access::controller( *state.searchWindow)
										   .activeOperationId() ;	// 再入前の元操作です。
				Access::beginSearchCommand( *state.searchWindow) ;
				Access::reviewIndexPlan( *state.searchWindow) ;
				// 元postを同scopeの生存HWNDへだけ再送します。
				if( state.searchReplay) {
					DispatchMessageW( &*state.searchReplay) ;
				}

				DRIVERCRATE_EXPECT( *state.context,
								   Access::controller( *state.searchWindow).activeOperationId() ==
										   operation &&
									   !Access::takeSearchContinuation( *state.searchWindow)) ;
			}

			const auto body = GetDlgItem( popup, IDC_PREPARATION_EULA_TEXT) ;	// 原read-only全文です。
			// 全文・原出典・公開revisionを読んでから、この対象へだけYES/NOを送ります。
			if( body) {
				++state.eulaDialogs ;
				// Search中の想定外EULAは同意せず、原失敗を保持します。
				if( state.rejectEula) {
					state.failed = true ;
					SendDlgItemMessageW( popup, IDCANCEL, BM_CLICK, 0, 0) ;
					return ;
				}

				// 元集合の表示順に対応するexact subjectとrevisionです。任意文字列へ緩和しません。
				const auto subject	= state.secondTermsSubject && state.eulaDialogs == 2U
										  ? L"fixture-second-source (https://vendor.example/)"
										  : L"fixture-source (https://vendor.example/)" ;
				const auto revision = state.secondTermsRevision && state.eulaDialogs == 2U
										  ? L"Original 2.0"
										  : L"Original 1.0" ;	// 元公開revisionの固定期待です。
				// HTMLの固定期待は独立した原titleと全段落です。読んだ本文を期待値へ代入しません。
				const auto expectedText =
					state.htmlTerms
						? L"Original 1.0\r\n\r\nFictional complete driver license.\r\n\r\nOriginal terms line two.\r\n"
						: L"Fictional complete driver license.\nOriginal terms line two.\n" ;
				state.eulaValid &=
					windowText( body) == expectedText &&
					windowText( GetDlgItem( popup, IDC_PREPARATION_EULA_REVISION)).find( subject) !=
						std::wstring::npos &&
					windowText( GetDlgItem( popup, IDC_PREPARATION_EULA_REVISION)).find( revision) !=
						std::wstring::npos ;
				state.handled = true ;
				SendDlgItemMessageW(
					popup, state.mode == DialogMode::INDEX_PREPARATION_CANCEL ? IDCANCEL : IDYES,
					BM_CLICK, 0, 0) ;
				return ;
			}

			// 通常導線にはEULA以外の汎用取得dialogを許可せず、予期しない表示を拒否します。
			if( state.twoStep) {
				state.failed = true ;
				++state.preparationTaskDialogs ;
				SendMessageW( popup, TDM_CLICK_BUTTON, IDCANCEL, 0) ;
				SendMessageW( popup, WM_COMMAND, GetDlgItem( popup, IDOK) ? IDOK : IDCANCEL, 0) ;
				return ;
			}

			// TaskDialogのDirectUI paneはbutton HWNDを公開しないため、元表示順の
			// documented TDM commandで操作します。未知popupではcommandが効かず失敗を保持します。
			if( GetDlgItem( popup, IDOK) == nullptr && GetDlgItem( popup, IDYES) == nullptr &&
			   GetWindow( popup, GW_CHILD) != nullptr) {
				state.handled = true ;
				// 元最初の一覧と、その後の各target取得判断を独立に数えます。
				const bool overview = state.preparationTaskDialogs++ == 0U ;
				// 一覧閲覧を取得判断として数えません。
				if( !overview) {
					++state.acquisitionDecisionDialogs ;
				}

				SendMessageW( popup, TDM_CLICK_BUTTON,
							 overview ? (state.mode == DialogMode::INDEX_PREPARATION_OVERVIEW_CANCEL
											 ? IDCANCEL
											 : IDOK)
							 : state.mode == DialogMode::INDEX_PREPARATION_TARGET_CANCEL ? IDCANCEL
							 : state.mode == DialogMode::INDEX_PREPARATION_TARGET_NO	 ? IDNO
																						 : IDYES,
							 0) ;
				return ;
			}

			// 一覧TaskDialogは原対象集合を表示した後だけ閉じます。
			if( findDialogControl( popup, IDOK) && findDialogControl( popup, IDCANCEL)) {
				state.handled = true ;
				SendMessageW( popup, TDM_CLICK_BUTTON,
							 state.mode == DialogMode::INDEX_PREPARATION_OVERVIEW_CANCEL ? IDCANCEL
																						 : IDOK,
							 0) ;
				return ;
			}

			// 対象別TaskDialogは任意network同意を既定未選択のまま保持します。
			if( findDialogControl( popup, IDYES) && findDialogControl( popup, IDNO) &&
			   findDialogControl( popup, IDCANCEL)) {
				state.handled = true ;
				++state.acquisitionDecisionDialogs ;
				SendMessageW( popup, TDM_CLICK_BUTTON,
							 state.mode == DialogMode::INDEX_PREPARATION_TARGET_CANCEL ? IDCANCEL
							 : state.mode == DialogMode::INDEX_PREPARATION_TARGET_NO   ? IDNO
																					   : IDYES,
							 0) ;
				return ;
			}

			// 具体的条件と件数のMessageBoxは既定NOを確認して明示YESへ進みます。
			if( GetDlgItem( popup, IDYES) && GetDlgItem( popup, IDNO)) {
				DRIVERCRATE_EXPECT( *state.context,
								   LOWORD( SendMessageW( popup, DM_GETDEFID, 0, 0)) == IDNO) ;
				state.handled = true ;
				++state.finalConfirmationDialogs ;
				SendDlgItemMessageW(
					popup, state.mode == DialogMode::INDEX_PREPARATION_FINAL_NO ? IDNO : IDYES,
					BM_CLICK, 0, 0) ;
				return ;
			}
		}

		// 本fixture所有の実導入確認だけを有限全文で読み、既定拒否を確認します。
		if( (state.mode == DialogMode::INDEX_INSTALL_ACCEPT ||
			state.mode == DialogMode::INDEX_INSTALL_CANCEL) &&
		   GetDlgItem( popup, IDYES) != nullptr && GetDlgItem( popup, IDNO) != nullptr) {
			// 同標準dialogの有限child集合だけから本文を読みます。
			for( HWND child = GetWindow( popup, GW_CHILD); child != nullptr;
				child	   = GetWindow( child, GW_HWNDNEXT)) {
				state.details += windowText( child) + L"\n" ;
			}

			DRIVERCRATE_EXPECT( *state.context,
							   LOWORD( SendMessageW( popup, DM_GETDEFID, 0, 0)) == IDNO) ;
			state.handled = true ;
			SendDlgItemMessageW( popup,
								state.mode == DialogMode::INDEX_INSTALL_ACCEPT ? IDYES : IDNO,
								BM_CLICK, 0, 0) ;
			return ;
		}

		// 実結果dialogの本文を保持し、表示後だけ同fixtureの案内を閉じます。
		if( (state.mode == DialogMode::INDEX_INSTALL_RESULT ||
			state.mode == DialogMode::INDEX_INSTALL_SELECTION_REQUIRED) &&
		   (GetDlgItem( popup, IDOK) != nullptr || GetDlgItem( popup, IDCANCEL) != nullptr)) {
			// 元結果の標準controlだけを読み、別Windowやdesktopをcaptureしません。
			for( HWND child = GetWindow( popup, GW_CHILD); child != nullptr;
				child	   = GetWindow( child, GW_HWNDNEXT)) {
				state.details += windowText( child) + L"\n" ;
			}

			state.handled = true ;
			SendDlgItemMessageW( popup, GetDlgItem( popup, IDOK) != nullptr ? IDOK : IDCANCEL,
								BM_CLICK, 0, 0) ;
			return ;
		}

		// 最初の条件dialogだけを選択操作する。
		if( GetDlgItem( popup, IDC_METADATA_PROVIDER_LIST) != nullptr && !state.handled) {
			exerciseSelectionDialog( popup, state) ;
			return ;
		}

		const HWND candidates =
			// Device表だけを別契約で扱います。
			GetDlgItem( popup, IDC_DEVICE_DETAIL_CANDIDATES) ;
		const HWND details = GetDlgItem( popup, IDC_METADATA_DETAIL_TEXT) ;	// 読取り専用詳細control。
		// 詳細はcopyとcloseだけを行い、取得条件へ戻さない。
		if( (details != nullptr || candidates != nullptr) && state.mode == DialogMode::DETAILS) {
			// 原規約の任意閲覧には同意buttonを置かず、偽装commandでも終了・承認しません。
			if( state.inlineTermsView) {
				DRIVERCRATE_EXPECT( *state.context, GetDlgItem( popup, IDYES) == nullptr &&
													   GetDlgItem( popup, IDNO) == nullptr &&
													   GetDlgItem( popup, IDOK) != nullptr) ;
				SendMessageW( popup, WM_COMMAND, IDYES, 0) ;
				DRIVERCRATE_EXPECT( *state.context, IsWindow( popup) != FALSE) ;
			}

			// 狭幅fixtureだけを元fontのDLUへresizeし、実monitor移動とは数えません。
			if( candidates != nullptr && state.detailNarrow) {
				RECT dimensions{0, 0, 500, 220} ;	// 製品の有限最小client DLUです。
				RECT outer{} ;						// 同windowの非client差です。
				RECT inner{} ;						// 元clientです。
				DRIVERCRATE_EXPECT( *state.context, MapDialogRect( popup, &dimensions) &&
													   GetWindowRect( popup, &outer) &&
													   GetClientRect( popup, &inner)) ;
				SetWindowPos( popup, nullptr, 0, 0,
							 dimensions.right + outer.right - outer.left - inner.right,
							 dimensions.bottom + outer.bottom - outer.top - inner.bottom,
							 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE) ;
			}

			// Device詳細の主操作が可視client領域に収まることを実controlで確認する。
			if( candidates != nullptr) {
				RECT client{} ;	// Modalの実client寸法。
				DRIVERCRATE_EXPECT( *state.context, GetClientRect( popup, &client) != FALSE) ;
				// 選択欄・本文・選択button・閉じるbuttonを一回ずつ確認する。
				for( const int id : {IDC_DEVICE_DETAIL_CANDIDATES, IDYES, IDOK}) {
					const HWND control = GetDlgItem( popup, id) ;	// 同dialogが所有する標準control。
					RECT	   bounds{} ;							// Screen座標から同dialogのclient座標へ変換する領域。
					const bool read = control != nullptr &&
									  // 元取得結果。
									  GetWindowRect( control, &bounds) != FALSE ;
					// RECTを二つのPOINTとして渡すWindowsの座標変換境界。
					MapWindowPoints( HWND_DESKTOP, popup, reinterpret_cast<POINT *>( &bounds), 2U) ;
					DRIVERCRATE_EXPECT(
						*state.context,
						read && IsWindowVisible( control) != FALSE && bounds.left >= client.left &&
							bounds.top >= client.top && bounds.right <= client.right &&
							bounds.bottom <= client.bottom && bounds.bottom > bounds.top) ;
				}
			}

			// 初期行なしでも表を閉じず、明示buttonは無効にします。
			if( candidates != nullptr && state.detailExpectNoInitial) {
				DRIVERCRATE_EXPECT( *state.context, ListView_GetSelectedCount( candidates) == 0U &&
													   !IsWindowEnabled( GetDlgItem( popup, IDYES))) ;
				SendMessageW( popup, WM_COMMAND, IDYES, 0) ;
				DRIVERCRATE_EXPECT( *state.context, IsWindow( popup)) ;
			}

			// Device詳細だけを実ListViewで操作し、旧comboの成功を継承しません。
			if( candidates != nullptr && state.detailEntry >= 0) {
				wchar_t className[64]{} ;	// 当該controlの実classです。
				GetClassNameW( candidates, className, 64) ;
				DRIVERCRATE_EXPECT( *state.context,
								   std::wstring_view{className} == L"SysListView32") ;
				DRIVERCRATE_EXPECT(
					*state.context,
					(GetWindowLongPtrW( candidates, GWL_STYLE) & LVS_TYPEMASK) == LVS_REPORT &&
						(GetWindowLongPtrW( candidates, GWL_STYLE) & LVS_SINGLESEL) != 0) ;
				const int count = ListView_GetItemCount( candidates) ;	// 実項目数です。
				DRIVERCRATE_EXPECT( *state.context,
								   count > state.detailEntry &&
									   (state.detailEntryCount == 0U ||
										static_cast<unsigned>( count) == state.detailEntryCount)) ;
				// 元choiceは初期highlightだけで、適用commandを生成しません。
				if( state.detailInitialEntry >= 0) {
					DRIVERCRATE_EXPECT( *state.context,
									   ListView_GetNextItem( candidates, -1, LVNI_SELECTED) ==
										   state.detailInitialEntry) ;
				}

				ListView_SetItemState( candidates, -1, 0, LVIS_SELECTED | LVIS_FOCUSED) ;
				ListView_SetItemState( candidates, state.detailEntry, LVIS_SELECTED | LVIS_FOCUSED,
									  LVIS_SELECTED | LVIS_FOCUSED) ;
				ListView_EnsureVisible( candidates, state.detailEntry, FALSE) ;
				DRIVERCRATE_EXPECT( *state.context,
								   GetDlgItem( popup, IDC_METADATA_DETAIL_TEXT) == nullptr &&
									   GetDlgItem( popup, IDC_DEVICE_DETAIL_NOTICE) == nullptr &&
									   GetDlgItem( popup, IDC_DEVICE_DETAIL_LABEL) == nullptr) ;
				DRIVERCRATE_EXPECT( *state.context, ListView_GetToolTips( candidates) == nullptr &&
													   deviceTipWindow( popup) != nullptr) ;
				const auto selectedTip =
					// 実選択の短い状態文です。
					hoverDeviceCell( popup, state.detailEntry, 4) ;
				DRIVERCRATE_EXPECT( *state.context,
								   !selectedTip.empty() && selectedTip.size() <= 320U) ;
				// 新しい表示groupも実row/ordinalと元一件選択の境界へ通します。
				if( state.detailDisplayProbe) {
					// 表示行のordinalと候補連番を独立に読みます。
					for( int position = 0; position < count; ++position) {
						LVITEMW identity{} ;	// 実rowの不透明な表示ordinalです。
						identity.mask  = LVIF_PARAM ;
						identity.iItem = position ;
						DRIVERCRATE_EXPECT( *state.context,
										   ListView_GetItem( candidates, &identity) &&
											   identity.lParam == position + 1) ;
					}

					wchar_t name[256]{} ;	// 元候補の番号と短い識別だけを読みます。
					ListView_GetItemText( candidates, 1, 0, name, 256) ;
					DRIVERCRATE_EXPECT( *state.context,
									   std::wstring_view( name).starts_with( L"候補 1:")) ;
					const auto nameTip =
						// 選択外でも同rowの説明です。
						hoverDeviceCell( popup, 1, 0) ;
					DRIVERCRATE_EXPECT( *state.context,
									   (std::wstring_view( name).find( L"別の配布情報 1") !=
										std::wstring::npos) == state.detailDistinctInformation &&
										   (nameTip.find( L"同一内容と確認できない") !=
											std::wstring::npos) == state.detailDistinctInformation) ;
					const auto currentTip = hoverDeviceCell( popup, 0, 1) ;	// 非選択の現在行です。
					DRIVERCRATE_EXPECT( *state.context,
									   currentTip.find( L"現在のドライバー") != std::wstring::npos &&
										   ListView_GetNextItem( candidates, -1, LVNI_SELECTED) ==
											   state.detailEntry) ;
				}

				// 五列と元entry ordinalを読み、文字列から候補identityを作りません。
				if( state.historyTableProbe) {
					const HWND header = ListView_GetHeader( candidates) ;	// 当該標準headerです。
					DRIVERCRATE_EXPECT( *state.context, Header_GetItemCount( header) == 5) ;
					const std::array<std::wstring_view, 5> headings{
						L"候補", L"バージョン", L"日付", L"取得元", L"区分"} ;	// 独立固定期待です。
					// 全見出しを実controlから読みます。
					for( int column = 0; column < 5; ++column) {
						wchar_t text[64]{} ;	// 有限の見出しです。
						HDITEMW item{} ;		// APIが同期書込みします。
						item.mask		= HDI_TEXT ;
						item.pszText	= text ;
						item.cchTextMax = 64 ;
						DRIVERCRATE_EXPECT( *state.context,
										   Header_GetItem( header, column, &item) &&
											   std::wstring_view{text} ==
												   headings[static_cast<std::size_t>( column)]) ;
					}

					// 現在/新版/旧版/reportを欠損欄も含めて全列確認します。
					for( int row = 0; row < count; ++row) {
						LVITEMW item{} ;	// ordinalの実保持値です。
						item.mask  = LVIF_PARAM ;
						item.iItem = row ;
						DRIVERCRATE_EXPECT( *state.context, ListView_GetItem( candidates, &item) &&
															   item.lParam == row + 1) ;
						// 全entryの全欄に表示値または未知記号があることを確認します。
						for( int column = 0; column < 5; ++column) {
							wchar_t text[512]{} ;	// 表の通常幅と独立した有限copyです。
							LVITEMW cell{} ;		// 実文字列copyの同期書込み領域です。
							cell.iSubItem	= column ;
							cell.pszText	= text ;
							cell.cchTextMax = 512 ;
							DRIVERCRATE_EXPECT( *state.context,
											   SendMessageW( candidates, LVM_GETITEMTEXTW,
															static_cast<WPARAM>( row),
															reinterpret_cast<LPARAM>( &cell)) > 0) ;
							// 元人工参照の版を列独自の省略や別候補から補完しません。
							if( column == 1 && row < 3) {
								constexpr std::array<std::wstring_view, 3> versions{
									L"2.0.0.0", L"3.0.0.0", L"1.0.0.0"} ;	// 原fixture値です。
								DRIVERCRATE_EXPECT( *state.context,
												   std::wstring_view{text} ==
													   versions[static_cast<std::size_t>( row)]) ;
							}
						}
					}

					const int selectedRow = ListView_GetNextItem(
						candidates, -1, LVNI_SELECTED) ;	// Hover前の実選択です。
					// 非選択の新しい参照を全columnでhoverし、選択した古い参照と混同しません。
					for( int column = 0; column < 5; ++column) {
						const auto tip = hoverDeviceCell( popup, 1, column) ;	// 別rowの実文字です。
						DRIVERCRATE_EXPECT( *state.context,
										   !tip.empty() && tip.size() <= 320U &&
											   tip.find( L"現在より新しい") != std::wstring::npos &&
											   tip.find( L"現在より古い") == std::wstring::npos) ;
						DRIVERCRATE_EXPECT( *state.context,
										   ListView_GetNextItem( candidates, -1, LVNI_SELECTED) ==
											   selectedRow) ;
					}

					DRIVERCRATE_EXPECT(
						*state.context,
						hoverDeviceCell( popup, 0, 4).find( L"導入候補ではありません") !=
							std::wstring::npos) ;
					DRIVERCRATE_EXPECT( *state.context,
									   emptyDeviceTipAfterHover( popup, count - 1, 1)) ;
					// 別cell/余白/header/退場/scroll/resizeでは以前のpopupを残しません。
					for( const UINT inputMessage :
						{UINT{WM_MOUSELEAVE}, UINT{WM_MOUSEWHEEL}, UINT{WM_HSCROLL}, UINT{WM_SIZE},
						 UINT{WM_KEYDOWN}}) {
						DRIVERCRATE_EXPECT( *state.context, !hoverDeviceCell( popup, 1, 1).empty()) ;
						SendMessageW( candidates, inputMessage, 0, 0) ;
						DRIVERCRATE_EXPECT( *state.context, waitDeviceTipHidden( popup)) ;
					}

					TTTOOLINFOW timeoutTool{	// 可視中の局所timer IDも実toolから読みます。
											sizeof( timeoutTool)} ;
					DRIVERCRATE_EXPECT( *state.context,
									   !hoverDeviceCell( popup, 1, 1).empty() &&
										   SendMessageW( deviceTipWindow( popup), TTM_ENUMTOOLSW, 0,
														reinterpret_cast<LPARAM>( &timeoutTool))) ;
					SendMessageW( popup, WM_TIMER, timeoutTool.uId, 0) ;
					DRIVERCRATE_EXPECT( *state.context, waitDeviceTipHidden( popup)) ;
					RECT versionCell{}, heading{} ;	// 余白とheaderの独立実座標です。
					ListView_GetSubItemRect( candidates, 1, 1, LVIR_BOUNDS, &versionCell) ;
					Header_GetItemRect( header, 1, &heading) ;
					MapWindowPoints( header, candidates, reinterpret_cast<POINT *>( &heading), 2U) ;
					// 実文字の右余白・header・負座標をそれぞれ拒否します。
					for( const POINT point :
						{POINT{heading.right - 2, (versionCell.top + versionCell.bottom) / 2},
						 POINT{heading.left + 9, 1}, POINT{-1, -1}}) {
						SendMessageW( candidates, WM_MOUSEMOVE, 0, MAKELPARAM( point.x, point.y)) ;
						SendMessageW( candidates, WM_MOUSEHOVER, 0, MAKELPARAM( point.x, point.y)) ;
						DRIVERCRATE_EXPECT( *state.context, waitDeviceTipHidden( popup)) ;
					}

					DRIVERCRATE_EXPECT( *state.context,
									   hoverDeviceCell( popup, state.detailEntry, 4) == selectedTip) ;
					std::cout << "HISTORY_SELECTION row="
							  << ListView_GetNextItem( candidates, -1, LVNI_SELECTED)
							  << " count=" << ListView_GetSelectedCount( candidates)
							  << " enabled=" << IsWindowEnabled( GetDlgItem( popup, IDYES))
							  << " chars=" << deviceTipText( popup).size() << "\n" ;
					const auto originalBody = deviceTipText( popup) ;	// 実選択の元本文です。
					NMHDR	   notice{candidates, IDC_DEVICE_DETAIL_CANDIDATES,
								  LVN_ITEMCHANGED} ;	// 同期借用通知です。
					// 通知の偽rowやdoubleclick/Enterだけでは適用しません。
					for( const UINT code :
						{static_cast<UINT>( NM_DBLCLK), static_cast<UINT>( NM_RETURN)}) {
						NMLISTVIEW spoof{} ;	// iItemは元範囲外でも実control選択を優先します。
						spoof.hdr	= {candidates, IDC_DEVICE_DETAIL_CANDIDATES, code} ;
						spoof.iItem = 99999 ;
						SendMessageW( popup, WM_NOTIFY, IDC_DEVICE_DETAIL_CANDIDATES,
									 reinterpret_cast<LPARAM>( &spoof)) ;
						DRIVERCRATE_EXPECT( *state.context,
										   IsWindow( popup) &&
											   hoverDeviceCell( popup, state.detailEntry, 4) ==
												   originalBody) ;
					}

					// Null/別HWND/id/wParamでは以前の表示・許可を残しません。
					for( unsigned variant = 0; variant < 4U; ++variant) {
						NMHDR foreign{variant == 1U ? GetDlgItem( popup, IDOK) : candidates,
									  static_cast<UINT_PTR>( variant == 2U
																? IDC_DEVICE_DETAIL_LABEL
																: IDC_DEVICE_DETAIL_CANDIDATES),
									  LVN_ITEMCHANGED} ;	// 所有fixture内だけの負例です。
						SendMessageW( popup, WM_NOTIFY,
									 variant == 3U ? IDC_DEVICE_DETAIL_LABEL
												   : IDC_DEVICE_DETAIL_CANDIDATES,
									 variant == 0U ? 0 : reinterpret_cast<LPARAM>( &foreign)) ;
						DRIVERCRATE_EXPECT( *state.context,
										   !IsWindowEnabled( GetDlgItem( popup, IDYES))) ;
						DRIVERCRATE_EXPECT( *state.context, waitDeviceTipHidden( popup)) ;
						SendMessageW( popup, WM_COMMAND, IDYES, 0) ;
						DRIVERCRATE_EXPECT( *state.context, IsWindow( popup)) ;
						SendMessageW( popup, WM_NOTIFY, IDC_DEVICE_DETAIL_CANDIDATES,
									 reinterpret_cast<LPARAM>( &notice)) ;
					}

					ListView_SetItemState( candidates, -1, 0, LVIS_SELECTED) ;
					SendMessageW( popup, WM_COMMAND, IDYES, 0) ;
					DRIVERCRATE_EXPECT( *state.context,
									   IsWindow( popup) &&
										   ListView_GetSelectedCount( candidates) == 0U &&
										   !IsWindowEnabled( GetDlgItem( popup, IDYES))) ;
					DRIVERCRATE_EXPECT( *state.context, waitDeviceTipHidden( popup)) ;
					ListView_SetItemState( candidates, state.detailEntry,
										  LVIS_SELECTED | LVIS_FOCUSED,
										  LVIS_SELECTED | LVIS_FOCUSED) ;
					// 範囲外/0/負値/別rowのordinalを実controlに入れ、最終button再読を確認します。
					for( const LPARAM invalid :
						{LPARAM{0}, LPARAM{-1}, static_cast<LPARAM>( count + 1),
						 static_cast<LPARAM>( state.detailEntry == 0 ? 2 : 1)}) {
						LVITEMW item{} ;	// Item textは変えません。
						item.mask	= LVIF_PARAM ;
						item.iItem	= state.detailEntry ;
						item.lParam = invalid ;
						ListView_SetItem( candidates, &item) ;
						DRIVERCRATE_EXPECT( *state.context,
										   emptyDeviceTipAfterHover( popup, state.detailEntry, 4)) ;
						SendMessageW( popup, WM_COMMAND, IDYES, 0) ;
						DRIVERCRATE_EXPECT( *state.context,
										   IsWindow( popup) &&
											   !IsWindowEnabled( GetDlgItem( popup, IDYES))) ;
						item.lParam = state.detailEntry + 1 ;
						ListView_SetItem( candidates, &item) ;
						SendMessageW( popup, WM_NOTIFY, IDC_DEVICE_DETAIL_CANDIDATES,
									 reinterpret_cast<LPARAM>( &notice)) ;
					}

					// 標準keyboardの行移動は下部閲覧だけを変更します。
					if( state.detailEntry > 0) {
						SetFocus( candidates) ;
						SendMessageW( candidates, WM_KEYDOWN, VK_UP, 0) ;
						DRIVERCRATE_EXPECT( *state.context,
										   ListView_GetNextItem( candidates, -1, LVNI_SELECTED) ==
											   state.detailEntry - 1) ;
						SendMessageW( candidates, WM_KEYDOWN, VK_DOWN, 0) ;
						DRIVERCRATE_EXPECT( *state.context,
										   ListView_GetNextItem( candidates, -1, LVNI_SELECTED) ==
												   state.detailEntry &&
											   hoverDeviceCell( popup, state.detailEntry, 4) ==
												   originalBody) ;
					}

					DRIVERCRATE_EXPECT(
						*state.context,
						GetNextDlgTabItem( popup, candidates, FALSE) ==
							GetDlgItem( popup, state.detailSelectable ? IDYES : IDOK)) ;
				}

				DRIVERCRATE_EXPECT( *state.context, (IsWindowEnabled( GetDlgItem( popup, IDYES)) !=
													FALSE) == state.detailSelectable) ;
			}

			// 初回paintがmessage loopを一巡するまで画像/適用を保留し、同じ所有snapshotを維持します。
			if( candidates != nullptr && (state.historyTableProbe || historyImagesOnly) &&
			   state.captureDetails && !state.historyCaptureReady) {
				state.historyCaptureReady = true ;
				RedrawWindow( popup, nullptr, nullptr,
							 RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW | RDW_FRAME) ;
				PostMessageW( popup, WM_NULL, 0, 0) ;
				return ;
			}

			state.details =
				candidates != nullptr
					? hoverDeviceCell( popup, ListView_GetNextItem( candidates, -1, LVNI_SELECTED), 4)
					: windowText( details) ;
			// 他の詳細dialogの既readonly EDITは変更しません。
			if( details != nullptr) {
				DRIVERCRATE_EXPECT( *state.context,
								   (GetWindowLongPtrW( details, GWL_STYLE) & ES_READONLY) != 0) ;
				DRIVERCRATE_EXPECT( *state.context, IsWindowVisible( details) != FALSE &&
													   IsWindowEnabled( details) != FALSE) ;
				// Read-only editの初期focusによる全選択を外し、本文の通常描画を確認する。
				SendMessageW( details, EM_SETSEL, 0, 0) ;
				// 元fresh/cacheだけは実生成/copy/可視座標を同じdialogで記録します。
				if( state.refreshWindow != nullptr) {
					// 新限定入口だけは元六fieldの具体値期待を維持して独立描画を観測します。
					if( independentRenderEvidence) {
						state.refreshStrict = true ;
					}

					inspectRefreshDetail( details, state) ;
					// 元probeの画像なし条件を通常入口では保持し、新入口だけ対撮影します。
					if( independentRenderEvidence) {
						captureIndependentRefreshEvidence( popup, state.refreshStage,
														  *state.context) ;
					}
				}
			}

			// 自作dialogだけのgeometryをPNGと同じscopeへ記録します。
			if( candidates != nullptr && state.captureDetails && state.historyTableProbe) {
				DWORD pid{} ;	// 当該HWNDの実所有processです。
				GetWindowThreadProcessId( popup, &pid) ;
				DRIVERCRATE_EXPECT( *state.context, pid == GetCurrentProcessId()) ;
				std::ofstream record(
					privateCaptureRoot /
					(state.captureName + L".geometry.txt")) ;	// 別保管の有限証跡です。
				record << "hwnd=" << reinterpret_cast<std::uintptr_t>( popup) << " pid=" << pid
					   << " dpi=" << GetDpiForWindow( popup) << " monitorDpiMoveTested=0\n" ;
				RECT previous{} ;	// Tableと本文と注意の非重複を照合します。
				// 本dialogの矩形だけを保持し、desktop画面を取得しません。
				for( const int id : {0, IDC_DEVICE_DETAIL_CANDIDATES, IDYES, IDOK}) {
					RECT bounds{} ;	// 実windowのscreen矩形です。
					DRIVERCRATE_EXPECT(
						*state.context,
						GetWindowRect( id == 0 ? popup : GetDlgItem( popup, id), &bounds)) ;
					record << "id=" << id << " rect=" << bounds.left << "," << bounds.top << ","
						   << bounds.right << "," << bounds.bottom << "\n" ;
					// 縦に並ぶ三領域の交差を許しません。
					if( id == IDYES) {
						DRIVERCRATE_EXPECT( *state.context, bounds.top >= previous.bottom) ;
					}

					previous = bounds ;
				}

				record.close() ;
				DRIVERCRATE_EXPECT( *state.context, record.good()) ;
				std::wcout << L"HISTORY_CAPTURE "
						   << (privateCaptureRoot / state.captureName).wstring() << L"\n" ;
			}

			// 事前に固定した画像数だけ保存し、別構成の反復画像は増やしません。
			if( state.captureDetails) {
				// README専用画像は新版の選択可能な通常dialogだけを保存します。
				if( candidates != nullptr && historyImagesOnly) {
					DRIVERCRATE_EXPECT( *state.context,
									   ListView_GetNextItem( candidates, -1, LVNI_SELECTED) == 1 &&
										   IsWindowEnabled( GetDlgItem( popup, IDYES)) != FALSE) ;
					SendMessageW( candidates, WM_MOUSELEAVE, 0, 0) ;
					DRIVERCRATE_EXPECT( *state.context, waitDeviceTipHidden( popup)) ;
					RedrawWindow( popup, nullptr, nullptr,
								 RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW | RDW_FRAME) ;
				}

				DRIVERCRATE_EXPECT( *state.context,
								   captureWindow( popup, state.captureName, historyImagesOnly)) ;
				// 追加画像は同dialog所有の実balloon一枚だけに限定します。
				if( candidates != nullptr && historyImagesOnly && !state.detailNarrow) {
					const auto currentText =
						hoverDeviceCell( popup, ListView_GetNextItem( candidates, -1, LVNI_SELECTED),
										4) ;					// Dialog再描画後の同じ文字を再hoverします。
					const HWND tip = deviceTipWindow( popup) ;	// ユーザーdesktopをcaptureしません。
					DRIVERCRATE_EXPECT( *state.context,
									   !currentText.empty() && tip != nullptr &&
										   IsWindowVisible( tip) &&
										   captureWindow( tip, state.captureName + L"-tooltip")) ;
				}
			}

			state.handled = true ;
			// 閲覧専用entryへの偽装commandでも選択や終了を許さない。
			if( candidates != nullptr && state.chooseDetailCandidate && !state.detailSelectable) {
				SendMessageW( popup, WM_COMMAND, IDYES, 0) ;
				DRIVERCRATE_EXPECT( *state.context, IsWindow( popup) != FALSE) ;
			}

			++captureTelemetry.closes ;
			captureTelemetry.closeDuringCapture += captureTelemetry.depth != 0U ? 1U : 0U ;
			std::cout << "CAPTURE_CLOSE seq=" << ++captureTelemetry.sequence
					  << " phase=begin depth=" << captureTelemetry.depth
					  << " alive=" << (IsWindow( popup) != FALSE)
					  << " bodyHash=" << captureBodyHash( popup) << '\n' ;
			// Enterは閲覧だけ、Alt+S/Spaceは明示buttonという標準dialogの区別です。
			if( candidates != nullptr &&
			   (state.detailEnterClose || state.detailApplyAccessKey || state.detailApplySpace)) {
				const HWND target = state.detailApplySpace ? GetDlgItem( popup, IDYES)
														   : candidates ;	// 明示focusです。
				SetFocus( target) ;
				std::cout << "HISTORY_KEY_INPUT space=" << state.detailApplySpace
						  << " alt=" << state.detailApplyAccessKey
						  << " enter=" << state.detailEnterClose
						  << " focus=" << (GetFocus() == target)
						  << " button=" << IsWindowEnabled( GetDlgItem( popup, IDYES)) << "\n" ;
				MSG key{} ;	// 自作dialogだけへのkeyboard入力です。
				key.hwnd	= target ;
				key.message = state.detailEnterClose ? WM_KEYDOWN : WM_SYSCHAR ;
				key.wParam	= state.detailEnterClose ? VK_RETURN : L's' ;
				// Spaceは標準buttonの押下/解放を通し、独自導入commandへ変換しません。
				if( state.detailApplySpace) {
					SendMessageW( target, WM_KEYDOWN, VK_SPACE, 0) ;
					SendMessageW( target, WM_KEYUP, VK_SPACE, 0) ;
				} else {
					DRIVERCRATE_EXPECT( *state.context, IsDialogMessageW( popup, &key)) ;
				}

				// EndDialogはcallback復帰後に終端するため、IsWindowで適用成否を判定しません。
				// Enterを閲覧だけに留めるcontrolでは、元modal結果を上書きしないpostで閉じます。
				if( state.detailEnterClose) {
					PostMessageW( popup, WM_COMMAND, IDOK, 0) ;
				}

				return ;
			}

			// 明示選択fixtureだけが実buttonを押し、他は閉じるだけでselectionを維持する。
			if( candidates != nullptr && state.chooseDetailCandidate && state.detailSelectable) {
				SendDlgItemMessageW( popup, IDYES, BM_CLICK, 0, 0) ;
			} else {
				SendMessageW( popup, WM_COMMAND, IDOK, 0) ;
			}

			std::cout << "CAPTURE_CLOSE seq=" << ++captureTelemetry.sequence
					  << " phase=end depth=" << captureTelemetry.depth
					  << " alive=" << (IsWindow( popup) != FALSE) << '\n' ;
			return ;
		}

		// Fake操作に限る終了待ち確認へ明示YESを送る。
		if( GetDlgItem( popup, IDYES) != nullptr && state.mode == DialogMode::CLOSE) {
			state.handled = true ;
			SendDlgItemMessageW( popup, IDYES, BM_CLICK, 0, 0) ;
			return ;
		}

		// 想定外errorも自動放置せず、失敗として記録してから試験を継続可能にする。
		if( GetDlgItem( popup, IDOK) != nullptr || GetDlgItem( popup, IDCANCEL) != nullptr) {
			++state.errors ;
			state.failed |= !state.allowError ;
			// WindowsのMB_OK実装が単一buttonへIDCANCELを割り当てる場合も案内を閉じる。
			SendDlgItemMessageW( popup, GetDlgItem( popup, IDOK) != nullptr ? IDOK : IDCANCEL,
								BM_CLICK, 0, 0) ;
		}
	} catch( ...) {
		state.failed = true ;
		SendMessageW( popup, WM_COMMAND, IDCANCEL, 0) ;
	}
}

/** @brief 同期dialog操作のtimerと借用pointerをscopeへ拘束する。 */
class DialogDriver final {
public:
	/**
     * @brief このUI threadの条件操作を開始する。
     * @param[in,out] state Timer終了まで生存する操作状態。
     */
	explicit DialogDriver( DialogState &state)
	{
		activeDialog = &state ;
		timer_		 = SetTimer( nullptr, 0U, 20U, dialogTimer) ;
		state.failed = timer_ == 0U ;
	}
	/**
	 * @brief Timer解除後に借用先を外し、遅延通知を無効化する。
	 */
	~DialogDriver()
	{
		// 生成できたtimerだけを終了する。
		if( timer_ != 0U) {
			KillTimer( nullptr, timer_) ;
		}

		activeDialog = nullptr ;
	}

private:
	/// 本scopeでだけ有効なthread timer。
	UINT_PTR timer_{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 人工のcapture中callbackと自然発生観測を別分母で検査します。
 * @param[in,out] context 旧五/六caseやexact60とは独立した集計先です。
 * @note 新しいbitmapや画像は作らず、実callbackのcapture限定guardを決定的に通します。
 */
//------------------------------------------------------------------------------
void runCaptureGuardRegression( TestContext &context)
{
	const auto before		 = context.assertionCount() ;		// 追加timer試験だけの開始分母です。
	const auto previousState = activeDialog ;					// 同UI threadの借用状態を復帰します。
	const auto previousDepth = captureTelemetry.depth ;			// 人工のin-flightを実capture数へ足しません。
	const bool previousArtificial = artificialCaptureTimer ;	// 元の自然/人工区分です。
	const auto calls  = captureTelemetry.artificialCalls ;		// 人工callbackだけの開始数です。
	const auto blocks = captureTelemetry.artificialBlocks ;		// 人工遮断だけの開始数です。
	DialogState probe{.context = &context,
					  .mode	   = DialogMode::DETAILS} ;	// HWNDを操作しない人工stateです。
	activeDialog		   = &probe ;
	artificialCaptureTimer = true ;
	captureTelemetry.depth = previousDepth + 1U ;
	dialogTimer( nullptr, WM_TIMER, 0U, 0U) ;
	const bool detailBlocked = captureTelemetry.artificialCalls == calls + 1U &&
							   captureTelemetry.artificialBlocks == blocks + 1U && !probe.handled &&
							   // 詳細の再入を遮断します。
							   probe.ticks == 0U ;
	probe.mode	  = DialogMode::INDEX_PREPARATION_ACCEPT ;
	probe.handled = true ;
	dialogTimer( nullptr, WM_TIMER, 0U, 0U) ;
	const bool preparationBlocked = captureTelemetry.artificialCalls == calls + 2U &&
									captureTelemetry.artificialBlocks == blocks + 2U &&
									probe.handled &&
									// 多段stateも変更しません。
									probe.eulaDialogs == 0U ;
	captureTelemetry.depth = previousDepth ;
	dialogTimer( nullptr, WM_TIMER, 0U, 0U) ;
	const bool released = captureTelemetry.artificialCalls == calls + 3U &&
						  // 撮影終了後には永続guardを残しません。
						  captureTelemetry.artificialBlocks == blocks + 2U ;
	activeDialog		   = previousState ;
	artificialCaptureTimer = previousArtificial ;
	DRIVERCRATE_EXPECT( context, detailBlocked) ;
	DRIVERCRATE_EXPECT( context, preparationBlocked) ;
	DRIVERCRATE_EXPECT( context, released) ;
	DRIVERCRATE_EXPECT( context, previousDepth == 0U && activeDialog == previousState &&
									captureTelemetry.depth == previousDepth &&
									artificialCaptureTimer == previousArtificial) ;
#if defined( _DEBUG)
	constexpr unsigned EXPECTED_CALLS = 7U ;	// legacy二枚と新五枚です。
#else
	constexpr unsigned EXPECTED_CALLS = 5U ;	// legacy二枚と新三枚です。
#endif
	DRIVERCRATE_EXPECT( context, captureTelemetry.calls == EXPECTED_CALLS &&
									captureTelemetry.flushes == EXPECTED_CALLS &&
									captureTelemetry.detaches == EXPECTED_CALLS &&
									captureTelemetry.boundaryFailures == 0U) ;
	DRIVERCRATE_EXPECT(
		context, captureTelemetry.snapshotFailures == 0U &&
					 captureTelemetry.closeDuringCapture == 0U && captureTelemetry.maxDepth == 1U &&
					 captureTelemetry.naturalBlocks == captureTelemetry.timerDuringCapture) ;
	std::cout << "CAPTURE_GUARD_ASSERTIONS assertions=" << context.assertionCount() - before
			  << " artificialCalls=" << captureTelemetry.artificialCalls - calls
			  << " artificialBlocks=" << captureTelemetry.artificialBlocks - blocks << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 専用buttonから本物の条件dialogを操作する。
 * @param[in,out] window 非通信factoryを設定済みのWindow。
 * @param[in,out] context Assertion集計先。
 * @param[in] cancel 条件選択を取消す場合true。
 * @param[in] queueFailure Queue停止後の固定errorを期待する場合true。
 */
//------------------------------------------------------------------------------
void beginMetadata( MainWindow &window, TestContext &context, const bool cancel = false,
				   const bool queueFailure = false)
{
	MSG previousQuit{} ;	// 同一process内で直前の試験Windowが残した終了通知。
	// 製品のWM_QUIT発行は変えず、次の独立試験のmodal loopへだけ持ち越さない。
	while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE) != FALSE) {
	}

	DialogState	 state{.context	   = &context,
					   .owner	   = Access::handle( window),
					   .mode	   = cancel ? DialogMode::CANCEL : DialogMode::ACCEPT,
					   .allowError = queueFailure} ;	// 同期操作状態。
	DialogDriver driver( state) ;						// SendMessage内のmodal loopだけを操作する。
	SendMessageW( state.owner, WM_COMMAND, IDC_METADATA_SEARCH, 0) ;
	// 不合格時だけ非機密の試験制御値を残し、modal操作と製品状態のどちらが止まったか分ける。
	if( !state.handled || state.failed) {
		std::cout << "Dialog control: handled=" << state.handled << " failed=" << state.failed
				  << " errors=" << state.errors << " ticks=" << state.ticks
				  << " window=" << (IsWindow( state.owner) != FALSE)
				  << " state=" << static_cast<unsigned>( Access::controller( window).state()) << '\n' ;
	}

	DRIVERCRATE_EXPECT( context, state.handled && !state.failed) ;
	DRIVERCRATE_EXPECT( context, state.errors == (queueFailure ? 1U : 0U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Metadata専用の処理中または取消し待ちかを判定する。
 * @param[in] window UI thread所有のWindow。
 * @return 終端event未受理ならtrue。
 */
//------------------------------------------------------------------------------
bool metadataBusy( const MainWindow &window)
{
	const auto state = Access::controller( window).state() ;	// 現在の状態機械。
	return state == ApplicationState::SCANNING ||
		   state == ApplicationState::CANCELLING_METADATA_SEARCH ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現DPI・最小sizeで新buttonやstatusの配置を確認する。
 * @param[in] window 実標準controlを持つ非通信Window。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void verifyGeometry( const MainWindow &window, TestContext &context)
{
	const HWND handle = Access::handle( window) ;	// 本試験のtop-level。
	RECT	   client{} ;							// 親clientの物理矩形。
	GetClientRect( handle, &client) ;
	// 追加buttonと下部全幅帯が親client内に収まることを確認する。
	for( const int id : {IDC_SCAN, IDC_INSTALL, IDC_UPDATE_TREE, IDC_TREE_HEADER, IDC_STATUS}) {
		RECT	   bounds{} ;							// 対象controlの矩形。
		const HWND control = GetDlgItem( handle, id) ;	// 親が所有するcontrol。
		DRIVERCRATE_EXPECT( context, control != nullptr && GetWindowRect( control, &bounds) != FALSE) ;
		MapWindowPoints( HWND_DESKTOP, handle, reinterpret_cast<POINT *>( &bounds), 2U) ;
		DRIVERCRATE_EXPECT( context,
						   bounds.left >= 0 && bounds.top >= 0 && bounds.right <= client.right &&
							   bounds.bottom <= client.bottom && bounds.bottom > bounds.top) ;
	}

	// 診断用操作も説明帯も生成せず、Tab順へ空の入口を残さない。
	for( const int id : {IDC_METADATA_SEARCH, IDC_PREPARATION, IDC_HEADER}) {
		DRIVERCRATE_EXPECT( context, GetDlgItem( handle, id) == nullptr) ;
	}

	RECT status{} ;		// 最下段の全幅帯。
	RECT buttons{} ;	// 同じ通常操作の比較位置。
	RECT header{} ;		// 上端にある三列見出し。
	GetWindowRect( GetDlgItem( handle, IDC_STATUS), &status) ;
	GetWindowRect( GetDlgItem( handle, IDC_SCAN), &buttons) ;
	GetWindowRect( GetDlgItem( handle, IDC_TREE_HEADER), &header) ;
	DRIVERCRATE_EXPECT( context, status.top > buttons.bottom && header.top < buttons.top &&
									Header_GetItemCount( GetDlgItem( handle, IDC_TREE_HEADER)) == 3) ;
	const auto gap =
		// 外周marginと同じ上限。
		MulDiv( 16, static_cast<int>( GetDpiForWindow( handle)), 96) ;
	MapWindowPoints( HWND_DESKTOP, handle, reinterpret_cast<POINT *>( &header), 2U) ;
	MapWindowPoints( HWND_DESKTOP, handle, reinterpret_cast<POINT *>( &status), 2U) ;
	DRIVERCRATE_EXPECT( context, header.top <= gap && client.bottom - status.bottom <= gap &&
									status.left == header.left && status.right == header.right) ;
	DRIVERCRATE_EXPECT( context, GetDpiForWindow( handle) >= 96U) ;
	const auto note =
		// 選択時だけの標準案内controlです。
		GetDlgItem( handle, IDC_INSTALL_TERMS_NOTE) ;
	// 親を非表示にした試験でも案内自身の表示状態と実座標を確認します。
	if( (GetWindowLongPtrW( note, GWL_STYLE) & WS_VISIBLE) != 0) {
		RECT terms{} ;		// 案内の実screen矩形です。
		RECT fullText{} ;	// 任意全文buttonの実screen矩形です。
		RECT install{} ;	// 下の明示Install buttonの実screen矩形です。
		GetWindowRect( note, &terms) ;
		GetWindowRect( GetDlgItem( handle, IDC_INSTALL_TERMS), &fullText) ;
		GetWindowRect( GetDlgItem( handle, IDC_INSTALL), &install) ;
		MapWindowPoints( HWND_DESKTOP, handle, reinterpret_cast<POINT *>( &terms), 2U) ;
		MapWindowPoints( HWND_DESKTOP, handle, reinterpret_cast<POINT *>( &fullText), 2U) ;
		MapWindowPoints( HWND_DESKTOP, handle, reinterpret_cast<POINT *>( &install), 2U) ;
		DRIVERCRATE_EXPECT( context,
						   terms.right < fullText.left && terms.top == fullText.top &&
							   terms.bottom < install.top && fullText.bottom < install.top &&
							   terms.left >= header.left && fullText.right <= header.right) ;
		wchar_t text[1024]{} ;	// 実案内の有限な文字列です。
		GetWindowTextW( note, text, 1024) ;
		RECT	   measured{0, 0, terms.right - terms.left, 0} ;	// 実幅で計算する折返し高さです。
		const auto dc = GetDC( note) ;								// 原fontの寸法だけを読む借用DCです。
		DRIVERCRATE_EXPECT( context, dc != nullptr) ;
		// 実DCがない場合に固定heightから可読性を推測しません。
		if( dc != nullptr) {
			const auto font = reinterpret_cast<HFONT>(
				// OSまたはMainWindow所有のfontです。
				SendMessageW( note, WM_GETFONT, 0, 0)) ;
			const auto previous = SelectObject( dc, font) ;	// 解放前に戻す非所有fontです。
			const auto height =
				DrawTextW( dc, text, -1, &measured,
						  DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX) ;	// 同じ実fontの必要高さです。
			SelectObject( dc, previous) ;
			ReleaseDC( note, dc) ;
			DRIVERCRATE_EXPECT( context, height > 0 && measured.bottom <= terms.bottom - terms.top) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 検索・明示選択Installの二段階を本物UI/workerと完全低位fakeで確認します。
 * @param[in,out] context 原assertionの集計先です。
 * @param[in] viewOnly 元一件/混在候補の二条件だけで準備中の表示保持を確認する場合trueです。
 * @throws std::bad_alloc 元fixture ownerを確保できない場合。既試験の例外捕捉へ渡します。
 * @note 元署名・ZIP・INF閉包と実queueを使い、HTTP/Windows/復旧/指定導入は既存の完全fakeです。
 */
//------------------------------------------------------------------------------
void runSearchPreparationUiScenarios( TestContext &context, const bool viewOnly = false)
{
	using Native = SignedIndexBindingNativeCase ;	// 元Windows低位fixtureの有限条件です。
	const std::array ids{
		"two-initial",		"one-selected",		"mixed-ready",	 "terms-view-only", "hash-rejected",
		"content-rejected", "ambiguous",		"cancel-queued", "new-scan-stale",	"close-queued",
		"restore-failed",	"unselected-target"} ;			// 固定十二条件です。
	const auto before		  = context.assertionCount() ;	// この機能の有限分母です。
	const auto failuresBefore = context.failureCount() ;	// 原失敗を保持します。
	// 正常二NICを先に実行し、続いて固定した拒否枝だけを独立ownerで確認します。
	for( std::size_t mode{}; mode < ids.size(); ++mode) {
		// 表示保持の有限確認では既低位fixtureの正常二条件だけを選びます。
		if( viewOnly && mode != 1U && mode != 2U) {
			continue ;
		}

		const auto caseFailures = context.failureCount() ;	// 条件別の原失敗数です。
		MSG		   quit{} ;									// 前の内部Windowの終了通知だけを除きます。
		// 独立した内部Window間でWM_QUITを次のmodalへ持ち越しません。
		while( PeekMessageW( &quit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
		}

		const bool mixed	  = mode == 2U ;	// 明示fake WUA候補と未取得候補を混在させます。
		const bool multi	  = mode == 6U ;	// 複数INFを勝手に選択しない条件です。
		const bool unselected = mode == 11U ;	// 別record取得の改ざんだけをworkerへ送ります。
		auto	   input	  = makeSignedIndexUiInput(
			   unselected, false, multi, false, false, false,
			   {.termsRequired	= !multi && !unselected,
						.htmlTerms		= !multi && !unselected,
						.corruptPayload = mode == 4U}) ;	// 原署名と完全HTTPの同scan入力です。
		const auto native = mixed				  ? Native::MIXED_READY
							: mode == 5U		  ? Native::INF_CLASS_MISMATCH
							: multi || unselected ? Native::SHARED_SUCCESS
												  : Native::INITIAL_SAME_ID ;	// 元低位条件です。
		auto	   bound  = makeSignedIndexBindingWorker(
			   input.services, input.zip, unselected, mode == 10U, false, native, {}, {}, {},
			   true) ;											// 自身の導入後状態だけを同fakeへ反映します。
		auto  state = std::make_shared<MetadataUiState>() ;		// 実Provider fallbackの禁止counterです。
		auto  windowOwner = std::make_unique<MainWindow>() ;	// 元scopeで同Windowをheap所有します。
		auto &window	  = *windowOwner ;						// 通常Appとは別の内部UI ownerです。
		Access::configure( window, state) ;
		const bool created =
			// 製品resourceと本物controlです。
			window.create( GetModuleHandleW( nullptr)) ;
		DRIVERCRATE_EXPECT( context, created) ;
		// 未作成Windowのfake成功を生成しません。
		if( !created) {
			bound.worker->stop() ;
			continue ;
		}

		const auto handle = Access::handle( window) ;	// 当該fixtureだけが所有するHWNDです。
		Access::attachIndexWorker( window, std::move( bound.worker)) ;
		// 本条件のworkerでは実WUA callbackを明示fakeへ置換済みです。
		if( mixed) {
			Access::enableManagedFixture( window) ;
		}

		try {
			DialogState search{
				.context = &context,
				.owner	 = handle,
				.mode = DialogMode::INDEX_PREPARATION_ACCEPT} ;	// 検索でdialogを許可しない観測です。
			search.twoStep	  = true ;
			search.rejectEula = true ;
			{
				DialogDriver driver( search) ;	// 想定外表示は承認せず元失敗へ残します。
				Access::beginSearchCommand( window) ;
			}

			DRIVERCRATE_EXPECT( context, !search.handled && !search.failed &&
											search.eulaDialogs == 0U &&
											search.preparationTaskDialogs == 0U) ;
			auto scannedOwner =
				std::make_unique<std::optional<WorkerEvent>>( Access::takeIndexTerminal(
					window,
					WorkerEventKind::SCAN_COMPLETED)) ;	// 同寿命の元eventをheapで所有します。
			auto &scanned = *scannedOwner ;				// 原検索終端です。
			DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan) ;
			// 原終端のない条件を合成planで成功へ進めません。
			if( scanned && scanned->preparationPlan) {
				const auto scanHttp =
					// EULA metadataだけの元HTTP数です。
					input.observeHttp().sends ;
				Access::dispatchIndex( window, *scanned) ;
				DRIVERCRATE_EXPECT( context, !Access::takeSearchContinuation( window) &&
												Access::controller( window).state() ==
													ApplicationState::SCAN_READY &&
												input.observeHttp().sends == scanHttp &&
												bound.observe().installs == 0U) ;
				// 元record候補の曖昧さは選択前に止め、詳細の閲覧だけで選択しません。
				if( multi) {
					const auto index =
						// 元候補の実位置です。
						Access::inspectPendingAmbiguity( window, context) ;
					const auto beforeSelection =
						// 閲覧前のcheckと指定です。
						Access::simpleSelection( window) ;
					DialogState details{.context = &context,
										.owner	 = handle,
										.mode	 = DialogMode::DETAILS} ;	// 選択しない実詳細です。
					details.captureDetails = false ;
					{
						DialogDriver driver( details) ;	// 詳細閲覧の実controlだけを操作します。
						Access::openCandidateDetails( window, index, NM_DBLCLK) ;
					}

					DRIVERCRATE_EXPECT( context,
									   details.handled && !details.failed &&
										   Access::simpleSelection( window) == beforeSelection &&
										   input.observeHttp().sends == scanHttp) ;
					Access::stopIndexWorker( window) ;
					DestroyWindow( handle) ;
					const auto observed = bound.observeAfterStop() ;	// Join後だけの低位事実です。
					const auto http		= input.observeHttp() ;			// 未取得の原HTTP観測です。
					DRIVERCRATE_EXPECT(
						context, observed.installs == 0U && observed.restoreBegins == 0U &&
									 http.opens == http.closes && bound.allNativeHandlesClosed()) ;
					std::cout << "TWO_STEP case=" << ids[mode] << " http=" << http.sends
							  << " install=0 restore=0 failures="
							  << context.failureCount() - caseFailures << " realOS=0\n"
							  << std::flush ;
					continue ;
				}

				// 表示保持の二条件は明示filter ON/OFFをそれぞれ操作前に固定します。
				if( viewOnly) {
					SendDlgItemMessageW( handle, IDC_RECOMMENDED_ONLY, BM_SETCHECK,
										mode == 2U ? BST_CHECKED : BST_UNCHECKED, 0) ;
					SendMessageW( handle, WM_COMMAND, MAKEWPARAM( IDC_RECOMMENDED_ONLY, BN_CLICKED),
								 0) ;
				}

				const auto selected = Access::selectInstallIntents(
					window, context, mode == 1U || unselected, mixed) ;	// 実checkの元集合です。
				// 同private HWNDで選択行も保存し、準備・導入の両終端へ比較します。
				if( viewOnly) {
					ShowWindow( handle, SW_SHOWNOACTIVATE) ;
					Access::expandClassPreview( window) ;
					const auto tree = GetDlgItem( handle, IDC_UPDATE_TREE) ;	// 当該所有controlです。
					TreeView_SelectItem( tree, TreeView_GetChild( tree, TreeView_GetRoot( tree))) ;
				}

				const auto originalView =
					// 再生成を検出する元handleです。
					Access::installTreeView( window) ;
				const auto originalCount =
					// 新候補の分母です。
					Access::indexCandidates( window).size() ;
				// 未検査参照の直接Install APIは引き続き復旧前に拒否されます。
				const auto pending = std::ranges::find_if(
					Access::indexCandidates( window), []( const auto &candidate) {
						return !candidate.installable &&
							   !candidate.preparationTargetIdentity.empty() ;
					}) ; // 混在時も既検証WUAではなく元未検査参照だけをprobeします。
				const auto direct =
					pending == Access::indexCandidates( window).end()
						? BeginResult{}
						: Access::rejectDirectIntentInstall(
							  window, pending->identity) ;	// 元未検査IDだけの原probeです。
				DRIVERCRATE_EXPECT( context, !direct.accepted &&
												direct.error == BeginError::UNKNOWN_IDENTITY) ;
				// 改ざん条件だけは元選択外の取得集合をworkerへ直接送り、取得0を検査します。
				if( unselected) {
					DRIVERCRATE_EXPECT( context,
									   Access::requestUnselectedIntent( window, selected.front())) ;
					auto rejectedOwner =
						std::make_unique<std::optional<WorkerEvent>>( Access::takeIndexTerminal(
							window,
							WorkerEventKind::
								PREPARATION_COMPLETED)) ;	// 同寿命の元eventをheapで所有します。
					const auto &rejected = *rejectedOwner ;	// 元worker拒否です。
					DRIVERCRATE_EXPECT( context,
									   rejected &&
										   rejected->preparationResult.approvalError ==
											   OfficialPreparationError::INVALID_APPROVAL &&
										   input.observeHttp().sends == scanHttp) ;
					DRIVERCRATE_EXPECT( context, Access::requestExpiredIndexInstall(
													window, scanned->operationId + 2U,
													scanned->scanResult.scanSessionId, selected)) ;
					auto directWorkerOwner = std::make_unique<
						std::optional<WorkerEvent>>( Access::takeIndexTerminal(
						window,
						WorkerEventKind::INSTALL_COMPLETED)) ;		// 同寿命の元eventをheapで所有します。
					const auto &directWorker = *directWorkerOwner ;	// 未検査refの元API拒否です。
					DRIVERCRATE_EXPECT( context, directWorker &&
													!directWorker->installResult.succeeded &&
													bound.observe().restoreBegins == 0U &&
													bound.observe().installs == 0U &&
													input.observeHttp().sends == scanHttp) ;
				} else {
					// 正常二件では原案内の表示と、差替え・旧選択からのInstall拒否を確認します。
					if( mode == 0U) {
						DialogState guard{
							.context = &context,
							.owner	 = handle,
							.mode	 = DialogMode::
								INDEX_PREPARATION_ACCEPT} ;	// 想定外dialogを拒否する監視です。
						guard.twoStep	 = true ;
						guard.rejectEula = true ;
						DialogDriver driver( guard) ;	// 拒否probeの間だけ原Windowを監視します。
						Access::verifyInlineInstallTerms( window, context) ;
						DRIVERCRATE_EXPECT( context, !guard.handled && !guard.failed &&
														input.observeHttp().sends == scanHttp &&
														bound.observe().restoreBegins == 0U &&
														bound.observe().installs == 0U) ;
					}

					// 任意の原全文閲覧は同意を発行せず、元選択とpayload未取得を維持します。
					if( mode == 0U || mode == 3U) {
						const auto beforeSelection =
							// 原check集合です。
							Access::simpleSelection( window) ;
						DialogState view{.context = &context,
										 .owner	  = handle,
										 .mode = DialogMode::DETAILS} ;	// 閉じるだけの任意閲覧です。
						view.captureDetails	 = mode == 0U ;
						view.captureName	 = L"inline-install-terms" ;
						view.inlineTermsView = true ;
						{
							DialogDriver driver( view) ;	// 元read-only controlを読んで閉じます。
							SendMessageW( handle, WM_COMMAND, IDC_INSTALL_TERMS, 0) ;
						}
						DRIVERCRATE_EXPECT(
							context,
							view.handled && !view.failed &&
								view.details.find(
									L"fixture-source (https://vendor.example/)\r\nOriginal 1.0\r\n\r\nOriginal 1.0\r\n\r\nFictional complete driver license.\r\n\r\nOriginal terms line two.\r\n") !=
									std::wstring::npos &&
								view.details.find( L"Fictional complete driver license.") ==
									view.details.rfind( L"Fictional complete driver license.") &&
								Access::simpleSelection( window) == beforeSelection &&
								input.observeHttp().sends == scanHttp &&
								Access::indexApproval( window).operationId == 0U &&
								bound.observe().installs == 0U &&
								bound.observe().restoreBegins == 0U) ;
						// 実controlで案内全文の高さと、三列・最下段progressの配置を確認します。
						if( mode == 0U) {
							ShowWindow( handle, SW_SHOWNOACTIVATE) ;
							// 通常幅と最小幅の両方で説明・閲覧・Installを重ねません。
							for( const int width : {1280, 960}) {
								SetWindowPos( handle, nullptr, 30, 30, width, 760,
											 SWP_NOACTIVATE | SWP_NOZORDER) ;
								verifyGeometry( window, context) ;
							}
						}
					}

					DialogState review{
						.htmlTerms = true,
						.context   = &context,
						.owner	   = handle,
						.mode =
							DialogMode::INDEX_PREPARATION_ACCEPT} ;	// 独立EULAを許可しない監視です。
					review.twoStep	  = true ;
					review.rejectEula = true ;
					{
						DialogDriver driver( review) ;	// 通常Installに独立規約dialogを挟ませません。
						// 同意しない条件ではInstallせず、選択を解除します。
						if( mode == 3U) {
							Access::clearInlineInstallTerms( window, context) ;
						} else {
							Access::beginIndexInstallCommand( window) ;
						}
					}

					DRIVERCRATE_EXPECT( context, !review.failed && review.eulaValid &&
													review.preparationTaskDialogs == 0U &&
													review.acquisitionDecisionDialogs == 0U &&
													review.finalConfirmationDialogs == 0U &&
													review.eulaDialogs == 0U) ;
					// 任意閲覧後の取消しはpayload0・同意0・復旧0で元候補表示へ戻します。
					if( mode == 3U) {
						DRIVERCRATE_EXPECT( context,
										   input.observeHttp().sends == scanHttp &&
											   Access::controller( window).state() ==
												   ApplicationState::SCAN_READY &&
											   Access::indexApproval( window).operationId == 0U &&
											   bound.observe().restoreBegins == 0U &&
											   bound.observe().installs == 0U) ;
					} else {
						auto preparedOwner =
							std::make_unique<std::optional<WorkerEvent>>( Access::takeIndexTerminal(
								window,
								WorkerEventKind::
									PREPARATION_COMPLETED)) ;	// 同寿命の元eventをheapで所有します。
						auto &prepared = *preparedOwner ;		// 元取得・監査終端です。
						DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
						// 元終端だけを通常UIへ渡し、成功をtest側で補完しません。
						if( prepared) {
							DRIVERCRATE_EXPECT(
								context,
								input.observeHttp().sends == scanHttp + 1U &&
									Access::indexApproval( window).installIntentIdentities ==
										selected) ;
							// 終端がqueue済みでも明示取消し後は導入へ継続しません。
							if( mode == 7U || mode == 8U) {
								Access::beginSearchCommand( window) ;
							}

							// 閉じる同意は協調取消しへ結び、元取得終端を待ちます。
							if( mode == 9U) {
								DialogState	 close{.context = &context,
												   .owner	= handle,
												   .mode = DialogMode::CLOSE} ;	// 終了判断だけです。
								DialogDriver driver(
									close) ;	// 所有fake Windowの終了判断だけを制御します。
								SendMessageW( handle, WM_CLOSE, 0, 0) ;
								DRIVERCRATE_EXPECT( context, close.handled && !close.failed) ;
							}

							Access::dispatchIndex( window, *prepared) ;
							// 検査済み候補のappendと一意選択が元itemで成立したことを確認します。
							if( viewOnly) {
								Access::verifyInstallTreeView( window, originalView, context) ;
								Access::verifyPreparedRowBindings( window, originalCount, context) ;
							}

							const bool installs =
								mode <= 2U || mode == 10U ;	// 全元選択が成立した固定条件です。
							// 正常二NICを既存復旧・指定導入・read-only現在観測まで通します。
							if( installs) {
								auto installedOwner = std::make_unique<
									std::optional<WorkerEvent>>( Access::takeIndexTerminal(
									window,
									WorkerEventKind::
										INSTALL_COMPLETED)) ;		// 同寿命の元eventをheapで所有します。
								auto &installed = *installedOwner ;	// 本体の元個別結果です。
								DRIVERCRATE_EXPECT(
									context, installed && installed->installResult.updates.size() ==
															  selected.size()) ;
								// 元導入終端がある場合だけ実結果と通常一覧を照合します。
								if( installed) {
									const auto &result =
										installed->installResult ;	// 復旧を含む原結果です。
									DRIVERCRATE_EXPECT( context, result.succeeded == (mode != 10U) &&
																	result.currentDevices.size() <=
																		selected.size()) ;
									// 二NIC正例は元選択二件の実read-only観測と現在版を独立に要求します。
									if( mode == 0U) {
										DRIVERCRATE_EXPECT( context,
														   result.currentDevices.size() == 2U &&
															   std::ranges::all_of(
																   result.currentDevices,
																   []( const auto &observed) {
																	   return observed.error == 0 &&
																			  observed.version ==
																				  L"1.0.0.0" ;
																   })) ;
									}

									DialogState shown{
										.context = &context,
										.owner	 = handle,
										.mode	 = DialogMode::
											INDEX_INSTALL_RESULT} ;	// 原結果の閲覧だけです。
									{
										DialogDriver driver(
											shown) ;	// 同fake導入の確定結果だけを閲覧します。
										Access::dispatchIndex( window, *installed) ;
									}

									// 復元前の停止では全driver roleを未実行のまま保持します。
									if( mode == 10U) {
										DRIVERCRATE_EXPECT(
											context,
											result.restorePointCreation.outcome ==
													OutcomeCode::FAILURE &&
												result.installOutcome == OutcomeCode::NOT_STARTED &&
												std::ranges::all_of(
													result.updates, []( const auto &item) {
														return item.installOutcome ==
																   OutcomeCode::NOT_STARTED &&
															   std::ranges::all_of(
																   item.requiredRoles,
																   []( const auto &role) {
																	   return role.stageOutcome ==
																				  OutcomeCode::
																					  NOT_STARTED &&
																			  role.installOutcome ==
																				  OutcomeCode::
																					  NOT_STARTED ;
																   }) ;
													})) ;
									}

									Access::verifyIndexResultRows( window, context, result,
																  mode == 10U) ;
									// 導入完了後も元filter・行集合・順序・caret/scrollを動かしません。
									if( viewOnly) {
										Access::verifyInstallTreeView( window, originalView,
																	  context) ;
										DRIVERCRATE_EXPECT(
											context,
											SendDlgItemMessageW( handle, IDC_RECOMMENDED_ONLY,
																BM_GETCHECK, 0, 0) ==
												(mode == 2U ? BST_CHECKED : BST_UNCHECKED)) ;
									}

									// 新候補版の転記でなく同終端観測が通常現在行へ反映されたか確認します。
									if( mode == 0U) {
										DRIVERCRATE_EXPECT(
											context, std::ranges::count_if(
														 Access::indexCandidates( window),
														 []( const auto &candidate) {
															 return candidate.current &&
																	candidate.version == L"1.0.0.0" ;
														 }) == 2) ;
									}

									const auto observed =
										// 元終端と同期した低位counterです。
										bound.observe() ;
									DRIVERCRATE_EXPECT(
										context,
										observed.restoreBegins == 1U &&
											observed.installs + observed.managedInstalls ==
												(mode == 10U ? 0U : selected.size()) &&
											observed.deviceInstalls[1] ==
												(mode == 1U || mixed || mode == 10U ? 0U : 1U)) ;
									// 元初回結果後の実fake再scanをそのまま受理します。
									if( mode == 0U) {
										DialogState guardState{
											.context = &context,
											.owner	 = handle,
											.mode	 = DialogMode::
												INDEX_PREPARATION_ACCEPT} ;	// 同ownerのdialog監視です。
										guardState.twoStep	  = true ;
										guardState.rejectEula = true ;
										{
											DialogDriver guard(
												guardState) ;	// 検索中の予期しないdialogを拒否します。
											Access::beginSearchCommand( window) ;
										}
										auto nextOwner = std::make_unique<
											std::optional<WorkerEvent>>( Access::takeIndexTerminal(
											window,
											WorkerEventKind::
												SCAN_COMPLETED)) ;	// 同寿命の元eventをheapで所有します。
										auto &next = *nextOwner ;	// 同fake workerの元終端です。
										DRIVERCRATE_EXPECT( context, next && !guardState.handled &&
																		!guardState.failed) ;
										// 元終端がある場合だけ表示へ反映します。
										if( next) {
											{
												DialogDriver guard(
													guardState) ;	// 通知処理中も想定外dialogを監視します。
												Access::dispatchIndex( window, *next) ;
											}
											DRIVERCRATE_EXPECT( context, !guardState.handled &&
																			!guardState.failed) ;
											Access::verifyFreshAfterInitial( window, context) ;
										}
									}
								}
							} else {
								DRIVERCRATE_EXPECT( context,
												   bound.observe().installs == 0U &&
													   bound.observe().restoreBegins == 0U) ;
								// 真の複数候補を自動選択しなかった理由を通常messageへ残します。
								if( multi) {
									DRIVERCRATE_EXPECT(
										context, Access::indexStatusText( window).find( L"複数") !=
													 std::wstring::npos) ;
								}
							}

							// 新検索後の旧取得終端を新しい選択意図として適用しません。
							if( mode == 8U) {
								Access::beginSearchCommand( window) ;
								auto nextOwner = std::make_unique<std::optional<WorkerEvent>>(
									Access::takeIndexTerminal(
										window,
										WorkerEventKind::
											SCAN_COMPLETED)) ;	// 同寿命の元eventをheapで所有します。
								const auto &next = *nextOwner ;	// 同workerの新scanです。
								DRIVERCRATE_EXPECT( context, next && next->operationId !=
																		scanned->operationId) ;
								// 新しい元終端がある場合にだけ旧eventを再送します。
								if( next) {
									Access::dispatchIndex( window, *next) ;
									Access::dispatchIndex( window, *prepared) ;
									DRIVERCRATE_EXPECT( context,
													   Access::controller( window).scanSessionId() ==
															   next->scanResult.scanSessionId &&
														   bound.observe().installs == 0U &&
														   !Access::takeSearchContinuation( window)) ;
								}
							}
						}
					}
				}
			}
		} catch( ...) {
			Access::stopIndexWorker( window) ;
			DestroyWindow( handle) ;
			throw ;
		}

		Access::stopIndexWorker( window) ;
		// 試験ownerだけを破棄し、通常AppのWindowへ操作を送りません。
		if( IsWindow( handle)) {
			DestroyWindow( handle) ;
		}

		const auto observed = bound.observeAfterStop() ;	// Join後だけ参照する低位事実です。
		const auto http		= input.observeHttp() ;			// 原HTTP handleの有限観測です。
		DRIVERCRATE_EXPECT( context, http.safe && http.opens == http.closes &&
										state->forbiddenCalls == 0U &&
										bound.allNativeHandlesClosed()) ;
		std::cout << "TWO_STEP case=" << ids[mode] << " http=" << http.sends
				  << " install=" << observed.installs + observed.managedInstalls
				  << " restore=" << observed.restoreBegins
				  << " failures=" << context.failureCount() - caseFailures << " realOS=0\n"
				  << std::flush ;
	}

	std::cout << "TWO_STEP_END cases=" << (viewOnly ? 2U : ids.size())
			  << " assertions=" << context.assertionCount() - before
			  << " failures=" << context.failureCount() - failuresBefore << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同taskの一取得本体と未消費routeを同scan第二Installへ接続します。
 * @param[in,out] context 原assertionです。
 * @param[in] localReuse 別recordの独立時刻窓/新LOCAL claimを確認する場合trueです。
 */
//------------------------------------------------------------------------------
void runTargetOnlySharedUiScenario( TestContext &context, const bool localReuse = false)
{
	using Native = SignedIndexBindingNativeCase ;	// 原Ports二nativeです。
	SignedIndexUiOptions options ;					// 別record一件だけ原時刻窓を独立にします。
	options.contentInspectedVersion = localReuse ? L"1.0.0.0" : L"" ;
	options.secondAttestationWindow = localReuse ;
	auto	   input				= makeSignedIndexUiInput( true, true, false, false, false, false,
															 options) ;	// 原Ports/二Modelsです。
	auto	   loads = std::make_shared<std::atomic_uint>( 0U) ;		// 自動全scanを元loadで検出します。
	const auto originalLoad = input.services.load ;						// 元RAM署名storeを保持します。
	input.services.load		= [loads, originalLoad]( auto now) {
		++*loads ;
		return originalLoad( now) ;
	} ;
	auto  bound		  = makeSignedIndexBindingWorker( input.services, input.zip, true, false, false,
													 Native::SHARED_SUCCESS, {}, {}, {},
													 true) ;	// 自己deviceだけ実版反映します。
	auto  state		  = std::make_shared<MetadataUiState>() ;	// 実fallback禁止です。
	auto  ownedWindow = std::make_unique<MainWindow>() ;		// 大きい所有UI stateをheapへ置きます。
	auto &window	  = *ownedWindow ;							// 元scopeがworker停止とWindow破棄まで所有します。
	Access::configure( window, state) ;
	DRIVERCRATE_EXPECT( context, window.create( GetModuleHandleW( nullptr))) ;
	const auto handle = Access::handle( window) ;	// 元所有Windowです。
	Access::attachIndexWorker( window, std::move( bound.worker)) ;
	Access::beginSearchCommand( window) ;
	auto scan =
		// 初回だけです。
		Access::takeIndexTerminal( window, WorkerEventKind::SCAN_COMPLETED) ;
	DRIVERCRATE_EXPECT( context,
					   scan && scan->scanResult.succeeded && scan->preparationPlan &&
						   scan->preparationPlan->targets.size() == (localReuse ? 2U : 1U)) ;
	// 生成原planを受理できた場合だけ明示取得へ進みます。
	if( scan) {
		Access::dispatchIndex( window, *scan) ;
		const auto session	= scan->scanResult.scanSessionId ;	// 維持する元scanです。
		const auto selected = Access::selectTargetOnlyReference(
			window, context, localReuse ? L"1.0.0.0" : L"") ;	// 元device一件です。
		DRIVERCRATE_EXPECT( context, selected.size() == 1U && input.observeHttp().sends == 0U) ;
		Access::beginIndexInstall( window) ;
		auto prepared = Access::takeIndexTerminal(
			window, WorkerEventKind::PREPARATION_COMPLETED) ;	// 原一回取得です。
		DRIVERCRATE_EXPECT( context, prepared && prepared->preparationResult.approvalError ==
													OfficialPreparationError::NONE) ;
		// 準備成功を公開flagだけで導入へ補完しません。
		if( prepared) {
			DialogState accepted{.context = &context,
								 .owner	  = handle,
								 .mode	  = DialogMode::INDEX_PREPARATION_ACCEPT} ;	// 通常経路です。
			accepted.twoStep = true ;
			{
				// このscopeだけで所有modalを駆動します。
				DialogDriver driver( accepted) ;
				Access::dispatchIndex( window, *prepared) ;
			}
			auto first = Access::takeIndexTerminal(
				window, WorkerEventKind::INSTALL_COMPLETED) ;	// 元一件です。
			DRIVERCRATE_EXPECT( context, first && first->installResult.succeeded &&
											first->installResult.updates.size() == 1U &&
											first->installRetention) ;
			DRIVERCRATE_EXPECT(
				context, first && first->installResult.currentDevices.size() == 1U &&
							 first->installResult.currentDevices.front().selectedTargetMatched) ;
			// 実ownerの残存証明後だけ第二の通常Installへ進みます。
			if( first) {
				DialogState shown{.context = &context,
								  .owner   = handle,
								  .mode = DialogMode::INDEX_INSTALL_RESULT} ;	// 原結果を閉じます。
				{
					// このscopeだけで所有modalを駆動します。
					DialogDriver driver( shown) ;
					Access::dispatchIndex( window, *first) ;
				}
				DRIVERCRATE_EXPECT( context, loads->load() == 1U &&
												input.observeHttp().sends == 1U &&
												bound.observe().installs == 1U) ;
				// 未準備Bは元ownerを保持した新planへ、同taskBは未消費routeへ明示選択します。
				if( localReuse) {
					DRIVERCRATE_EXPECT(
						context,
						first->installRetention->preparationPlan &&
							first->installRetention->preparationPlan->targets.size() == 1U &&
							first->installRetention->preparationPlan->planId >
								scan->preparationPlan->planId &&
							first->installRetention->references.size() == 1U &&
							Access::controller( window).preparationPlan()) ;
					const auto remaining = Access::selectInstallIntents(
						window, context, true, false, L"1.0.0.0") ;	// 元Bの通常checkboxです。
					DRIVERCRATE_EXPECT( context, remaining.size() == 1U && remaining != selected) ;
				} else {
					Access::selectIndexCandidates(
						window, context,
						std::array{first->installRetention->candidates.front().identity}) ;
				}

				Access::beginIndexInstall( window) ;
				// 別record Bは新しい明示承認による実LOCAL検査を先に完了します。
				if( localReuse) {
					auto inspected = Access::takeIndexTerminal(
						window, WorkerEventKind::PREPARATION_COMPLETED) ;	// 本体GETは増えません。
					DRIVERCRATE_EXPECT(
						context,
						inspected &&
							inspected->preparationResult.approvalError ==
								OfficialPreparationError::NONE &&
							inspected->preparationResult.controlError == 0U &&
							inspected->preparationResult.items.size() == 1U &&
							inspected->preparationResult.items.front().result.state ==
								OfficialPreparationItemState::LOCAL_INSPECTION_COMPLETED &&
							inspected->preparationResult.items.front().result.localInspection &&
							inspected->preparationResult.items.front().result.byteCount == 0U &&
							inspected->indexPreparation.items.size() == 1U &&
							inspected->indexPreparation.items.front().acquisition ==
								OfficialAcquisitionState::NOT_STARTED &&
							inspected->indexPreparation.items.front().reusedOwnedBody &&
							inspected->indexPreparation.items.front().acceptedInfCount == 1U &&
							input.observeHttp().sends == 1U && bound.observe().installs == 1U) ;
					// 実結果だけを通常UIへ送り、fake成功を補完しません。
					if( inspected) {
						DialogState acceptedAgain{
							.context = &context,
							.owner	 = handle,
							.mode = DialogMode::INDEX_PREPARATION_ACCEPT} ;	// 二度目の明示操作です。
						acceptedAgain.twoStep = true ;
						{
							// このscopeだけで所有modalを駆動します。
							DialogDriver driver( acceptedAgain) ;
							Access::dispatchIndex( window, *inspected) ;
						}
					}
				}

				auto second = Access::takeIndexTerminal(
					window, WorkerEventKind::INSTALL_COMPLETED) ;	// 未消費routeです。
				DRIVERCRATE_EXPECT( context,
								   second && second->installResult.succeeded &&
									   second->installResult.updates.size() == 1U &&
									   Access::controller( window).scanSessionId() == session &&
									   loads->load() == 1U && input.observeHttp().sends == 1U &&
									   bound.observe().installs == 2U) ;
			}
		}
	}

	Access::stopIndexWorker( window) ;
	DestroyWindow( handle) ;
	MSG quit{} ;	// 次のcaseへ終了を持ち越しません。
	// 元集合の各要素を同じscopeへ一度ずつ照合します。
	while( PeekMessageW( &quit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
	}

	std::cout << (localReuse ? "TARGET_ONLY_LOCAL_REUSE loads=" : "TARGET_ONLY_SHARED loads=")
			  << loads->load() << " http=" << input.observeHttp().sends
			  << " installs=" << bound.observeAfterStop().installs << " realOS=0\n"
			  << std::flush ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同低位Ports二nativeの直接DS一件後に同scanの第二Installを確認します。
 * @param[in,out] context 正負の原assertion集計先です。
 * @param[in] latestView 正常一件だけ再起動不要を明示し最新解消表示を確認します。
 * @note WUA/HTTP/復旧/指定導入は完全fake、実OS変更はありません。
 */
//------------------------------------------------------------------------------
void runTargetOnlyLocalUiScenario( TestContext &context, const bool latestView = false)
{
	using Native = SignedIndexBindingNativeCase ;	// 原低位条件です。
	auto input	 = makeSignedIndexUiInput( true) ;	// 原Ports/二Models、metadata GET不要です。
	auto bound	 = makeSignedIndexBindingWorker(
		  input.services, input.zip, true, false, false, Native::SHARED_SUCCESS, {}, {}, {}, true,
		  SignedIndexBindingBatchFault::NONE, true, latestView) ;	// 元二nativeです。
	auto	   state = std::make_shared<MetadataUiState>() ;		// fallback実行の禁止です。
	MainWindow window ;												// private desktopだけの内部Windowです。
	Access::configure( window, state) ;
	DRIVERCRATE_EXPECT( context, window.create( GetModuleHandleW( nullptr))) ;
	const auto handle = Access::handle( window) ;	// 当該所有Windowです。
	Access::attachIndexWorker( window, std::move( bound.worker)) ;
	Access::beginSearchCommand( window) ;
	auto scan =
		// 一回だけの検索です。
		Access::takeIndexTerminal( window, WorkerEventKind::SCAN_COMPLETED) ;
	DRIVERCRATE_EXPECT( context, scan && scan->scanResult.succeeded) ;
	// 原scanがない場合に作成した候補で成功を補いません。
	if( scan) {
		Access::dispatchIndex( window, *scan) ;
		const auto session	= scan->scanResult.scanSessionId ;					// 変えない原scanです。
		const auto consumed = Access::startTargetOnlyLocal( window, context) ;	// 一対象だけです。
		const auto view		= Access::installTreeView( window) ;				// 元HTREEITEM/順序/分類です。
		auto	   first	= Access::takeIndexTerminal(
			 window, WorkerEventKind::INSTALL_COMPLETED) ;	// 実workerの終端です。
		DRIVERCRATE_EXPECT( context, first && first->installResult.succeeded &&
										first->installRetention &&
										first->installRetention->scanSessionId == session) ;
		// 同所有終端がある場合だけ次の通常入口へ進みます。
		if( first) {
			DialogState shown{.context = &context,
							  .owner   = handle,
							  .mode = DialogMode::INDEX_INSTALL_RESULT} ;	// 元結果だけを閉じます。
			{
				// このscopeだけで所有modalを駆動します。
				DialogDriver driver( shown) ;
				Access::dispatchIndex( window, *first) ;
			}
			Access::verifyInstallTreeView( window, view, context) ;
			// 最新解消の表示条件は明示した正常一件だけで確認します。
			if( latestView) {
				Access::verifyLatestResolved( window, context, consumed) ;
			}

			DRIVERCRATE_EXPECT( context, input.observeHttp().sends == 0U &&
											bound.observe().installs == 1U &&
											!Access::takeSearchContinuation( window)) ;
			// 元有効選択の操作を開始できた場合だけtrueです。
			const bool started =
				Access::startTargetOnlyRemaining( window, context, session, consumed) ;
			auto second =
				started ? Access::takeIndexTerminal( window, WorkerEventKind::INSTALL_COMPLETED)
						: std::optional<WorkerEvent>{} ;	// 通常操作の第二終端です。
			DRIVERCRATE_EXPECT( context, second && second->installResult.succeeded &&
											second->installResult.updates.size() == 1U &&
											bound.observe().installs == 2U &&
											bound.observe().restoreBegins == 2U &&
											input.observeHttp().sends == 0U) ;
		}
	}

	Access::stopIndexWorker( window) ;
	DestroyWindow( handle) ;
	MSG quit{} ;	// 次の独立caseへ終了messageを持ち越しません。
	// 元集合の各要素を同じscopeへ一度ずつ照合します。
	while( PeekMessageW( &quit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
	}

	std::cout << "TARGET_ONLY_LOCAL scans=1 http=" << input.observeHttp().sends
			  << " installs=" << bound.observeAfterStop().installs << " realOS=0\n"
			  << std::flush ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ非通信Windowで最新解消の既知新版/未確認等を有限確認します。
 * @param[in,out] context 原assertion集計先です。
 */
//------------------------------------------------------------------------------
void runLatestBoundaryUiScenarios( TestContext &context)
{
	// 元history fixtureと同じく各条件を独立したWindow/scanへ結びます。
	for( unsigned variant = 0; variant < 15U; ++variant) {
		auto state	= std::make_shared<MetadataUiState>() ;	// 実Provider/復旧を許可しません。
		auto window = std::make_unique<MainWindow>() ;		// 大きいfixture所有はheapに置きます。
		Access::configure( *window, state) ;
		const bool created =
			// 同private desktopの標準controlです。
			window->create( GetModuleHandleW( nullptr)) ;
		DRIVERCRATE_EXPECT( context, created) ;
		// Window作成不成立では後続のcontrol操作へ進みません。
		if( !created) {
			return ;
		}

		Access::latestBoundaries( *window, context, variant) ;
		DRIVERCRATE_EXPECT( context, state->forbiddenCalls == 0U && state->restoreCalls == 0U) ;
		DestroyWindow( Access::handle( *window)) ;
		MSG quit{} ;	// 次のcaseへ所有Windowの終了を持ち越しません。
		// この所有WindowがpostしたWM_QUITだけを回収します。
		while( PeekMessageW( &quit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元結果九条件と非零scroll二条件を既fake HWNDで有限確認します。
 * @param[in,out] context 原assertion集計先です。
 */
//------------------------------------------------------------------------------
void runInstallTreeViewUiScenarios( TestContext &context)
{
	auto	   state = std::make_shared<MetadataUiState>() ;	// 実Provider/復旧呼出しを禁止します。
	MainWindow window ;											// 同private desktopだけの所有Windowです。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 製品と同じcontrolです。
	DRIVERCRATE_EXPECT( context, created) ;
	// 不存在controlへ試験入力を渡しません。
	if( !created) {
		return ;
	}

	const auto handle = Access::handle( window) ;	// 当該Windowだけを表示します。
	ShowWindow( handle, SW_SHOWNOACTIVATE) ;
	SetWindowPos( handle, nullptr, 0, 0, 960, 560, SWP_NOACTIVATE | SWP_NOZORDER) ;
	const auto deliver = []( MainWindow &target, const WorkerEvent &event, TestContext &assertions) {
		DialogState dialog{
			.context = &assertions,
			.owner	 = Access::handle( target),
			.mode	 = DialogMode::INDEX_INSTALL_RESULT} ;	// 既timerで原結果を閉じるだけです。
		{
			DialogDriver driver( dialog) ;	// 所有modalだけを処理します。
			Access::deliverInstallCompleted( target, event) ;
		}

		DRIVERCRATE_EXPECT( assertions, dialog.handled && !dialog.failed) ;
	} ; // Captureを持たず、同期callback中だけ元Windowと集計先を借用します。
	Access::verifyPostInstallDisplay( window, context, deliver) ;
	// Filter ON/OFFで同じ非零scroll・部分選択の保持を確認します。
	for( const bool filter : {true, false}) {
		Access::verifyScrolledInstallView( window, context, filter, deliver) ;
	}

	DRIVERCRATE_EXPECT( context, state->forbiddenCalls == 0U && state->normalCalls == 0U &&
									state->restoreCalls == 0U) ;
	SendMessageW( handle, WM_CLOSE, 0, 0) ;
	DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
	std::cout << "INSTALL_VIEW_END resultCases=9 scrolledCases=2 physicalInput=0 realOS=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新検索前段階と既存取得前案内だけを非通信Windowで確認します。
 * @param[in,out] context Assertion集計先です。
 */
//------------------------------------------------------------------------------
void runHardwareRefreshUiScenarios( TestContext &context)
{
	auto	   state = std::make_shared<MetadataUiState>() ;	// 正規fake factoryだけです。
	MainWindow window ;											// 通常Appとは別の内部UI試験Windowです。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 本物resource/controlです。
	DRIVERCRATE_EXPECT( context, created) ;
	// 未作成Windowへ制御を送りません。
	if( !created) {
		return ;
	}

	Access::verifyHardwareRefresh( window, context) ;
	Access::verifyPreparationGuidance( window, context) ;
	Access::verifyPostInstallDisplay(
		window, context,
		[]( MainWindow &target, const WorkerEvent &event, TestContext &testContext) {
			DialogState dialog{.context = &testContext,
							   .owner	= Access::handle( target),
							   .mode	= DialogMode::INDEX_INSTALL_RESULT} ;
			{
				DialogDriver guard( dialog) ;
				Access::deliverInstallCompleted( target, event) ;
			}
			DRIVERCRATE_EXPECT( testContext,
							   !dialog.failed &&
								   dialog.handled ==
									   (event.kind == WorkerEventKind::INSTALL_COMPLETED)) ;
		}) ;
	const auto handle = Access::handle( window) ;	// 本試験だけが所有するHWND。
	verifyGeometry( window, context) ;
	// 実DPI通知とresizeでも列と最下段帯の配置を維持する。
	for( const int dpi : {144, 192, 96}) {
		RECT suggested{0, 0, MulDiv( 1100, dpi, 96), MulDiv( 700, dpi, 96)} ;	// 推奨矩形。
		SendMessageW( handle, WM_DPICHANGED, MAKEWPARAM( dpi, dpi),
					 reinterpret_cast<LPARAM>( &suggested)) ;
		verifyGeometry( window, context) ;
	}

	// 導入後結果と不明機器の詳細を一回ずつ閲覧する。
	for( const bool unknown : {false, true}) {
		// 不明行も通常詳細を開き、閲覧用reportから導入指定を発行しない。
		if( unknown) {
			Access::unknownSimpleDetails( window, context) ;
		}

		const auto	before = Access::simpleSelection( window) ;	// 元の指定/check。
		DialogState details{
			.context = &context, .owner = handle, .mode = DialogMode::DETAILS} ;	// 閲覧だけの判断。
		details.captureDetails	 = false ;
		details.detailSelectable = false ;
		details.detailEntry		 = 1 ;
		{
			DialogDriver driver( details) ;	// 同期閲覧だけを行う既存helper。
			Access::openCandidateDetails( window, 0U, NM_DBLCLK) ;
		}
		DRIVERCRATE_EXPECT(
			context, details.handled && !details.failed &&
						 Access::simpleSelection( window) == before &&
						 details.details.find( unknown ? L"取得・検査全体の結果を示す行です"
													  : L"インストール") != std::wstring::npos) ;
	}

	DialogState classificationGuard{
		.context = &context,
		.owner	 = Access::handle( window),
		.mode	 = DialogMode::
			INDEX_PREPARATION_ACCEPT} ;	// 新fixtureの想定外dialogは同意せず失敗へ残します。
	classificationGuard.twoStep	   = true ;
	classificationGuard.rejectEula = true ;
	{
		DialogDriver guard( classificationGuard) ;	// 既存の有限なmodal監督だけを借用します。
		Access::verifyInstalledClassification( window, context) ;
	}
	DRIVERCRATE_EXPECT( context, !classificationGuard.handled && !classificationGuard.failed) ;
	DRIVERCRATE_EXPECT( context, state->normalCalls == 0U && state->metadataCalls == 0U &&
									state->forbiddenCalls == 0U && state->restoreCalls == 0U) ;
	DestroyWindow( Access::handle( window)) ;
	std::cout << "Hardware refresh UI: native CM/token/query/install=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常・失敗・取消しの終端一覧と専用dialogを操作する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void runUiScenarios( TestContext &context)
{
	auto	   state = std::make_shared<MetadataUiState>() ;	// WorkerとUIが共有する非機密counter。
	MainWindow window ;											// 実Providerへ接続しない所有Window。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 製品と同じresourceを使用する。
	DRIVERCRATE_EXPECT( context, created) ;
	// 作成不能なWindowへ制御messageを送らない。
	if( !created) {
		return ;
	}

	const HWND handle = Access::handle( window) ;	// 生存期間中だけ使う非所有handle。
	ShowWindow( handle, SW_SHOWNOACTIVATE) ;
	SetWindowPos( handle, nullptr, 30, 30, 1280, 760, SWP_NOACTIVATE | SWP_NOZORDER) ;
	verifyGeometry( window, context) ;
	beginMetadata( window, context, true) ;
	DRIVERCRATE_EXPECT( context, state->metadataCalls == 0U &&
									Access::controller( window).state() == ApplicationState::IDLE) ;
	// 同じWindowで全終端を明示再検索し、前回の選択・同意を継承しないことも確認する。
	for( const auto scenario : {MetadataUiScenario::INFORMATION, MetadataUiScenario::NO_INFORMATION,
							   MetadataUiScenario::NOT_APPLICABLE, MetadataUiScenario::FAILED,
							   MetadataUiScenario::REJECTED}) {
		state->scenario = scenario ;
		beginMetadata( window, context) ;
		DRIVERCRATE_EXPECT( context, pumpUntil( [&] { return !metadataBusy( window) ; })) ;
		const auto *summary =
			// 検証済み終端だけを参照する。
			Access::controller( window).metadataSearchSummary() ;
		DRIVERCRATE_EXPECT( context, summary != nullptr) ;
		// 未検証packetをdereferenceしない。
		if( summary == nullptr) {
			continue ;
		}

		DRIVERCRATE_EXPECT(
			context, summary->request.enabledProviderIds ==
						 std::vector<std::wstring>{std::wstring( PROLIFIC_OFFICIAL_PROVIDER_ID)}) ;
		DRIVERCRATE_EXPECT( context, !summary->request.restrictedNetworkApproved) ;
		DRIVERCRATE_EXPECT( context, Access::count( window) ==
										(scenario == MetadataUiScenario::INFORMATION ? 5U : 3U)) ;
		Access::verifyStale( window, context) ;
		// 正常な情報二行では未知版と明示配布版の両方を確認する。
		if( scenario == MetadataUiScenario::INFORMATION) {
			Access::verifyRows( window, context) ;
			const auto text = Access::displayText( window) ;	// 読み上げ用の全field。
			DRIVERCRATE_EXPECT( context, text.find( L"1.2.3.4") != std::wstring::npos &&
											text.find( L"9.8") != std::wstring::npos &&
											text.find( L"—") != std::wstring::npos) ;
			DRIVERCRATE_EXPECT( context, captureWindow( handle, L"information")) ;
			DialogState details{.context = &context,
								.owner	 = handle,
								.mode	 = DialogMode::DETAILS} ;	// 詳細だけを開く。
			{
				DialogDriver driver( details) ;	// 取得元buttonの新mode用途を検証する。
				SendMessageW( handle, WM_COMMAND, IDC_PROVIDER_SOURCES, 0) ;
			}
			DRIVERCRATE_EXPECT( context,
							   details.handled && !details.failed && !details.details.empty()) ;
			DRIVERCRATE_EXPECT( context,
							   details.details.find( L"fixture-device") == std::wstring::npos &&
								   details.details.find( L"Fixture maker") == std::wstring::npos &&
								   details.details.find( L"https://") == std::wstring::npos &&
								   details.details.find( L"32 MiB") != std::wstring::npos) ;
		}

		Access::verifyDisplayOnly( window, context) ;
		// 合成clickでも取得・導入権限を発行しない。
		for( const int command :
			{IDC_INSTALL, IDC_SELECT_ALL_RECOMMENDED, IDC_CLEAR_SELECTION, IDC_PREPARATION}) {
			DialogState	 rejected{.context	  = &context,
								  .owner	  = handle,
								  .allowError = true} ;	// 空選択の案内だけは閉じる。
			DialogDriver driver( rejected) ;			// 合成commandで開く情報dialogを試験scope内で扱う。
			SendMessageW( handle, WM_COMMAND, static_cast<WPARAM>( command), 0) ;
			DRIVERCRATE_EXPECT( context, !rejected.failed && rejected.errors <= 1U) ;
		}

		DRIVERCRATE_EXPECT( context, state->normalCalls == 0U && state->forbiddenCalls == 0U &&
										state->restoreCalls == 0U && state->planCalls == 0U) ;
	}

	state->scenario = MetadataUiScenario::INFORMATION ;
	state->holdNext = true ;
	beginMetadata( window, context) ;
	DRIVERCRATE_EXPECT( context, pumpUntil( [&] { return state->waiting.load() ; })) ;
	const auto beforeCancel =
		// 同じbuttonで新しい操作を作らないことを確認する。
		state->metadataCalls.load() ;
	SendMessageW( handle, WM_COMMAND, IDC_METADATA_SEARCH, 0) ;
	DRIVERCRATE_EXPECT( context, Access::controller( window).state() ==
									ApplicationState::CANCELLING_METADATA_SEARCH) ;
	DRIVERCRATE_EXPECT( context, IsWindowEnabled( GetDlgItem( handle, IDC_METADATA_SEARCH)) == FALSE) ;
	Access::verifyProgress( window, context) ;
	DRIVERCRATE_EXPECT( context, windowText( GetDlgItem( handle, IDC_STATUS)).find( L"取消し") !=
									std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, captureWindow( handle, L"cancelling")) ;
	state->release.release() ;
	DRIVERCRATE_EXPECT( context, pumpUntil( [&] { return !metadataBusy( window) ; })) ;
	DRIVERCRATE_EXPECT( context,
					   Access::count( window) == 3U && state->metadataCalls == beforeCancel) ;
	Access::verifyDisplayOnly( window, context) ;
	const auto *cancelled =
		// 取消しの部分結果。
		Access::controller( window).metadataSearchSummary() ;
	DRIVERCRATE_EXPECT( context, cancelled != nullptr &&
									cancelled->reason == MetadataSearchReason::CANCELLED) ;
	DRIVERCRATE_EXPECT( context, state->waitTimeouts == 0U && state->normalCalls == 0U) ;

	// 終端後、通常scanを明示開始し、同じbuttonから協調取消しできることを確認する。
	state->holdNextNormal = true ;
	SendMessageW( handle, WM_COMMAND, IDC_SCAN, 0) ;
	DRIVERCRATE_EXPECT( context, pumpUntil( [&] { return state->waiting.load() ; })) ;
	DRIVERCRATE_EXPECT( context, Access::controller( window).state() == ApplicationState::SCANNING) ;
	DRIVERCRATE_EXPECT( context, IsWindowEnabled( GetDlgItem( handle, IDC_SCAN)) != FALSE) ;
	DRIVERCRATE_EXPECT( context, windowText( GetDlgItem( handle, IDC_SCAN)).find( L"取消し") !=
									std::wstring::npos) ;
	SendMessageW( handle, WM_COMMAND, IDC_SCAN, 0) ;
	DRIVERCRATE_EXPECT( context,
					   Access::controller( window).state() == ApplicationState::CANCELLING_SCAN) ;
	DRIVERCRATE_EXPECT( context, IsWindowEnabled( GetDlgItem( handle, IDC_SCAN)) == FALSE) ;
	DRIVERCRATE_EXPECT( context, pumpUntil( [&] {
						   return Access::controller( window).state() !=
								  ApplicationState::CANCELLING_SCAN ;
					   })) ;
	DRIVERCRATE_EXPECT( context, Access::controller( window).state() == ApplicationState::IDLE) ;
	DRIVERCRATE_EXPECT( context, state->normalCalls == 1U && state->normalCancelled == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   windowText( GetDlgItem( handle, IDC_STATUS)).find( L"取り消しました") !=
						   std::wstring::npos) ;

	// 取消し終端から利用者が再度明示した場合だけ通常経路を新しく開始する。
	SendMessageW( handle, WM_COMMAND, IDC_SCAN, 0) ;
	DRIVERCRATE_EXPECT( context, pumpUntil( [&] {
						   return Access::controller( window).state() != ApplicationState::SCANNING ;
					   })) ;
	DRIVERCRATE_EXPECT( context,
					   state->normalCalls == 2U &&
						   Access::controller( window).scanPurpose() == ScanPurpose::STANDARD) ;
	Access::verifyClassGrouping( window, context) ;
	DRIVERCRATE_EXPECT( context, captureWindow( handle, L"device-classes")) ;
	Access::expandClassPreview( window) ;
	DRIVERCRATE_EXPECT( context, captureWindow( handle, L"device-classes-expanded")) ;
	// 旧版の閲覧だけでは選択を変えず、現在構成への明示選択commandは拒否する。
	for( const int entry : {3, 1}) {
		DialogState detail{.context = &context,
						   .owner	= handle,
						   .mode	= DialogMode::DETAILS} ;	// 同deviceの四entryと全体report。
		detail.captureDetails		 = false ;
		detail.detailEntry			 = entry ;
		detail.detailEntryCount		 = 5U ;
		detail.chooseDetailCandidate = entry == 1 ;
		detail.detailSelectable		 = entry != 1 ;
		{
			DialogDriver driver( detail) ;	// 閲覧・拒否の実control通知だけを送る。
			Access::openCandidateDetails( window, 0U, NM_RETURN) ;
		}

		DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed) ;
		Access::verifyDetailChoice( window, context, 2U) ;
	}

	const auto	beforeReport = Access::simpleSelection( window) ;	// 候補指定とcheckの閲覧前snapshot。
	DialogState report{.context = &context,
					   .owner	= handle,
					   .mode	= DialogMode::DETAILS} ;	// 末尾の全体reportを閲覧する。
	report.captureDetails		 = false ;
	report.detailEntry			 = 4 ;
	report.detailEntryCount		 = 5U ;
	report.detailSelectable		 = false ;
	report.chooseDetailCandidate = true ;
	{
		DialogDriver driver( report) ;	// reportへの偽装選択commandも拒否された後に閉じる。
		Access::openCandidateDetails( window, 0U, NM_DBLCLK) ;
	}
	DRIVERCRATE_EXPECT(
		context,
		report.handled && !report.failed && Access::simpleSelection( window) == beforeReport &&
			report.details.find( L"このデバイスだけの検査結果ではありません") != std::wstring::npos) ;
	Access::verifyDetailChoice( window, context, 2U) ;

	DialogState choose{.context = &context,
					   .owner	= handle,
					   .mode	= DialogMode::DETAILS} ;	// 明示選択を確認する同device。
	choose.captureName			 = L"device-candidate-choice" ;
	choose.detailEntry			 = 3 ;
	choose.detailEntryCount		 = 5U ;
	choose.chooseDetailCandidate = true ;
	{
		DialogDriver driver( choose) ;	// 元index3だけを通常button経由で選ぶ。
		Access::openCandidateDetails( window, 0U, NM_DBLCLK) ;
	}

	DRIVERCRATE_EXPECT( context, choose.handled && !choose.failed) ;
	Access::verifyDetailChoice( window, context, 3U) ;
	DialogState ambiguous{.context = &context,
						  .owner   = handle,
						  .mode	   = DialogMode::DETAILS} ;	// 未指定checkboxからの詳細。
	ambiguous.captureDetails		= false ;
	ambiguous.detailEntry			= 2 ;
	ambiguous.detailEntryCount		= 5U ;
	ambiguous.chooseDetailCandidate = true ;
	{
		DialogDriver driver( ambiguous) ;	// 複数候補の一括導入へ変換しない。
		Access::checkAmbiguousDevice( window, context) ;
	}

	DRIVERCRATE_EXPECT( context, ambiguous.handled && !ambiguous.failed) ;
	Access::verifyDetailChoice( window, context, 2U) ;
	Access::verifyClassInstallResults( window, context) ;
	Access::verifyObservations( window, context) ;
	Access::expandClassPreview( window) ;
	DRIVERCRATE_EXPECT( context, captureWindow( handle, L"device-observations")) ;
	// 二つの標準通知で同じread-only境界へ入り、取得・導入commandを生成しない。
	for( std::size_t index = 0U; index < 2U; ++index) {
		DialogState detail{.context = &context,
						   .owner	= handle,
						   .mode	= DialogMode::DETAILS} ;	// 同期dialogの所有値。
		detail.captureName =
			index == 0U ? L"device-observation-details" : L"candidate-assessment-details" ;
		detail.detailEntry		= static_cast<int>( index) ;
		detail.detailSelectable = false ;
		detail.detailEntryCount = 4U ;
		{
			const auto	 before = Access::simpleSelection( window) ;	// 閲覧前の候補指定/check。
			DialogDriver driver( detail) ;								// Read-only本文の検査と終了だけを行う。
			Access::openCandidateDetails( window, index, index == 0U ? NM_RETURN : NM_DBLCLK) ;
			DRIVERCRATE_EXPECT( context, Access::simpleSelection( window) == before) ;
		}
		DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed && detail.errors == 0U) ;
		DRIVERCRATE_EXPECT(
			context,
			detail.details.find( index == 0U ? L"未導入" : L"現時点ではインストールできません") !=
				std::wstring::npos) ;
	}

	DRIVERCRATE_EXPECT( context, state->forbiddenCalls == 0U && state->restoreCalls == 0U) ;
	SendMessageW( handle, WM_CLOSE, 0, 0) ;
	DRIVERCRATE_EXPECT( context, IsWindow( handle) == FALSE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Window closeの非blocking取消し待ちとqueue拒否を確認する。
 * @param[in,out] context Assertion集計先。
 * @param[in] queueOnly 終了待ちではなくqueue拒否だけを独立processで試験する場合true。
 */
//------------------------------------------------------------------------------
void runCloseAndQueue( TestContext &context, const bool queueOnly)
{
	auto	   state = std::make_shared<MetadataUiState>() ;	// 待機だけを注入する合成worker状態。
	MainWindow window ;											// Close動作専用の所有Window。
	Access::configure( window, state) ;
	// Queue拒否試験は独立processの最初のWindowだけで行う。
	if( queueOnly) {
		const bool queueCreated =
			// Fakeだけの独立Window。
			window.create( GetModuleHandleW( nullptr)) ;
		DRIVERCRATE_EXPECT( context, queueCreated) ;
		// 初期化に失敗したWindowへqueue停止やmodal操作を送らない。
		if( !queueCreated) {
			return ;
		}

		ShowWindow( Access::handle( window), SW_SHOWNOACTIVATE) ;
		Access::stopWorker( window) ;
		beginMetadata( window, context, false, true) ;
		DRIVERCRATE_EXPECT( context,
						   Access::controller( window).state() == ApplicationState::FAILURE &&
							   Access::controller( window).metadataSearchSummary() == nullptr &&
							   Access::count( window) == 0U) ;
		SendMessageW( Access::handle( window), WM_CLOSE, 0, 0) ;
		return ;
	}

	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 前のWindow classを再利用する。
	DRIVERCRATE_EXPECT( context, created) ;
	// Windowなしではmodal操作を開始しない。
	if( !created) {
		return ;
	}

	const HWND handle = Access::handle( window) ;	// 破棄待ちを検査する非所有handle。
	ShowWindow( handle, SW_SHOWNOACTIVATE) ;
	state->holdNext = true ;
	beginMetadata( window, context) ;
	DRIVERCRATE_EXPECT( context, pumpUntil( [&] { return state->waiting.load() ; })) ;
	DialogState close{.context = &context,
					  .owner   = handle,
					  .mode	   = DialogMode::CLOSE} ;	// 合成処理の終了だけに同意する。
	{
		DialogDriver driver( close) ;	// 同期MessageBox内のtimer操作。
		SendMessageW( handle, WM_CLOSE, 0, 0) ;
	}
	DRIVERCRATE_EXPECT( context, close.handled && !close.failed) ;
	DRIVERCRATE_EXPECT( context, IsWindow( handle) != FALSE && Access::closePending( window) &&
									Access::controller( window).state() ==
										ApplicationState::CANCELLING_METADATA_SEARCH) ;
	state->release.release() ;
	DRIVERCRATE_EXPECT( context, pumpUntil( [&] { return IsWindow( handle) == FALSE ; })) ;
	DRIVERCRATE_EXPECT( context, state->waitTimeouts == 0U && state->forbiddenCalls == 0U &&
									state->restoreCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同内容表示と別情報の有限八条件を元plan/実詳細へ通します。
 * @param[in,out] context 原失敗を保持する集計先です。
 */
//------------------------------------------------------------------------------
void runHistoryDisplayUiScenarios( TestContext &context)
{
	// 各条件はfresh Windowと元五候補/同planで独立に確認します。
	for( unsigned variant = 0U; variant < 8U; ++variant) {
		MSG previousQuit{} ;	// 前の所有Windowの終了通知だけを消費します。
		// 既成功fixtureと同じく、WM_QUITを次のmodal loopへ持ち越しません。
		while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE) != FALSE) {
		}

		auto	   state = std::make_shared<MetadataUiState>() ;	// 通信/導入の禁止counterです。
		MainWindow window ;											// 同private desktopの所有Windowです。
		Access::configure( window, state) ;
		const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 製品resourceを使います。
		DRIVERCRATE_EXPECT( context, created) ;
		// 存在しないWindowを先頭候補へ補完しません。
		if( !created) {
			return ;
		}

		const auto handle = Access::handle( window) ;	// 所有期間中だけの借用です。
		ShowWindow( handle, SW_SHOWNOACTIVATE) ;
		Access::historyDetails( window, context) ;
		Access::historyDisplayVariant( window, context, variant) ;
		// 結果行の再選択拒否は元の失効状態で確認します。
		if( variant == 7U) {
			Access::historyInvalidate( window, context) ;
		}

		const auto	before = Access::simpleSelection( window) ;	// 元後出memberの指定です。
		DialogState detail{.context = &context,
						   .owner	= handle,
						   .mode	= DialogMode::DETAILS} ;	// 元dialog driverです。
		detail.captureDetails	  = false ;
		detail.detailDisplayProbe = true ;
		detail.detailDistinctInformation =
			variant == 1U || variant == 3U || variant == 5U || variant == 6U ;
		detail.detailEntry			 = variant == 4U || variant == 7U ? 2 : 1 ;
		detail.detailInitialEntry	 = variant == 0U ? 1 : variant == 4U ? -1 : 2 ;
		detail.detailEntryCount		 = variant == 0U ? 3U : 4U ;
		detail.detailSelectable		 = variant != 4U && variant != 7U ;
		detail.chooseDetailCandidate = variant == 0U || variant == 4U || variant == 7U ;
		{
			DialogDriver driver( detail) ;	// 閲覧または元一候補への明示buttonだけです。
			Access::openCandidateDetails( window, 1U, variant % 2U == 0U ? NM_DBLCLK : NM_RETURN) ;
		}
		DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
										Access::simpleSelection( window) == before) ;
		DRIVERCRATE_EXPECT( context, state->forbiddenCalls == 0U && state->restoreCalls == 0U &&
										state->normalCalls == 0U) ;
		SendMessageW( handle, WM_CLOSE, 0, 0) ;
		DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
	}

	std::cout
		<< "DISPLAY_IDENTITY_UI cases=8 originalCandidates=5 originalPlan=1 network=0 install=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 準備不成立後の全device/元参照/開閉と実行拒否を有限確認します。
 * @param[in,out] context 原assertionの集計先です。
 */
//------------------------------------------------------------------------------
void runPreparationFailureUiScenarios( TestContext &context)
{
	// 九つの固定原因だけを別Windowへ送り、実取得や実導入は行いません。
	for( unsigned variant{}; variant < 9U; ++variant) {
		MSG previousQuit{} ;	// 前Windowの通常終了通知だけを消費します。
		// WM_QUITを次のmodal driverへ持ち越しません。
		while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
		}

		auto	   state = std::make_shared<MetadataUiState>() ;	// 禁止された実経路を監視します。
		MainWindow window ;											// 所有UIとworkerは各ケースだけの寿命です。
		Access::configure( window, state) ;
		const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 実resourceのcontrolです。
		DRIVERCRATE_EXPECT( context, created) ;
		// 作成失敗をWindow試験成功として続けません。
		if( !created) {
			continue ;
		}

		const auto handle = Access::handle( window) ;	// 同private desktopの実HWNDです。
		ShowWindow( handle, SW_SHOWNOACTIVATE) ;
		Access::preparationFailure( window, context, variant) ;
		const auto	before = Access::simpleSelection( window) ;	// 閲覧で変更しない元選択です。
		// 元参照のreadonly初期highlightを実dialogで確認します。
		DialogState detail{.context = &context, .owner = handle, .mode = DialogMode::DETAILS} ;
		detail.captureDetails		 = false ;
		detail.detailInitialEntry	 = 1 ;
		detail.detailEntry			 = 1 ;
		detail.detailEntryCount		 = 5U ;
		detail.detailSelectable		 = false ;
		detail.chooseDetailCandidate = true ;
		{
			DialogDriver driver( detail) ;	// 元参照はhighlightだけでChooseを拒否します。
			Access::openCandidateDetails( window, 1U, NM_RETURN) ;
		}
		DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
										Access::simpleSelection( window) == before) ;
		Access::retainedCheckboxInput( window, context, variant) ;
		DialogState result{.context = &context,
						   .owner	= handle,
						   .mode	= DialogMode::INDEX_INSTALL_RESULT} ;	// 元結果案内だけです。
		{
			DialogDriver driver( result) ;	// 実driverを呼ばない人工終端だけを閉じます。
			Access::retainedCheckboxTerminal( window, context, variant) ;
		}
		DRIVERCRATE_EXPECT( context, result.handled && !result.failed) ;
		Access::preparationFailureReset( window, context) ;
		DRIVERCRATE_EXPECT( context, state->forbiddenCalls == 0U && state->restoreCalls == 0U &&
										state->normalCalls == 0U) ;
		SendMessageW( handle, WM_CLOSE, 0, 0) ;
		DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
		std::cout << "PREPARATION_FAILURE_UI case=" << variant << " network=0 install=0\n" ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 製品loggerと実status/結果dialogを非通信fixtureへ接続します。
 * @param[in,out] context 元assertion集計先です。
 * @param[in] failed 固定writer失敗を注入する場合trueです。
 */
//------------------------------------------------------------------------------
void runDiagnosticUiScenarios( TestContext &context, const bool failed)
{
	startLocalDiagnostics() ;
	DRIVERCRATE_EXPECT( context, pumpUntil( [] { return localDiagnosticStatus().startupFlushed ; })) ;
	// 自己所有の試験EXE隣writerだけに失敗を与えます。
	if( failed) {
		local_diagnostic_detail::Access::failProcess( DiagnosticStorageStage::WRITE) ;
		recordLocalDiagnostic( DiagnosticRecord{}) ;
		DRIVERCRATE_EXPECT( context, pumpUntil( [] {
							   return localDiagnosticStatus().state ==
									  DiagnosticStorageState::FAILED ;
						   })) ;
	}

	MSG previousQuit{} ;	// 既成功手順で前の終了通知を消費します。
	// 製品のWM_QUIT発行は変えません。
	while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
	}

	auto	   state = std::make_shared<MetadataUiState>() ;	// 実Providerを禁止するcounterです。
	MainWindow window ;											// 同private desktopの所有Windowです。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 製品と同じresourceです。
	DRIVERCRATE_EXPECT( context, created) ;
	// 不存在controlを試験済みにしません。
	if( !created) {
		stopLocalDiagnostics() ;
		return ;
	}

	const auto handle = Access::handle( window) ;	// Fixture所有の実HWNDです。
	Access::historyDetails( window, context) ;
	Access::historyLocalScan( window, context) ;
	const std::array identities{
		std::wstring{L"history-local-old"}} ;	// 元local fixtureの候補だけです。
	Access::selectIndexCandidates( window, context, identities) ;
	Access::diagnosticStatus( window, context, failed) ;
	const auto	before = Access::simpleSelection( window) ;	// 診断で選択を変えません。
	DialogState cancelled{.context = &context,
						  .owner   = handle,
						  .mode =
							  DialogMode::INDEX_INSTALL_CANCEL} ;	// 元の旧版最終確認を取り消します。
	{
		DialogDriver driver( cancelled) ;	// 実Appの要求eventを確認し、実行しません。
		Access::beginIndexInstallCommand( window) ;
	}
	DRIVERCRATE_EXPECT( context, cancelled.handled && !cancelled.failed &&
									Access::simpleSelection( window) == before) ;
	DialogState display{.context = &context,
						.owner	 = handle,
						.mode	 = DialogMode::INDEX_INSTALL_RESULT} ;	// 元結果dialogを確認します。
	{
		DialogDriver driver( display) ;	// APIは呼ばない合成終端だけです。
		Access::diagnosticResult( window, context) ;
	}
	DRIVERCRATE_EXPECT( context, display.handled && !display.failed &&
									display.details.find( L"匿名診断") != std::wstring::npos) ;
	// 診断失敗でもdriverの元成功messageを改作していません。
	DRIVERCRATE_EXPECT( context,
					   display.details.find( L"インストールしました") != std::wstring::npos &&
						   state->forbiddenCalls == 0U && state->restoreCalls == 0U &&
						   state->normalCalls == 0U) ;
	SendMessageW( handle, WM_CLOSE, 0, 0) ;
	DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
	stopLocalDiagnostics() ;
	const auto storage = localDiagnosticStatus() ;	// 通常終了の実保存状態です。
	DRIVERCRATE_EXPECT( context, storage.startupFlushed &&
									(failed ? storage.state == DiagnosticStorageState::FAILED &&
												  storage.code == ERROR_WRITE_FAULT
											: storage.state == DiagnosticStorageState::STOPPED &&
												  storage.pending == 0U && storage.saved > 10U)) ;
	std::cout << "DIAGNOSTIC_UI failed=" << failed << " startupFlushed=" << storage.startupFlushed
			  << " saved=" << storage.saved << " pending=" << storage.pending
			  << " dropped=" << storage.dropped << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最新候補の初期閲覧と元一件選択の非干渉を有限条件で確認します。
 * @param[in,out] context 原失敗を保持する集計先です。
 */
//------------------------------------------------------------------------------
void runHistoryLatestUiScenarios( TestContext &context)
{
	constexpr std::array<int, 18> initialRows{2, 1, 1, 2, 2,  0, 0, 0, 2,
											  0, 2, 2, 0, -1, 3, 1, 1, 1} ;	// 独立した期待位置です。
	// 一条件一Windowで元WM_QUITを持ち越しません。
	for( unsigned variant = 0U; variant < initialRows.size(); ++variant) {
		MSG previousQuit{} ;	// 前の所有Windowの終了通知だけです。
		// 781で確認済みの成功手順を再利用します。
		while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
		}

		auto state = std::make_shared<MetadataUiState>() ;	// 実通信/導入を禁止するcounterです。
		MainWindow window ;									// この条件だけの所有Windowです。
		Access::configure( window, state) ;
		const bool created =
			// 製品と同じ標準controlです。
			window.create( GetModuleHandleW( nullptr)) ;
		DRIVERCRATE_EXPECT( context, created) ;
		// 存在しないWindowへ候補を補完しません。
		if( !created) {
			return ;
		}

		const auto handle = Access::handle( window) ;	// Modalより長く生存します。
		ShowWindow( handle, SW_SHOWNOACTIVATE) ;
		Access::historyDetails( window, context) ;
		Access::historyLatestVariant( window, context, variant) ;
		// 結果と失効は元controllerの終端状態を使います。
		if( variant == 11U || variant == 12U) {
			Access::historyInvalidate( window, context) ;
		}

		const auto before =
			// 初期highlight前の実checkbox集合です。
			Access::simpleSelection( window) ;
		DialogState detail{.context = &context,
						   .owner	= handle,
						   .mode	= DialogMode::DETAILS} ;	// 元実dialogの操作だけです。
		detail.captureDetails		 = false ;
		detail.detailExpectNoInitial = variant == 13U ;
		detail.detailInitialEntry	 = initialRows[variant] ;
		detail.detailEntry			 = variant == 13U ? 1 : initialRows[variant] ;
		detail.detailEntryCount = variant == 10U ? 5U : variant == 13U || variant == 17U ? 3U : 4U ;
		detail.detailSelectable = variant == 0U || variant == 1U || variant == 2U ||
								  variant == 3U || variant == 4U || variant == 8U ||
								  variant == 10U || variant == 13U || variant == 15U ||
								  variant == 16U || variant == 17U ;
		{
			DialogDriver driver( detail) ;	// 閲覧/手動行移動だけでbuttonを押しません。
			Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
		}
		DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
										Access::simpleSelection( window) == before) ;
		// 最新行の明示buttonだけで元一候補が確定し、再表示でも維持します。
		if( variant == 0U) {
			detail.handled				 = false ;
			detail.ticks				 = 0U ;
			detail.chooseDetailCandidate = true ;
			{
				DialogDriver driver( detail) ;	// 元index2だけを明示指定します。
				Access::openCandidateDetails( window, 1U, NM_RETURN) ;
			}
			const auto chosen = Access::simpleSelection( window) ;	// 他deviceの選択を保持します。
			// 後続のrow結合も含むsnapshot長を保持し、checkboxの先頭二件を照合します。
			DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
											chosen.size() == before.size() && chosen.size() >= 2U &&
											chosen[0] == 2U && chosen[1] == 4U) ;
			detail.handled				 = false ;
			detail.ticks				 = 0U ;
			detail.chooseDetailCandidate = false ;
			{
				DialogDriver driver( detail) ;	// 明示した元候補の再表示です。
				Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
			}
			DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
											Access::simpleSelection( window) == chosen) ;
		}

		DRIVERCRATE_EXPECT( context, state->forbiddenCalls == 0U && state->restoreCalls == 0U &&
										state->normalCalls == 0U) ;
		SendMessageW( handle, WM_CLOSE, 0, 0) ;
		DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
	}

	std::cout
		<< "LATEST_HIGHLIGHT_UI cases=18 originalPlan=1 beforeChooseSelectionUnchanged=1 network=0 install=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同device新版/旧版の実詳細を元planから開く限定回帰です。
 * @param[in,out] context 初回期待失敗も保持する元集計先です。
 * @param[in] keysOnly trueなら失敗後のkeyboard診断だけへ限定します。
 */
//------------------------------------------------------------------------------
void runHistoryUiScenarios( TestContext &context, const bool keysOnly = false)
{
	std::cout << std::unitbuf ;
	std::cerr << std::unitbuf ;
	std::cout << "HISTORY_STAGE begin\n" ;
	auto state = std::make_shared<MetadataUiState>() ;	// 実Provider fallbackを禁止するcounterです。
	MainWindow window ;									// 同private desktopの所有Windowです。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 実product resourceです。
	DRIVERCRATE_EXPECT( context, created) ;
	// 不存在windowを試験成功へ読み替えません。
	if( !created) {
		return ;
	}

	const auto handle = Access::handle( window) ;	// 同processが所有する実HWNDです。
	ShowWindow( handle, SW_SHOWNOACTIVATE) ;
	std::cout << "HISTORY_STAGE window-created\n" ;
	DialogState setupGuard{
		.context = &context,
		.owner	 = handle,
		.mode = DialogMode::INDEX_PREPARATION_ACCEPT} ;	// 元setupの想定外modalを同意せず閉じます。
	setupGuard.twoStep	  = true ;
	setupGuard.rejectEula = true ;
	{
		DialogDriver guard( setupGuard) ;	// 有限監督だけを元正常scanへ付けます。
		Access::historyDetails( window, context) ;
	}
	std::cout << "HISTORY_STAGE scan-ready modal=" << setupGuard.handled
			  << " failure=" << setupGuard.failed << "\n" ;
	DRIVERCRATE_EXPECT( context, !setupGuard.handled && !setupGuard.failed) ;
	// 画像専用入口は負例probeの前に通常の新版候補を表示して終了します。
	if( historyImagesOnly) {
		// 既checkboxの通常handlerで表示copyの版と検索結果の案内を同期します。
		SendMessageW( handle, WM_COMMAND, IDC_RECOMMENDED_ONLY, 0) ;
		Access::expandClassPreview( window) ;
		DRIVERCRATE_EXPECT( context, IsWindowEnabled( GetDlgItem( handle, IDC_INSTALL)) != FALSE) ;
#if !defined( _DEBUG)
		DRIVERCRATE_EXPECT( context, captureWindow( handle, L"device-list-ready", true)) ;
#endif
		DialogState sample{.context = &context,
						   .owner	= handle,
						   .mode	= DialogMode::DETAILS} ;	// 同じ元planの通常dialogです。
		sample.detailEntry		= 1 ;
		sample.detailEntryCount = 4U ;
		sample.detailSelectable = true ;
		sample.captureName		= L"history-table-normal" ;
#if defined( _DEBUG)
		sample.captureDetails = false ;
#endif
		{
			DialogDriver driver( sample) ;	// 閲覧を閉じ、導入や候補の適用は行いません。
			Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
		}
		DRIVERCRATE_EXPECT( context, sample.handled && !sample.failed) ;
		SendMessageW( handle, WM_CLOSE, 0, 0) ;
		DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
		return ;
	}

	const auto	before = Access::simpleSelection( window) ;	// 元別deviceの選択も保持します。
	DialogState restricted{
		.context = &context, .owner = handle, .mode = DialogMode::DETAILS} ;	// filter ONです。
	restricted.captureDetails		 = false ;
	restricted.historyTableProbe	 = true ;
	restricted.detailEntry			 = 2 ;
	restricted.detailEntryCount		 = 4U ;
	restricted.detailSelectable		 = false ;
	restricted.chooseDetailCandidate = true ;
	{
		DialogDriver driver( restricted) ;	// readonly行への偽装commandも元guardへ渡します。
		Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
	}
	DRIVERCRATE_EXPECT( context, restricted.handled && !restricted.failed &&
									Access::simpleSelection( window) == before) ;
	Access::historyShowAll( window) ;
	DialogState all{.context = &context,
					.owner	 = handle,
					.mode	 = DialogMode::DETAILS} ;	// 同じ原候補のfilter OFFです。
	all.captureDetails		  = false ;
	all.historyTableProbe	  = true ;
	all.detailEntry			  = 2 ;
	all.detailEntryCount	  = 4U ;
	all.detailSelectable	  = true ;
	all.chooseDetailCandidate = true ;
#if !defined( _DEBUG)
	all.captureDetails = historyImagesOnly ;
	all.captureName	   = L"history-table-normal" ;
#endif
	{
		DialogDriver driver( all) ;	// 実buttonから旧版一候補を明示指定します。
		Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
	}
	DRIVERCRATE_EXPECT( context, all.handled && !all.failed) ;
	const auto chosen = Access::simpleSelection( window) ;	// 一候補と別deviceの指定を確認します。
	DRIVERCRATE_EXPECT( context, chosen.size() >= 2U && chosen[0] == 2U && chosen[1] == 4U) ;
	// Key限定入口では成功済み画像/閲覧matrixを反復しません。
	if( !keysOnly) {
		DialogState narrow{.context = &context,
						   .owner	= handle,
						   .mode	= DialogMode::DETAILS} ;	// 同じ元choiceの狭幅です。
		narrow.captureDetails	  = false ;
		narrow.historyTableProbe  = true ;
		narrow.detailNarrow		  = true ;
		narrow.detailInitialEntry = 2 ;
		narrow.detailEntry		  = 2 ;
		narrow.detailEntryCount	  = 4U ;
#if !defined( _DEBUG)
		narrow.captureDetails = false ;
		narrow.captureName	  = L"history-table-narrow" ;
#endif
		{
			DialogDriver driver( narrow) ;	// 閲覧だけで選択を保ちます。
			Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
		}
		DRIVERCRATE_EXPECT( context, narrow.handled && !narrow.failed &&
										Access::simpleSelection( window) == chosen) ;
		// 画像専用processは二枚と所有終端だけを確認し、成立済み全caseを反復しません。
		if( historyImagesOnly) {
			SendMessageW( handle, WM_CLOSE, 0, 0) ;
			DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
			return ;
		}

		// 現在/新版/reportの閲覧とreadonly command拒否を同じ元planで確認します。
		for( const int entry : {0, 1, 3}) {
			DialogState detail{.context = &context,
							   .owner	= handle,
							   .mode	= DialogMode::DETAILS} ;	// 対象は同deviceだけです。
			detail.captureDetails		 = false ;
			detail.detailEntry			 = entry ;
			detail.detailEntryCount		 = 4U ;
			detail.detailSelectable		 = entry == 1 ;
			detail.chooseDetailCandidate = entry != 1 ;
			{
				DialogDriver driver( detail) ;	// 元real controlだけを操作します。
				Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
			}
			DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
											Access::simpleSelection( window) == chosen) ;
			// 全体結果の実失敗状態と原数値を汎用readonly文だけへ失わせません。
			if( entry == 3) {
				DRIVERCRATE_EXPECT( context,
								   detail.details.find( L"取得失敗") != std::wstring::npos &&
									   detail.details.find( L"0x80070005") != std::wstring::npos) ;
			}
		}
	}

	// Enterは選択せず、Alt+SとSpaceは同device一候補だけを明示指定します。
	for( unsigned key = 0; key < 3U; ++key) {
		DialogState detail{.context = &context,
						   .owner	= handle,
						   .mode	= DialogMode::DETAILS} ;	// 標準keyboardの一操作です。
		detail.captureDetails		= false ;
		detail.detailEntry			= key == 2U ? 2 : 1 ;
		detail.detailEntryCount		= 4U ;
		detail.detailEnterClose		= key == 0U ;
		detail.detailApplyAccessKey = key == 1U ;
		detail.detailApplySpace		= key == 2U ;
		{
			// 同dialogだけを有限に操作する元監督です。
			DialogDriver driver( detail) ;
			Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
		}
		const auto selection = Access::simpleSelection( window) ;	// 最終button結果の実照合です。
		std::cout << "HISTORY_KEY key=" << key << " handled=" << detail.handled
				  << " failed=" << detail.failed << " size=" << selection.size()
				  << " first=" << (selection.empty() ? 9999U : selection[0])
				  << " second=" << (selection.size() < 2U ? 9999U : selection[1]) << "\n" ;
		DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed && selection.size() >= 2U &&
										selection[0] == (key == 1U ? 1U : 2U) &&
										selection[1] == 4U) ;
	}

	// Key限定診断は同じ元Windowの所有終端を確認して返します。
	if( keysOnly) {
		SendMessageW( handle, WM_CLOSE, 0, 0) ;
		DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
		return ;
	}

	// 同版/未知も手選択でき、計画にない参照は閲覧だけです。
	for( unsigned variant = 0; variant < 3U; ++variant) {
		Access::historyVariant( window, variant) ;
		const auto	unchanged = Access::simpleSelection( window) ;	// 閲覧前の全deviceです。
		// 同じ元参照だけを閲覧するdialog操作です。
		DialogState detail{.context = &context, .owner = handle, .mode = DialogMode::DETAILS} ;
		detail.captureDetails		 = false ;
		detail.detailEntry			 = 2 ;
		detail.detailEntryCount		 = 4U ;
		detail.detailSelectable		 = variant != 2U ;
		detail.chooseDetailCandidate = variant == 2U ;
		{
			// 同dialogだけを有限に操作する元監督です。
			DialogDriver driver( detail) ;
			Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
		}
		DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
										Access::simpleSelection( window) == unchanged) ;
		DRIVERCRATE_EXPECT(
			context, detail.details.find( variant == 0U	 ? L"同じ申告バージョン"
										 : variant == 1U ? L"新旧比較は未確認"
														 : L"現時点ではインストールできません") !=
						 std::wstring::npos) ;
	}

	Access::historyVariant( window, 3U) ;
	Access::historyPreparedBlock( window, context) ;
	// 非適合の元scan候補は一覧/詳細に残しても、command偽装で選択しません。
	{
		// 想定外のscan警告を同意せず閉じる監督状態です。
		DialogState guard{
			.context = &context, .owner = handle, .mode = DialogMode::INDEX_PREPARATION_ACCEPT} ;
		guard.twoStep	 = true ;
		guard.rejectEula = true ;
		// 同dialogだけを有限に操作する元監督です。
		DialogDriver driver( guard) ;
		Access::historyLocalScan( window, context, true) ;
		DRIVERCRATE_EXPECT( context, !guard.handled && !guard.failed) ;
	}
	// 非適合候補への偽装選択commandを確認する状態です。
	DialogState rejected{.context = &context, .owner = handle, .mode = DialogMode::DETAILS} ;
	rejected.captureDetails		   = false ;
	rejected.detailEntry		   = 1 ;
	rejected.detailEntryCount	   = 3U ;
	rejected.detailSelectable	   = false ;
	rejected.chooseDetailCandidate = true ;
	{
		// 同dialogだけを有限に操作する元監督です。
		DialogDriver driver( rejected) ;
		Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
	}
	DRIVERCRATE_EXPECT( context,
					   rejected.handled && !rejected.failed &&
						   rejected.details.find( L"適用条件を満たさない") != std::wstring::npos) ;
	// 検査済み旧版の最終警告を明示NOで取消し、実worker/復元点へ進みません。
	{
		DialogState guard{.context = &context,
						  .owner   = handle,
						  .mode = DialogMode::INDEX_PREPARATION_ACCEPT} ;	// Scan失敗の有限監督です。
		guard.twoStep	 = true ;
		guard.rejectEula = true ;
		// 同dialogだけを有限に操作する元監督です。
		DialogDriver driver( guard) ;
		Access::historyLocalScan( window, context) ;
		DRIVERCRATE_EXPECT( context, !guard.handled && !guard.failed) ;
	}
	DialogState local{.context = &context,
					  .owner   = handle,
					  .mode	   = DialogMode::DETAILS} ;	// 元有効Windows候補です。
	local.captureDetails		= false ;
	local.detailEntry			= 1 ;
	local.detailEntryCount		= 3U ;
	local.chooseDetailCandidate = true ;
	{
		// 同dialogだけを有限に操作する元監督です。
		DialogDriver driver( local) ;
		Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
	}
	DRIVERCRATE_EXPECT( context, local.handled && !local.failed) ;
	DialogState cancel{.context = &context,
					   .owner	= handle,
					   .mode	= DialogMode::INDEX_INSTALL_CANCEL} ;	// 既最終dialogを取消します。
	{
		// 同dialogだけを有限に操作する元監督です。
		DialogDriver driver( cancel) ;
		SendMessageW( handle, WM_COMMAND, IDC_INSTALL, 0) ;
	}
	DRIVERCRATE_EXPECT( context,
					   cancel.handled && !cancel.failed &&
						   cancel.details.find( L"古いバージョンへの切替") != std::wstring::npos) ;
	Access::historyInvalidate( window, context) ;
	DialogState stale{.context = &context,
					  .owner   = handle,
					  .mode	   = DialogMode::DETAILS} ;	// 失効した同じ旧表示です。
	stale.captureDetails		= false ;
	stale.detailEntry			= 1 ;
	stale.detailEntryCount		= 3U ;
	stale.detailSelectable		= false ;
	stale.chooseDetailCandidate = true ;
	{
		// 同dialogだけを有限に操作する元監督です。
		DialogDriver driver( stale) ;
		Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
	}
	DRIVERCRATE_EXPECT( context, stale.handled && !stale.failed &&
									stale.details.find( L"失効しています") != std::wstring::npos) ;

	DRIVERCRATE_EXPECT( context, state->forbiddenCalls == 0U && state->restoreCalls == 0U &&
									state->normalCalls == 0U && state->metadataCalls == 0U) ;
	SendMessageW( handle, WM_CLOSE, 0, 0) ;
	DRIVERCRATE_EXPECT( context, !IsWindow( handle)) ;
	std::cout << "HISTORY_TABLE originalPlan=1 sameDeviceNewOld=1 driverHttp=0 install=0\n" ;
	runHistoryDisplayUiScenarios( context) ;
	runHistoryLatestUiScenarios( context) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 初回参照の実worker/元planをfresh private Windowのtableへ接続します。
 * @param[in,out] context 元集計先です。
 */
//------------------------------------------------------------------------------
void runHistoryInitialUiScenarios( TestContext &context)
{
	std::cout << std::unitbuf ;						// 段階到達だけを原pipeへ直ちに保持します。
	auto input = makeSignedIndexUiInput( false) ;	// 既隔離software鍵の人工索引です。
	std::cout << "HISTORY_INITIAL stage=input\n" ;
	auto bound = makeSignedIndexBindingWorker(
		input.services, input.zip, false, false, false,
		SignedIndexBindingNativeCase::INITIAL) ;		// 全Windows依存は既低位fakeです。
	auto state = std::make_shared<MetadataUiState>() ;	// 実Provider fallbackの拒否counterです。
	MainWindow window ;									// このprivate子だけのfresh Windowです。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 同じ製品resourceです。
	DRIVERCRATE_EXPECT( context, created) ;
	// Windowが作れなければ実modalを待たず元workerを停止します。
	if( !created) {
		bound.worker->stop() ;
		return ;
	}

	const HWND handle = Access::handle( window) ;	// 同processの所有HWNDです。
	Access::attachIndexWorker( window, std::move( bound.worker)) ;
	std::cout << "HISTORY_INITIAL stage=attached\n" ;
	DialogState guard{.context = &context,
					  .owner   = handle,
					  .mode =
						  DialogMode::INDEX_PREPARATION_ACCEPT} ;	// 想定外modalだけを拒否します。
	guard.twoStep	 = true ;
	guard.rejectEula = true ;
	{
		DialogDriver driver( guard) ;	// 同start/dispatchだけの有限監督です。
		Access::beginIndexScan( window) ;
		std::cout << "HISTORY_INITIAL stage=begin\n" ;
		auto scanned = Access::takeIndexTerminal(
			window, WorkerEventKind::SCAN_COMPLETED) ;	// 同原workerの終端です。
		DRIVERCRATE_EXPECT( context,
						   scanned && scanned->scanResult.succeeded && scanned->preparationPlan) ;
		std::cout << "HISTORY_INITIAL stage=terminal present=" << scanned.has_value() << "\n" ;
		// 元成功/計画がない入力を手製の候補へ補完しません。
		if( scanned && scanned->scanResult.succeeded && scanned->preparationPlan) {
			Access::dispatchIndex( window, *scanned) ;
		}
	}
	DRIVERCRATE_EXPECT( context, !guard.handled && !guard.failed) ;
	DialogState initial{.context = &context,
						.owner	 = handle,
						.mode	 = DialogMode::DETAILS} ;	// 元初回参照だけを閲覧します。
	initial.captureDetails	 = false ;
	initial.detailEntry		 = 1 ;
	initial.detailEntryCount = 3U ;
	initial.detailSelectable = true ;
	{
		DialogDriver driver( initial) ;	// 当該tableのbutton可否を確認します。
		Access::openCandidateDetails( window, 1U, NM_DBLCLK) ;
	}
	DRIVERCRATE_EXPECT( context, initial.handled && !initial.failed &&
									initial.details.find( L"初回の候補") != std::wstring::npos) ;
	Access::stopWorker( window) ;
	DRIVERCRATE_EXPECT( context, bound.observe().installs == 0U && bound.observe().stages == 0U &&
									bound.allNativeHandlesClosed()) ;
	DestroyWindow( handle) ;
	DRIVERCRATE_EXPECT( context, !IsWindow( handle) && state->forbiddenCalls == 0U &&
									state->restoreCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本物MainWindowの索引結果受入を隠した標準controlで検証します。
 * @param[in,out] context Assertion集計先。
 * @note Fake workerとHWNDは例外時も停止・破棄し、実Providerへfallbackしません。
 */
//------------------------------------------------------------------------------
void runIndexUiScenarios( TestContext &context)
{
	auto	   state = std::make_shared<MetadataUiState>() ;	// 呼出しなしを確認する既存fake状態。
	MainWindow window ;											// 内部factory以外を持たない本物画面。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 製品と同じresource。
	DRIVERCRATE_EXPECT( context, created) ;
	// Windowがない状態を索引受入として数えません。
	if( !created) {
		return ;
	}

	const HWND handle = Access::handle( window) ;	// 本scopeだけの非所有handle。
	ShowWindow( handle, SW_HIDE) ;
	try {
		Access::verifyIndexSummaryCases( window, context) ;
		Access::verifyRefreshTimeReason( window, context) ;
		Access::verifyIndexDelays( window, context) ;
	} catch( ...) {
		Access::stopWorker( window) ;
		// 例外でも試験Windowを残さず、元例外はmainへ返します。
		if( IsWindow( handle) != FALSE) {
			DestroyWindow( handle) ;
		}

		throw ;
	}

	// 前提失敗でも生存Windowを停止・回収します。
	if( IsWindow( handle) != FALSE) {
		Access::stopWorker( window) ;
		DestroyWindow( handle) ;
	}

	DRIVERCRATE_EXPECT( context, state->normalCalls == 0U && state->metadataCalls == 0U &&
									state->officialCalls == 0U && state->restoreCalls == 0U &&
									state->planCalls == 0U && state->forbiddenCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, state->waitTimeouts == 0U && IsWindow( handle) == FALSE) ;
	std::cout
		<< "Index UI fixture: hidden window, fake calls0, real network/inventory/restore/install0, candidate success0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定refresh・実隔離commit・queue・通常画面を五条件で確認します。
 * @param[in,out] context 旧assertionを保持する集計先です。
 * @note HTTPは完全fakeのP4回帰と分離し、この群は実隔離storeのworker接続です。
 */
//------------------------------------------------------------------------------
void runRefreshUiScenarios( TestContext &context)
{
	const auto originalAssertions = context.assertionCount() ;	// 旧五caseだけの開始分母です。
	const auto originalFailures	  = context.failureCount() ;	// 新六caseと分ける原失敗数です。
	// 元T01と追加W02/03/04/07/08/09を一Windowずつ直列に通します。
	for( unsigned mode = 0U; mode < 5U; ++mode) {
		const auto before = context.failureCount() ;	// 固定caseの開始失敗数です。
		MSG		   previous{} ;							// 前fixtureの終了通知を次へ持ち込みません。
		// 前Windowだけが残したWM_QUITを消費します。
		while( PeekMessageW( &previous, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE) != FALSE) {
		}

		auto input = makeSignedIndexUiInput(
			false, false, false, false, false, false,
			SignedIndexUiOptions{.deferredRefresh = mode != 2U}) ;		// P5だけ空storeから開始します。
		auto entered   = std::make_shared<std::atomic_bool>( false) ;	// Close barrierです。
		auto cancelled = std::make_shared<std::atomic_bool>( false) ;	// 同workerが観測した停止です。
		// 暗号拒否は他Providerの正常scanと別に保持します。
		if( mode == 1U) {
			input.services.refresh = []( const ProviderScanCancellation &) {
				return IndexRefreshSummary{.status = IndexRefreshStatus::MANIFEST_REJECTED,
										   .error  = static_cast<NativeError>( E_ACCESSDENIED)} ;
			} ;
		}

		// 明示cache観測後も実隔離storeの原byteを現在UTCでreloadします。
		if( mode == 2U) {
			input.services.refresh = []( const ProviderScanCancellation &) {
				return IndexRefreshSummary{.status	   = IndexRefreshStatus::AUTHENTICATED_CACHE,
										   .error	   = static_cast<NativeError>( E_FAIL),
										   .httpError  = static_cast<NativeError>( E_FAIL),
										   .httpStatus = 503U,
										   .usedAuthenticatedCache = true} ;
			} ;
		}

		// WM_CLOSEは同operationの協調信号でだけ有限な受信待ちを停止します。
		if( mode == 4U) {
			input.services.refresh = [entered, cancelled]( const ProviderScanCancellation &cancel) {
				entered->store( true) ;
				const auto deadline = std::chrono::steady_clock::now() +
									  std::chrono::seconds{3} ;	// Fixtureだけの有限待機です。
				// 取消しまたは固定期限までだけ待機します。
				while( !(cancel && cancel()) && std::chrono::steady_clock::now() < deadline) {
					std::this_thread::sleep_for( std::chrono::milliseconds{1}) ;
				}

				cancelled->store( cancel && cancel()) ;
				return IndexRefreshSummary{.status = cancelled->load()
														 ? IndexRefreshStatus::CANCELLED
														 : IndexRefreshStatus::TIMED_OUT} ;
			} ;
		}

		auto bound = makeSignedIndexBindingWorker( std::move( input.services),
												  input.zip) ;	// 全低位APIはfakeです。
		DRIVERCRATE_EXPECT( context, bound.worker != nullptr) ;
		// Worker生成失敗をcaseの成功へ数えません。
		if( !bound.worker) {
			continue ;
		}

		auto	   state = std::make_shared<MetadataUiState>() ;	// 誤った製品fallbackを検出します。
		MainWindow window ;											// 本物resource/queue/controllerだけを使います。
		Access::configure( window, state) ;
		const bool created = window.create( GetModuleHandleW( nullptr)) ;	// Fixture所有HWNDです。
		DRIVERCRATE_EXPECT( context, created) ;
		// HWNDなしでは所有workerを停止します。
		if( !created) {
			bound.worker->stop() ;
			continue ;
		}

		const HWND handle = Access::handle( window) ;	// このscopeの非所有handleです。
		ShowWindow( handle, SW_SHOWNOACTIVATE) ;
		Access::attachIndexWorker( window, std::move( bound.worker)) ;
		// 明示無効なら同registry IDの索引だけを除きます。
		if( mode == 3U) {
			Access::disableIndex( window) ;
		}

		Access::beginIndexScan( window) ;
		// Fetch中の実WM_CLOSEを確認してから元終端をdispatchします。
		if( mode == 4U) {
			DRIVERCRATE_EXPECT( context, pumpUntil( [&] { return entered->load() ; })) ;
			DialogState close{.context = &context,
							  .owner   = handle,
							  .mode	   = DialogMode::CLOSE} ;	// Fixture停止へのYESです。
			{
				DialogDriver driver( close) ;	// 同fixtureの終了確認だけを操作します。
				SendMessageW( handle, WM_CLOSE, 0, 0) ;
			}
			DRIVERCRATE_EXPECT( context, close.handled && !close.failed) ;
		}

		auto scanned =
			// 原queue終端です。
			Access::takeIndexTerminal( window, WorkerEventKind::SCAN_COMPLETED) ;
		DRIVERCRATE_EXPECT( context, scanned.has_value()) ;
		// 未到達は後段の候補表示で補完しません。
		if( scanned) {
			const auto observation = input.observeRefresh() ;	// Terminalで同期した非atomic観測です。
			// 空storeから実commit/reloadした場合だけ一関係を発行します。
			if( mode == 0U) {
				DRIVERCRATE_EXPECT( context, scanned->indexSummary.refresh &&
												scanned->indexSummary.refresh->status ==
													IndexRefreshStatus::REFRESHED &&
												scanned->preparationPlan &&
												scanned->preparationPlan->targets.size() == 1U) ;
				DRIVERCRATE_EXPECT( context,
								   observation == (std::array<std::uint32_t, 4U>{1U, 1U, 1U, 1U})) ;
			}

			// 索引拒否と他Provider成功を同時に残します。
			if( mode == 1U) {
				DRIVERCRATE_EXPECT( context, scanned->scanResult.succeeded &&
												scanned->indexSummary.status ==
													IndexScanStatus::LOAD_REJECTED &&
												observation[1] == 0U) ;
			}

			// 明示cacheも候補0から最新へ昇格しません。
			if( mode == 2U) {
				DRIVERCRATE_EXPECT( context,
								   scanned->indexSummary.refresh &&
									   scanned->indexSummary.refresh->usedAuthenticatedCache &&
									   scanned->indexSummary.refresh->error != 0) ;
			}

			// 無効Providerはrefresh/load/sendを一度も開始しません。
			if( mode == 3U) {
				DRIVERCRATE_EXPECT( context,
								   scanned->indexSummary.status == IndexScanStatus::NOT_RUN &&
									   observation[0] == 0U && observation[1] == 0U &&
									   input.observeHttp().sends == 0U) ;
			}

			// Close取消しから新しいrelationやgrantを作りません。
			if( mode == 4U) {
				DRIVERCRATE_EXPECT( context,
								   cancelled->load() &&
									   scanned->indexSummary.status == IndexScanStatus::CANCELLED &&
									   observation[1] == 0U) ;
			}

			Access::dispatchIndex( window, *scanned) ;
			// Close以外は通常UI本文を実際のscan終端から確認します。
			if( mode < 3U) {
				const auto text = Access::indexResultText( window) ;	// 製品が表示する所有本文です。
				DRIVERCRATE_EXPECT( context, text.find( mode == 0U   ? L"更新と保存"
													  : mode == 1U ? L"更新は拒否"
																   : L"更新には失敗") !=
													std::wstring::npos &&
												text.find( L"https://") == std::wstring::npos) ;
			}

			// 正常関係は同Windowで再scanし、旧operationの通知を受理しません。
			if( mode == 0U) {
				const auto firstSession = scanned->scanResult.scanSessionId ;	// 旧sessionです。
				const auto rows			= Access::count( window) ;				// 旧通知前の実行数です。
				auto	   stale		= *scanned ;							// 原packetを所有copyした遅延通知です。
				// 原packetのoperationだけを変えます。
				--stale.operationId ;
				Access::dispatchIndex( window, stale) ;
				DRIVERCRATE_EXPECT( context, Access::count( window) == rows) ;
				Access::beginIndexScan( window) ;
				auto next = Access::takeIndexTerminal(
					window, WorkerEventKind::SCAN_COMPLETED) ;	// 二回目の実終端です。
				DRIVERCRATE_EXPECT( context, next &&
												next->scanResult.scanSessionId != firstSession &&
												input.observeRefresh()[0] == 2U &&
												input.observeRefresh()[1] == 2U) ;
				// 原二回目通知だけを表示します。
				if( next) {
					Access::dispatchIndex( window, *next) ;
				}
			}
		}

		// 同fixture HWNDだけをcaptureし、他アプリ/desktopを読みません。
		if( mode == 0U || mode == 2U) {
#if defined( _DEBUG)
			const std::wstring name = mode == 0U ? L"index-refresh-fresh-debug"
												 : L"index-refresh-cache-debug" ;	// 固定名です。
#else
			const std::wstring name = mode == 0U ? L"index-refresh-fresh-release"
												 : L"index-refresh-cache-release" ;	// 固定名です。
#endif
			DRIVERCRATE_EXPECT( context, captureWindow( handle, name)) ;
		}

		// Closeが未破棄でもcleanupは同worker/HWNDへ限定します。
		if( IsWindow( handle) != FALSE) {
			Access::stopIndexWorker( window) ;
			DestroyWindow( handle) ;
		}

		DRIVERCRATE_EXPECT( context, IsWindow( handle) == FALSE && state->forbiddenCalls == 0U) ;
		std::cout << "P5 UI case=" << mode << " reached=" << scanned.has_value()
				  << " failures=" << context.failureCount() - before << '\n' ;
	}

	std::cout << "P5_REFRESH_ORIGINAL_END cases=5 assertions="
			  << context.assertionCount() - originalAssertions
			  << " failures=" << context.failureCount() - originalFailures << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同一本体の再利用後も通常workerとMainWindowが候補を保持することを確認します。
 * @param[in,out] context 元refresh二入力と分ける原assertionです。
 * @note Refresh終端だけを固定し、後続loadは元の実隔離storeを全再認証します。
 */
//------------------------------------------------------------------------------
void runUnchangedRefreshUiScenario( TestContext &context)
{
	const auto firstAssertion = context.assertionCount() ;	// この一条件だけの開始分母です。
	const auto firstFailure	  = context.failureCount() ;	// 元二入力の失敗を混ぜません。
	MSG		   previous{} ;									// 前の所有Windowが残したWM_QUITだけを消費します。
	// 別fixtureの終了通知を新しいworkerの完了と取り違えません。
	while( PeekMessageW( &previous, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE) != FALSE) {
	}

	auto input = makeSignedIndexUiInput(
		false, false, false, false, false, false,
		SignedIndexUiOptions{.deferredRefresh = false}) ;			// 原署名headは既に実commit済みです。
	const auto loads = std::make_shared<std::atomic_uint>( 0U) ;	// 通常loadそのものの実行観測です。
	const auto originalLoad = input.services.load ;					// 元の実隔離store能力を保持します。
	input.services.load = [loads, originalLoad]( const std::optional<std::chrono::sys_seconds> now) {
		++(*loads) ;
		return originalLoad( now) ;
	} ; // Deferred専用counterを、preseed済み通常loadの観測へ読み替えません。
	input.services.refresh = []( const ProviderScanCancellation &) {
		return IndexRefreshSummary{.status				= IndexRefreshStatus::UNCHANGED,
								   .httpStatus			= 200U,
								   .sends				= 1U,
								   .attemptedGeneration = 7U,
								   .store = {.status = IndexStoreStatus::SNAPSHOT_READY,
											 .persistedGeneration = 7U,
											 .usableSnapshot	  = true},
								   .usedAuthenticatedCache = true} ;
	} ; // 通信省略の終端だけ固定し、通常scanの成功gateへ実際に渡します。
	auto bound = makeSignedIndexBindingWorker( input.services, input.zip) ;	// 同じ低位fakeです。
	auto state = std::make_shared<MetadataUiState>() ;						// 製品fallbackは0を要求します。
	MainWindow window ;														// 本物のcontroller/queue/resourceと所有Windowです。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// Private desktop内だけです。
	DRIVERCRATE_EXPECT( context, created && bound.worker != nullptr) ;
	// 生成失敗を候補表示の成功へ補完しません。
	if( !created || !bound.worker) {
		// 所有workerができている場合だけ協調停止します。
		if( bound.worker) {
			bound.worker->stop() ;
		}

		// 所有Windowができている場合だけ同じhandleを破棄します。
		if( created) {
			DestroyWindow( Access::handle( window)) ;
		}

		return ;
	}

	const HWND handle = Access::handle( window) ;	// このfixtureだけの借用handleです。
	ShowWindow( handle, SW_SHOWNOACTIVATE) ;
	Access::attachIndexWorker( window, std::move( bound.worker)) ;
	Access::beginIndexScan( window) ;
	auto scanned =
		// 通常queueの終端です。
		Access::takeIndexTerminal( window, WorkerEventKind::SCAN_COMPLETED) ;
	DRIVERCRATE_EXPECT( context, scanned.has_value()) ;
	// 元終端に到達した場合だけ、通常loadと元候補への継続を確認します。
	if( scanned) {
		DRIVERCRATE_EXPECT(
			context, scanned->indexSummary.refresh &&
						 scanned->indexSummary.refresh->status == IndexRefreshStatus::UNCHANGED &&
						 scanned->indexSummary.status == IndexScanStatus::COMPLETED &&
						 loads->load() == 1U && scanned->indexSummary.relationCount == 1U &&
						 scanned->preparationPlan &&
						 scanned->preparationPlan->targets.size() == 1U) ;
		Access::dispatchIndex( window, *scanned) ;
		Access::verifyUnchangedCandidate( window, context) ;
		const auto text = Access::indexResultText( window) ;	// 実際に結果へ保持した本文です。
		DRIVERCRATE_EXPECT( context,
						   !scanned->scanResult.candidates.empty() &&
							   text.find( L"本体の再取得を省きました") != std::wstring::npos &&
							   text.find( L"更新には失敗") == std::wstring::npos &&
							   text.find( L"更新と保存") == std::wstring::npos &&
							   text.find( L"HTTP: 200") != std::wstring::npos &&
							   text.find( L"commit区分: 0") != std::wstring::npos &&
							   text.find( L"manifest世代: 7") != std::wstring::npos &&
							   text.find( L"保存世代: 7") != std::wstring::npos) ;
		Access::inspectRefreshRoute( window, context, true) ;
	}

	Access::stopIndexWorker( window) ;
	const auto observation = bound.observeAfterStop() ;	// 全worker join後の低位事実だけです。
	DRIVERCRATE_EXPECT( context, input.observeHttp().sends == 0U && state->forbiddenCalls == 0U &&
									observation.installs == 0U && observation.restoreBegins == 0U &&
									observation.restoreCompletes == 0U) ;
	DestroyWindow( handle) ;
	std::cout << "UI_UNCHANGED_END cases=1 assertions=" << context.assertionCount() - firstAssertion
			  << " failures=" << context.failureCount() - firstFailure << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief VUI01–06の固定入力で実menu/可視editと元同版publicationを確認します。
 * @param[in,out] context 原五caseと区別して加算する集計先です。
 * @param[in] probeOnly 元fresh/cacheだけを画像なしで観測し、修正後の受入と区別する場合trueです。
 * @note 実network/実inventory/実導入を使用しません。画像はDebug五枚・Release三枚です。
 */
//------------------------------------------------------------------------------
void runVisibleRefreshUiScenarios( TestContext &context, const bool probeOnly = false)
{
	const auto originalAssertions = context.assertionCount() ;	// 新六caseだけの開始分母です。
	const auto originalFailures	  = context.failureCount() ;	// 旧五caseの原失敗を含めません。
	const auto exactBefore = refreshExactAssertions ;			// 新しい具体値assertだけの開始分母です。
	const auto observationsBefore = refreshDetailObservations ;	// 元入力数と別の実dialog到達数です。
	// 新六入力を一Windowずつ通し、失敗した条件も分母へ残します。
	for( unsigned mode{}; mode < (probeOnly ? 2U : 6U); ++mode) {
		const auto before = context.failureCount() ;	// この入力だけの原失敗数です。
		MSG		   previous{} ;							// 前fixtureのWM_QUITを次のmodal loopへ持ち越しません。
		// 前fixtureが残した終了通知だけを消費します。
		while( PeekMessageW( &previous, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE) != FALSE) {
		}

		auto input = makeSignedIndexUiInput(
			false, false, false, false, false, false,
			SignedIndexUiOptions{.deferredRefresh =
									 mode != 1U}) ;	// 元record/INFは全条件で保持します。
		// VUI02は元E_FAIL/503と現在再認証したcacheを同時に保持します。
		if( mode == 1U) {
			input.services.refresh = []( const ProviderScanCancellation &) {
				return IndexRefreshSummary{.status	   = IndexRefreshStatus::AUTHENTICATED_CACHE,
										   .error	   = static_cast<NativeError>( E_FAIL),
										   .httpError  = static_cast<NativeError>( E_FAIL),
										   .httpStatus = 503U,
										   .usedAuthenticatedCache = true} ;
			} ; // 元storeの所有callbackと現在UTCによるreloadは保持します。
		}

		// VUI03は独立Provider成功を索引暗号拒否で上書きしません。
		if( mode == 2U) {
			input.services.refresh = []( const ProviderScanCancellation &) {
				return IndexRefreshSummary{.status = IndexRefreshStatus::MANIFEST_REJECTED,
										   .error  = static_cast<NativeError>( E_ACCESSDENIED)} ;
			} ; // 原拒否だけを返し、loadへ進めません。
		}

		auto bound = makeSignedIndexBindingWorker(
			input.services, input.zip, false, false, false,
			mode == 3U
				? SignedIndexBindingNativeCase::NORMAL_SAME_VERSION
				: SignedIndexBindingNativeCase::NORMAL) ;	// VUI04だけ原currentを同版へ固定します。
		auto state = std::make_shared<MetadataUiState>() ;	// 製品fallbackを数える別counterです。
		MainWindow window ;									// 製品resource/controllerと実worker queueの同所有者です。
		Access::configure( window, state) ;
		const bool created = window.create( GetModuleHandleW( nullptr)) ;	// Fixture所有HWNDです。
		DRIVERCRATE_EXPECT( context, created && bound.worker != nullptr) ;
		// 未生成を成功へ補完せず、所有workerだけを停止します。
		if( !created || !bound.worker) {
			// 生成できたworkerの停止だけを行います。
			if( bound.worker) {
				bound.worker->stop() ;
			}

			continue ;
		}

		const HWND handle = Access::handle( window) ;	// 同fixtureだけの非所有handleです。
		ShowWindow( handle, SW_SHOWNOACTIVATE) ;
		SetWindowPos( handle, nullptr, 0, 0, 2100, 850, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE) ;
		Access::attachIndexWorker( window, std::move( bound.worker)) ;
		// VUI06はregistryで索引だけを明示無効にします。
		if( mode == 5U) {
			Access::disableIndex( window) ;
		}

		Access::beginIndexScan( window) ;
		auto scanned =
			// 元終端です。
			Access::takeIndexTerminal( window, WorkerEventKind::SCAN_COMPLETED) ;
		DRIVERCRATE_EXPECT( context, scanned.has_value()) ;
		// 元終端に到達した入力だけで可視導線と後続取得を確認します。
		if( scanned) {
			Access::dispatchIndex( window, *scanned) ;
			Access::inspectRefreshRoute( window, context, mode != 5U) ;
			// VUI01は空の元隔離storeへの実commit/reload四観測を同終端で確認します。
			if( mode == 0U) {
				DRIVERCRATE_EXPECT( context, input.observeRefresh() ==
												(std::array<std::uint32_t, 4U>{1U, 1U, 1U, 1U})) ;
			}

			std::wstring beforeText ;	// 実可視editから得た元本文だけを比較基準にします。
			// 無効Providerに成功dialogを開かせません。
			if( mode != 5U) {
				DialogState detail{
					.context		= &context,
					.owner			= handle,
					.mode			= DialogMode::DETAILS,
					.captureName	= mode == 1U ? L"complete-index-cache-before"
												 : L"complete-index-fresh-before",
					.captureDetails = false,
					.refreshWindow	= mode < 2U ? &window : nullptr,
					.refreshFresh	= mode == 0U,
					.refreshStrict	= !probeOnly,
					.refreshStage	= mode == 0U ? "fresh-before"
												 : "cache-before"} ;	// 元非機密summaryだけを読みます。
#if defined( _DEBUG)
				detail.captureDetails = !probeOnly && mode < 2U ;
#endif
				{
					DialogDriver driver( detail) ;	// 同所有dialogだけを読み閉じます。
					Access::openRefreshDetails( window) ;
				}
				beforeText = detail.details ;
				DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
												beforeText.find( mode == 1U	 ? L"更新には失敗"
																: mode == 2U ? L"更新は拒否"
																			 : L"更新と保存") !=
													std::wstring::npos &&
												beforeText.find( L"https://") == std::wstring::npos) ;
			}

			// 元通信失敗をcache成功説明だけで隠しません。
			if( mode == 1U) {
				DRIVERCRATE_EXPECT( context, beforeText.find( L"503") != std::wstring::npos &&
												beforeText.find( L"80004005") != std::wstring::npos) ;
			}

			// 暗号拒否でも独立Providerのscan成功は保持し、索引loadは0です。
			if( mode == 2U) {
				DRIVERCRATE_EXPECT(
					context, scanned->scanResult.succeeded && input.observeRefresh()[1] == 0U &&
								 beforeText.find( L"80070005") != std::wstring::npos &&
								 beforeText.find( L"更新と保存") == std::wstring::npos &&
								 beforeText.find( L"保存索引を使用") == std::wstring::npos) ;
			}

			// 明示無効はrefresh/load/HTTPを一度も開始しません。
			if( mode == 5U) {
				DRIVERCRATE_EXPECT( context, !scanned->indexSummary.refresh &&
												input.observeRefresh()[0] == 0U &&
												input.observeRefresh()[1] == 0U &&
												input.observeHttp().sends == 0U) ;
			}

			// VUI05は異なる拒否summaryを持つ旧operationで確定表示を書き換えません。
			if( mode == 4U) {
				auto stale = *scanned ;	// 元packetの所有copyから遅延通知だけを作ります。
				--stale.operationId ;
				stale.indexSummary.refresh =
					IndexRefreshSummary{.status = IndexRefreshStatus::MANIFEST_REJECTED,
										.error	= static_cast<NativeError>( E_ACCESSDENIED)} ;
				Access::dispatchIndex( window, stale) ;
				DialogState detail{
					.context = &context,
					.owner	 = handle,
					.mode	 = DialogMode::DETAILS,
					.captureDetails =
						false} ;	// 現在受理済みsummaryだけが残ることを実editで読みます。
				{
					DialogDriver driver( detail) ;	// この旧通知後の実dialogだけを同期観測します。
					Access::openRefreshDetails( window) ;
				}
				DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
												detail.details == beforeText) ;
			}

			// Fresh/cacheのplan前後と元同版publicationを同じscanから確認します。
			if( mode < 2U || mode == 3U) {
				DRIVERCRATE_EXPECT( context, scanned->preparationPlan &&
												scanned->preparationPlan->targets.size() == 1U) ;
				// 元計画がなければ任意の取得承認を構築しません。
				if( scanned->preparationPlan) {
					DialogState approval{
						.context = &context,
						.owner	 = handle,
						.mode =
							DialogMode::INDEX_PREPARATION_ACCEPT} ;	// 同planへの明示取得判断です。
					{
						DialogDriver driver( approval) ;	// 元planの実確認だけをこのscopeへ結びます。
						Access::reviewIndexPlan( window) ;
					}
					DRIVERCRATE_EXPECT( context, approval.handled && !approval.failed) ;
					Access::inspectRefreshRoute( window, context, false) ;
					auto prepared = Access::takeIndexTerminal(
						window,
						WorkerEventKind::
							PREPARATION_COMPLETED) ;	// 同元record/INFの実取得・検査終端です。
					DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
					// 元取得終端だけをMainWindowへ渡し、actionを変更しません。
					if( prepared) {
						Access::dispatchIndex( window, *prepared) ;
						Access::inspectRefreshRoute( window, context, true) ;
						DialogState detail{
							.context		= &context,
							.owner			= handle,
							.mode			= DialogMode::DETAILS,
							.captureName	= mode == 1U ? L"complete-index-cache-after"
														 : L"complete-index-fresh-after",
							.captureDetails = false,
							.refreshWindow	= mode < 2U ? &window : nullptr,
							.refreshFresh	= mode == 0U,
							.refreshStrict	= !probeOnly,
							.refreshStage =
								mode == 0U
									? "fresh-after"
									: "cache-after"} ;	// 取得結果本文のclearに依存しない同summaryです。
#if defined( _DEBUG)
						detail.captureDetails = !probeOnly && mode < 2U ;
#else
						detail.captureDetails = !probeOnly && mode < 2U ;
						detail.captureName	  = mode == 1U ? L"complete-index-cache-after-release"
														   : L"complete-index-fresh-after-release" ;
#endif
						{
							DialogDriver driver( detail) ;	// 準備後の同summaryを実editから読みます。
							Access::openRefreshDetails( window) ;
						}
						DRIVERCRATE_EXPECT( context, detail.handled && !detail.failed &&
														detail.details == beforeText) ;
						// VUI04は同publicationの1.0.0.0を同版行へ表示し推奨一括選択へ含めません。
						if( mode == 3U) {
							std::size_t publications{} ;	// 元auditReportだけの発行数です。
							// 元内容・適用性を通った同候補を確認します。
							for( const auto &report : prepared->preparationResult.auditReports) {
								// 同reportの発行候補を元順に検査し、合成候補を追加しません。
								for( const auto &candidate : report.publishedCandidates) {
									++publications ;
									DRIVERCRATE_EXPECT(
										context, report.acceptedInfCount == 1U &&
													 report.applicablePairCount == 1U &&
													 candidate.version == L"1.0.0.0" &&
													 candidate.action == DriverAction::REINSTALL &&
													 !candidate.recommended) ;
								}
							}

							DRIVERCRATE_EXPECT( context,
											   publications == 1U &&
												   bound.observe().baseInitiallySameVersion) ;
							Access::inspectReinstallRow( window, context) ;
#if defined( _DEBUG)
							DRIVERCRATE_EXPECT(
								context, captureWindow( handle, L"complete-index-same-version")) ;
#else
							DRIVERCRATE_EXPECT(
								context,
								captureWindow( handle, L"complete-index-same-version-release")) ;
#endif
						}
					}
				}
			}
		}

		Access::stopIndexWorker( window) ;
		const auto observation =
			// 同worker停止後だけ読む低位counterです。
			bound.observeAfterStop() ;
		DRIVERCRATE_EXPECT( context, observation.installs == 0U && observation.restoreBegins == 0U &&
										observation.restoreCompletes == 0U &&
										state->forbiddenCalls == 0U) ;
		DestroyWindow( handle) ;
		std::cout << "VISIBLE_REFRESH case=VUI0" << mode + 1U << " reached=" << scanned.has_value()
				  << " failures=" << context.failureCount() - before << '\n' ;
	}

	std::cout << "VISIBLE_REFRESH_NEW_END cases=" << (probeOnly ? 2U : 6U) << " assertions="
			  << context.assertionCount() - originalAssertions -
					 (refreshExactAssertions - exactBefore)
			  << " failures=" << context.failureCount() - originalFailures << '\n' ;
	std::cout << "DETAIL_EXACT_FIELDS_END observations="
			  << refreshDetailObservations - observationsBefore
			  << " assertions=" << refreshExactAssertions - exactBefore << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 真署名・実byte・同bindingから本物MainWindowの通常選択と導入結果を確認します。
 * @param[in,out] context Assertion集計先です。
 * @note 実導入APIは完全低位fakeだけです。失敗caseを分母から除かず元診断を残します。
 */
//------------------------------------------------------------------------------
void runSignedIndexBindingUiScenarios( TestContext &context)
{
	const auto		 before			= context.assertionCount() ;	// 新有限caseの開始assertion数です。
	const auto		 beforeFailures = context.failureCount() ;		// 元失敗を保持する開始値です。
	const std::array names{
		"P01-UI",		  "P05-UI",			  "N20-UI-REPORT", "N23-UI-STAGE",
		"N26-UI-RESTORE", "N25-UI-DUPLICATE", "P06-UI-PARTIAL"} ;	// 事前固定した有限caseです。
	// 七固定条件を一Window/一workerずつ直列に実行して全条件で終了します。
	for( unsigned mode = 0U; mode < names.size(); ++mode) {
		std::cout << "BINDING_BEGIN case=" << names[mode] << " records=" << (mode == 1U ? 2U : 1U)
				  << '\n' ;
		MSG previousQuit{} ;	// 前の独立Windowの終了通知です。
		// 次の実modal loopへ前WindowのWM_QUITを持ち越しません。
		while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE) != FALSE) {
		}

		auto input =
			// CNG署名と実commit/reloadからだけ作る入力です。
			makeSignedIndexUiInput( mode == 1U) ;
		auto bound = makeSignedIndexBindingWorker( std::move( input.services), input.zip, mode == 1U,
												  mode == 4U,
												  // 完全低位Windows fakeだけを結びます。
												  mode == 3U) ;
		DRIVERCRATE_EXPECT( context, bound.worker != nullptr) ;
		// 完全workerの不成立を正常候補へ数えません。
		if( !bound.worker) {
			continue ;
		}

		auto  state = std::make_shared<MetadataUiState>() ;		// 元UI factoryの誤呼出しを検出します。
		auto  windowOwner = std::make_unique<MainWindow>() ;	// 同scopeの元Windowをheap所有します。
		auto &window	  = *windowOwner ;						// 製品resourceを使用する本物Windowです。
		Access::configure( window, state) ;
		const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 隠した実標準controlです。
		DRIVERCRATE_EXPECT( context, created) ;
		// Windowなしではworkerを終了し、UI受入を未到達に残します。
		if( !created) {
			bound.worker->stop() ;
			continue ;
		}

		const HWND handle = Access::handle( window) ;	// 同scopeだけの非所有HWNDです。
		ShowWindow( handle, SW_HIDE) ;
		Access::attachIndexWorker( window, std::move( bound.worker)) ;
		try {
			// 以下の各未到達は失敗を記録し、同scopeの終端清掃へ進みます。
			do {
				Access::beginIndexScan( window) ;
				auto scanned = Access::takeIndexTerminal(
					window, WorkerEventKind::SCAN_COMPLETED) ;	// 実scan終端です。
				DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
												scanned->preparationPlan) ;
				// 同scanの元planがない場合は取得へ進みません。
				if( !scanned || !scanned->preparationPlan) {
					break ;
				}

				Access::dispatchIndex( window, *scanned) ;
				const auto &plan =
					*scanned->preparationPlan ;	// 元operation/session/planの借用です。
				const std::size_t expected =
					// 実行前に固定した元候補分母です。
					mode == 1U ? 2U : 1U ;
				DRIVERCRATE_EXPECT( context, plan.targets.size() == expected &&
												Access::controller( window).state() ==
													ApplicationState::SCAN_READY) ;
				DRIVERCRATE_EXPECT( context, Access::acquireIndexPlan( window, plan)) ;
				auto prepared = Access::takeIndexTerminal(
					window, WorkerEventKind::
								PREPARATION_COMPLETED) ;	// 元取得/内容/適合/publication終端です。
				DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
				// 元取得eventなしでは候補DTOを作りません。
				if( !prepared) {
					break ;
				}

				std::vector<UpdateCandidate>
					original ;	// 実bindingから発行された元候補の所有copyです。
				// 全原reportからだけ選択元candidateを採取します。
				for( const auto &report : prepared->preparationResult.auditReports) {
					DRIVERCRATE_EXPECT( context, report.acceptedInfCount == 1U &&
													report.applicablePairCount == 1U &&
													report.publication.publishedCount == 1U) ;
					original.insert( original.end(), report.publishedCandidates.begin(),
									report.publishedCandidates.end()) ;
				}

				DRIVERCRATE_EXPECT( context,
								   original.size() == expected &&
									   prepared->indexPreparation.items.size() == expected) ;
				std::cout << "BINDING_PUBLICATION case=" << names[mode]
						  << " originalCandidates=" << original.size() << " expected=" << expected
						  << " session=" << plan.scanSessionId << " plan=" << plan.planId << '\n' ;
				// 正常candidate不足を後の導入成功で補完しません。
				if( original.size() != expected) {
					break ;
				}

				std::vector<std::wstring> identities ;	// 元publication順だけを保持する選択IDです。
				// 元候補の非推奨・独立device/packageを保ち、表示名からIDを作りません。
				for( const auto &candidate : original) {
					DRIVERCRATE_EXPECT( context, candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
													candidate.installable &&
													!candidate.recommended &&
													candidate.action == DriverAction::UPDATE &&
													!candidate.packageIdentity.empty()) ;
					identities.push_back( candidate.identity) ;
				}

				// 同URL/title/versionの二recordを共有packageへ黙ってまとめません。
				if( mode == 1U) {
					DRIVERCRATE_EXPECT(
						context, original[0].identity != original[1].identity &&
									 original[0].deviceIdentity != original[1].deviceIdentity &&
									 original[0].packageIdentity != original[1].packageIdentity) ;
				}

				const auto rowsBefore = Access::count( window) ;	// 原参照行と現在行の保持基準です。
				// 元生成eventからtupleだけを変え、古い通知の適用を個別に拒否します。
				for( unsigned staleMode = 0U; staleMode < 3U; ++staleMode) {
					auto stale = *prepared ;	// 一条件だけ差し替える遅延通知です。
					// Envelopeの別operationを拒否します。
					if( staleMode == 0U) {
						--stale.operationId ;
					}
					// 元resultの別sessionを拒否します。
					else if( staleMode == 1U) {
						++stale.preparationResult.scanSessionId ;
					} else {
						++stale.preparationResult.planId ;
					}

					Access::dispatchIndex( window, stale) ;
					DRIVERCRATE_EXPECT( context, Access::controller( window).state() ==
														ApplicationState::PREPARING &&
													Access::count( window) == rowsBefore) ;
				}

				// 不正Providerと重複IDは別caseへ限定して原reportを一項目だけ変えます。
				if( mode == 2U || mode == 5U) {
					auto invalid = *prepared ;	// 元byte/取得成功とは分離した不正通知です。
					// 別Providerの候補を同索引reportへ結合しません。
					if( mode == 2U) {
						invalid.preparationResult.auditReports[0]
							.publishedCandidates[0]
							.providerId = DRIVER_STORE_PROVIDER_ID ;
					} else {
						auto &report = invalid.preparationResult
										   .auditReports[0] ;	// 同reportだけの重複拒否です。
						report.publishedCandidates.push_back( report.publishedCandidates[0]) ;
						++report.publication.publishedCount ;
					}

					Access::dispatchIndex( window, invalid) ;
					DRIVERCRATE_EXPECT(
						context, Access::controller( window).state() == ApplicationState::FAILURE &&
									 Access::controller( window).scanSessionId() == 0U &&
									 Access::count( window) == rowsBefore) ;
					const auto observed = bound.observe() ;	// 同workerがidleの低位観測です。
					DRIVERCRATE_EXPECT( context, observed.stages == 0U && observed.installs == 0U) ;
					std::cout << "BINDING_REJECTION case=" << names[mode]
							  << " originalCandidates=" << original.size()
							  << " added=0 scanExpired="
							  << (Access::controller( window).scanSessionId() == 0U)
							  << " stage=" << observed.stages
							  << " specifiedInstall=" << observed.installs << '\n' ;
					break ;
				}

				// 候補発行済みでも一部INFが未対応となる表示入力を、既存六条件と分けて固定します。
				if( mode == 6U) {
					auto &summary =
						// 表示用の人工部分結果です。
						prepared->indexPreparation.items.front() ;
					summary.inventoryFileCount		  = 3U ;
					summary.infCount				  = 2U ;
					summary.parsedInfCount			  = 1U ;
					summary.signatureRejectedInfCount = 0U ;
					summary.acceptedInfCount		  = 1U ;
					summary.firstInfRejection =
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
					auto &report = prepared->preparationResult.auditReports
									   .front() ;	// 同対象の人工監査集計です。
					report.infCount				 = 2U ;
					report.firstContentRejection = summary.firstInfRejection ;
				}

				Access::dispatchIndex( window, *prepared) ;
				DRIVERCRATE_EXPECT(
					context, Access::controller( window).state() == ApplicationState::SCAN_READY &&
								 Access::count( window) == rowsBefore + original.size()) ;
				// 部分結果の候補を未選択で保持し、実行操作前の表示だけを検証して終了します。
				if( mode == 6U) {
					Access::verifyPartialIndexPublication( window, context) ;
					const auto observed = bound.observe() ;	// 同workerの完全低位fakeだけです。
					DRIVERCRATE_EXPECT( context, observed.stages == 0U && observed.installs == 0U &&
													observed.restoreBegins == 0U &&
													observed.restoreCompletes == 0U) ;
					std::cout << "BINDING_PARTIAL case=" << names[mode]
							  << " acceptedInf=1 infCount=2 firstInfRejection=0x80070032"
							  << " published=" << original.size()
							  << " selection=0 install=0 restore=0\n" ;
					break ;
				}

				Access::dispatchIndex( window, *prepared) ;
				DRIVERCRATE_EXPECT( context, Access::count( window) == rowsBefore + original.size()) ;
				Access::verifyIndexSelectionBoundary( window, context, identities) ;
				Access::selectIndexCandidates( window, context, identities) ;
				DialogState execute{
					.context = &context,
					.owner	 = handle,
					.mode = DialogMode::INDEX_INSTALL_ACCEPT} ;	// 汎用確認を出さない一回の実行です。
				{
					DialogDriver driver( execute) ;	// 想定外dialogを成功へ読み替えません。
					Access::beginIndexInstallCommand( window) ;
				}

				DRIVERCRATE_EXPECT( context, !execute.handled && !execute.failed) ;
				auto installed = Access::takeIndexTerminal(
					window,
					WorkerEventKind::INSTALL_COMPLETED) ;	// 復旧境界の内側から返る実個別結果です。
				DRIVERCRATE_EXPECT( context, installed.has_value()) ;
				// 元導入結果なしでは表示だけの成功結果を作りません。
				if( !installed) {
					break ;
				}

				const auto &result	 = installed->installResult ;	// 同元selectionの実結果です。
				const auto	observed = bound.observe() ;			// 指定INF/nodeと署名APIの元観測です。
				DRIVERCRATE_EXPECT(
					context, observed.specifiedBindingMatches && observed.restoreBegins == 1U &&
								 observed.restoreCompletes == (mode == 4U ? 0U : 1U)) ;
				DRIVERCRATE_EXPECT( context, observed.stages == (mode == 4U ? 0U : expected) &&
												observed.installs ==
													(mode == 3U || mode == 4U ? 0U : expected)) ;
				// 復旧開始拒否はProviderを呼ばず、その元診断を保持します。
				if( mode == 4U) {
					DRIVERCRATE_EXPECT( context, !result.succeeded &&
													result.restorePointCreation.error ==
														static_cast<NativeError>( E_ACCESSDENIED)) ;
				} else {
					DRIVERCRATE_EXPECT( context, result.updates.size() == identities.size()) ;
					// 元選択順の各HRESULTを全件比較し、個別失敗を全体成功へ変更しません。
					for( std::size_t index = 0U;
						index < result.updates.size() && index < identities.size(); ++index) {
						const auto &item = result.updates[index] ;	// 元candidate一件だけの結果です。
						const bool	success =
							mode != 3U && !(mode == 1U && index == 1U) ;	// 固定低位拒否の期待です。
						DRIVERCRATE_EXPECT(
							context,
							item.identity == identities[index] &&
								item.downloadOutcome == OutcomeCode::SUCCESS &&
								item.installOutcome ==
									(success ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE) &&
								item.installError ==
									(success ? 0 : static_cast<NativeError>( E_ACCESSDENIED))) ;
						std::cout << "BINDING_ITEM case=" << names[mode]
								  << " selectionIndex=" << index
								  << " originalIdentity=" << (item.identity == identities[index])
								  << " download=" << static_cast<unsigned>( item.downloadOutcome)
								  << " install=" << static_cast<unsigned>( item.installOutcome)
								  << " hresult=" << item.installError
								  << " reboot=" << item.rebootRequired << '\n' ;
					}

					DRIVERCRATE_EXPECT( context,
									   result.succeeded == (mode == 0U) &&
										   result.rebootRequired == (mode == 1U) &&
										   result.installOutcome ==
											   (mode == 1U	 ? OutcomeCode::SUCCEEDED_WITH_ERRORS
												: mode == 3U ? OutcomeCode::FAILURE
															 : OutcomeCode::SUCCESS)) ;
				}

				DialogState display{
					.context = &context,
					.owner	 = handle,
					.mode	 = DialogMode::INDEX_INSTALL_RESULT} ;	// 実結果dialogの読取りです。
				{
					DialogDriver driver( display) ;	// 確定結果の本物案内だけを閉じます。
					Access::dispatchIndex( window, *installed) ;
				}
				DRIVERCRATE_EXPECT( context,
								   display.handled && !display.failed && !display.details.empty()) ;
				Access::verifyIndexResultRows( window, context, result) ;
				const auto kept =
					// 旧通知で上書きされない表示基準です。
					Access::displayText( window) ;
				Access::dispatchIndex( window, *prepared) ;
				DRIVERCRATE_EXPECT( context, Access::displayText( window) == kept &&
												Access::controller( window).state() ==
													(mode == 0U ? ApplicationState::COMPLETED
																: ApplicationState::FAILURE)) ;
				DRIVERCRATE_EXPECT( context, observed.signature.setupCalls > 0U &&
												observed.signature.verifyCalls > 0U &&
												observed.signature.verifyCalls ==
													observed.signature.closeCalls &&
												observed.signature.rejectedCalls == 0U) ;
				const auto http = input.observeHttp() ;	// 元grant限定HTTPの終端観測です。
				DRIVERCRATE_EXPECT( context, http.sends == expected && http.safe &&
												http.opens == http.closes) ;
				std::cout << "BINDING_RESULT case=" << names[mode]
						  << " originalCandidates=" << original.size()
						  << " rows=" << Access::count( window) << " stage=" << observed.stages
						  << " specifiedInstall=" << observed.installs
						  << " exactInfNode=" << observed.specifiedBindingMatches
						  << " installOutcome=" << static_cast<unsigned>( result.installOutcome)
						  << " succeeded=" << result.succeeded
						  << " rebootOR=" << result.rebootRequired
						  << " restoreBegin=" << observed.restoreBegins
						  << " restoreEnd=" << observed.restoreCompletes
						  << " fakeHttp=" << http.sends
						  << " signatureReject=" << observed.signature.rejectedCalls
						  << " scanExpired=" << (Access::controller( window).scanSessionId() == 0U)
						  << " realOSChanges=0\n" ;
			} while( false) ;
		} catch( ...) {
			Access::stopWorker( window) ;
			DestroyWindow( handle) ;
			throw ;
		}

		Access::stopWorker( window) ;
		DestroyWindow( handle) ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed() && IsWindow( handle) == FALSE &&
										state->forbiddenCalls == 0U && state->restoreCalls == 0U &&
										state->normalCalls == 0U) ;
	}

	std::cout << "Binding UI assertions: " << context.assertionCount() - before
			  << ", failures: " << context.failureCount() - beforeFailures
			  << ", native CAT positive UNCONFIRMED, driver coverage increase0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原HTML全文から通常取得command・同active task・候補publicationへ固定正負を通します。
 * @param[in,out] context 原assertion分母の集計先です。
 * @note 真署名は既存RAM鍵fixtureだけです。HTTP/CAT/rankは完全低位fakeで、実取得や導入に数えません。
 */
//------------------------------------------------------------------------------
void runPreparationCommandUiScenarios( TestContext &context)
{
	using Native = SignedIndexBindingNativeCase ;	// 既存完全低位Windows境界だけです。
	/** @brief Code前に固定した11条件と元期待を所有します。 */
	struct Case {
		/// 元固定条件の一意IDです。
		const char			*id ;
		/// 元署名HTMLとpayloadの一要因です。
		SignedIndexUiOptions options ;
		/// 同worker内の低位native条件です。
		Native				 native ;
		/// 別recordとして二対象を原署名へ含む場合trueです。
		bool				 twoRecords ;
		/// 同descriptorを一回だけ取得する場合trueです。
		bool				 shared ;
		/// 原本物dialogへの明示判断です。
		DialogMode			 decision ;
		/// 元planの対象数です。失敗条件を分母から除外しません。
		std::size_t			 targets ;
		/// 原scanで行う規約pageの低位fake GET数です。
		std::uint32_t		 termsGets ;
		/// 原取得operationで行う低位fake payload GET数です。
		std::uint32_t		 payloadGets ;
		/// 元content/bindingから発行する通常候補数です。
		std::size_t			 candidates ;
		/// 原scan後だけ信頼UTCを期限外へ移す条件です。
		bool				 expired{} ;
	} ;
	// 正負の入力・分母・期待をcode前planと一致させ、後続成功で変更しません。
	const std::array cases{
		Case{"Q01",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 1U},
		Case{"Q02",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_CANCEL,
			 1U,
			 1U,
			 0U,
			 0U},
		Case{"Q03",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_TARGET_NO,
			 1U,
			 1U,
			 0U,
			 0U},
		Case{"Q04",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_FINAL_NO,
			 1U,
			 1U,
			 0U,
			 0U},
		Case{"Q05",
			 {.termsRequired = true, .htmlTerms = true, .corruptTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 0U,
			 1U,
			 0U,
			 0U},
		Case{"Q06",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 0U,
			 0U,
			 true},
		Case{"Q07",
			 {.termsRequired = true, .htmlTerms = true, .corruptPayload = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 0U},
		Case{"Q08",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::SHARED_SUCCESS,
			 true,
			 true,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 2U,
			 1U,
			 2U},
		Case{"Q09",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::INDEX_VERIFIED_PARTIAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 1U},
		Case{"Q10",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::INDEX_NON_UNIQUE,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 2U},
		Case{"Q11",
			 {.termsRequired = true, .htmlTerms = true, .corruptSecondPayload = true},
			 Native::NORMAL,
			 true,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 2U,
			 2U,
			 2U,
			 1U},
		Case{"Q12",
			 {.requiredComponentCase = 178U, .termsRequired = true, .htmlTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 1U},
		Case{"Q13",
			 {.requiredComponentCase = 179U, .termsRequired = true, .htmlTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 0U},
		Case{"Q14",
			 {.requiredComponentCase = 180U, .termsRequired = true, .htmlTerms = true},
			 Native::NORMAL,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 1U},
		Case{"Q15",
			 {.requiredComponentCase = 178U, .termsRequired = true, .htmlTerms = true},
			 Native::DEPENDENCY_SIGNATURE_REJECTED,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 0U},
		Case{"Q16",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::INITIAL_SAME_ID,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 2U},
		Case{"Q17",
			 {.termsRequired = true, .htmlTerms = true},
			 Native::INITIAL_SAME_ID_OTHER_INCOMPLETE,
			 false,
			 false,
			 DialogMode::INDEX_PREPARATION_ACCEPT,
			 1U,
			 1U,
			 1U,
			 2U}} ;
	const auto before	= context.assertionCount() ;	// 原assertionに追加する開始位置です。
	const auto failures = context.failureCount() ;		// 原失敗を保持する開始位置です。
	// 元十一と追加四条件を一Window/一workerで直列実行し、未到達も元caseの失敗へ残します。
	for( const auto &testCase : cases) {
		const auto caseFailures = context.failureCount() ;	// 当該条件の原失敗開始数です。
		MSG		   previousQuit{} ;							// 前の独立試験Windowの終了通知だけです。
		// 製品の終了通知を変更せず次caseのmodal loopへだけ持ち越しません。
		while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
		}

		auto input =
			makeSignedIndexUiInput( testCase.twoRecords, testCase.shared, false, false, false, false,
								   testCase.options) ;		// 真署名原byteと完全低位HTTPの同所有者です。
		auto expired	 = std::make_shared<bool>( false) ;	// Worker idle中だけ変更する期限条件です。
		const auto clock = input.services.utc ;				// 元信頼UTC callbackの所有copyです。
		input.services.utc = [clock, expired]() {
			auto value = clock() ;	// 元UTCだけを再照会します。
			// 期限を刷新せず元許可の失効だけを再現します。
			if( *expired && value) {
				*value += std::chrono::days{2} ;
			}

			return value ;
		} ; // 同scopeを共有所有し、結果や元署名byteを変更しません。
		auto bound = makeSignedIndexBindingWorker(
			input.services, input.zip, testCase.twoRecords, false, false,
			testCase.native) ;								// 既存COM MTA・同queue・完全CAT/Windows低位表です。
		auto state = std::make_shared<MetadataUiState>() ;	// 不許可の製品呼出しを別に観測します。
		MainWindow window ;									// 製品resourceと実controllerを所有する本物画面です。
		Access::configure( window, state) ;
		const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 原生成結果です。
		DRIVERCRATE_EXPECT( context, created) ;
		// 未生成caseを成功へ補完せず、元workerを停止して次の固定caseへ進みます。
		if( !created) {
			bound.worker->stop() ;
			continue ;
		}

		const auto handle = Access::handle( window) ;	// 同試験scopeだけの非所有HWNDです。
		ShowWindow( handle, SW_HIDE) ;
		Access::attachIndexWorker( window, std::move( bound.worker)) ;
		bool preparationEnabledBeforeCommand{} ;	// 同原scan終端の実取得button観測です。
		try {
			// 元scan終端からだけ進み、未到達や拒否で当該条件を終了します。
			do {
				Access::beginIndexScan( window) ;
				auto scanned = Access::takeIndexTerminal(
					window, WorkerEventKind::SCAN_COMPLETED) ;	// 原worker終端です。
				DRIVERCRATE_EXPECT( context, scanned.has_value()) ;
				// 原終端欠損からplanや成功DTOを生成しません。
				if( !scanned) {
					break ;
				}

				Access::dispatchIndex( window, *scanned) ;
				const auto scanHttp = input.observeHttp() ;	// 原scan同期終端後の低位HTTPです。
				preparationEnabledBeforeCommand =
					Access::controller( window).preparationPlan() != nullptr ;
				DRIVERCRATE_EXPECT( context, scanHttp.sends == testCase.termsGets && scanHttp.safe &&
												scanHttp.opens == scanHttp.closes) ;
				// 他nodeの不足と私有positiveを完全MATCHEDへ変えません。
				if( testCase.native == Native::INDEX_VERIFIED_PARTIAL) {
					DRIVERCRATE_EXPECT( context,
									   scanned->indexSummary.status == IndexScanStatus::PARTIAL &&
										   scanned->indexSummary.error != 0U &&
										   scanned->indexSummary.matchedRelations == 0U &&
										   scanned->indexSummary.verifiedPartialRelations == 1U &&
										   scanned->indexSummary.undeterminedRelations == 1U) ;
				}

				// 二node非一意を一つの取得targetへ縮めません。
				if( testCase.native == Native::INDEX_NON_UNIQUE) {
					DRIVERCRATE_EXPECT( context, scanned->indexSummary.nonUniqueRelations == 1U &&
													scanned->indexSummary.matchedRelations == 0U) ;
				}

				// Hash/非一意拒否では元planがないか空で、取得operationを開始しません。
				if( testCase.targets == 0U) {
					DRIVERCRATE_EXPECT( context, !scanned->preparationPlan ||
													scanned->preparationPlan->targets.empty()) ;
					DRIVERCRATE_EXPECT( context, bound.observe().stages == 0U &&
													bound.observe().installs == 0U) ;
					break ;
				}

				DRIVERCRATE_EXPECT( context, scanned->preparationPlan.has_value()) ;
				// 元planの未到達を任意対象や承認DTOで補完しません。
				if( !scanned->preparationPlan) {
					break ;
				}

				const auto &plan = *scanned->preparationPlan ;	// 原session/plan/全targetです。
				DRIVERCRATE_EXPECT( context,
								   plan.targets.size() == testCase.targets &&
									   Access::controller( window).preparationPlan() != nullptr) ;
				// 全原targetの全文・改訂・出典が本物の共通HTML検証から得られた事実を照合します。
				for( const auto &target : plan.targets) {
					DRIVERCRATE_EXPECT(
						context,
						target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
							target.eulaRevision == L"Original 1.0" &&
							target.eulaSourceSubject ==
								L"fixture-source (https://vendor.example/)" &&
							target.eulaText ==
								L"Original 1.0\r\n\r\nFictional complete driver license.\r\n\r\nOriginal terms line two.\r\n") ;
				}

				Access::rejectIndexConsentChanges( window, context, plan) ;
				const auto beforeOperation =
					// 未承認時の元operationです。
					Access::controller( window).activeOperationId() ;
				DialogState approval{.htmlTerms = true,
									 .context	= &context,
									 .owner		= handle,
									 .mode		= testCase.decision} ;	// 同UI threadの一判断です。
				*expired = testCase.expired ;
				{
					DialogDriver driver( approval) ;	// 元modal loopのtimerを同scopeで回収します。
					Access::reviewIndexPlan( window) ;
				}
				DRIVERCRATE_EXPECT( context, approval.handled && !approval.failed &&
												approval.eulaValid && approval.eulaDialogs == 1U) ;
				// 三つの明示拒否は元sessionを保持し、payloadもactive取得taskも作りません。
				if( testCase.decision != DialogMode::INDEX_PREPARATION_ACCEPT) {
					DRIVERCRATE_EXPECT(
						context,
						Access::controller( window).state() == ApplicationState::SCAN_READY &&
							Access::controller( window).activeOperationId() == beforeOperation &&
							Access::indexApproval( window).operationId == 0U &&
							input.observeHttp().sends == scanHttp.sends) ;
					DRIVERCRATE_EXPECT(
						context,
						approval.acquisitionDecisionDialogs ==
								(testCase.decision == DialogMode::INDEX_PREPARATION_CANCEL ? 0U
																						   : 1U) &&
							approval.finalConfirmationDialogs ==
								(testCase.decision == DialogMode::INDEX_PREPARATION_FINAL_NO ? 1U
																							 : 0U)) ;
					break ;
				}

				const auto originalApproval =
					// 通常commandが確定した元snapshotです。
					Access::indexApproval( window) ;
				DRIVERCRATE_EXPECT( context,
								   originalApproval.operationId != 0U &&
									   originalApproval.operationId ==
										   Access::controller( window).activeOperationId() &&
									   originalApproval.scanSessionId == plan.scanSessionId &&
									   originalApproval.planId == plan.planId &&
									   originalApproval.decisions.size() == plan.targets.size() &&
									   Access::controller( window).state() ==
										   ApplicationState::PREPARING &&
									   approval.acquisitionDecisionDialogs == testCase.targets &&
									   approval.finalConfirmationDialogs == 1U) ;
				// 元全対象にだけ今回の明示判断が結合され、同意や取得IDの差替えがないことを検査します。
				for( std::size_t index{}; index < originalApproval.decisions.size(); ++index) {
					const auto &decision =
						originalApproval.decisions[index] ;	// 一原targetへの今回の判断です。
					DRIVERCRATE_EXPECT( context, index < plan.targets.size() &&
													decision.target == plan.targets[index] &&
													decision.acquire && decision.eulaAccepted &&
													!decision.restrictedNetworkApproved) ;
				}

				auto prepared = Access::takeIndexTerminal(
					window, WorkerEventKind::PREPARATION_COMPLETED) ;	// 同実workerの終端です。
				DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
				// 元active taskを通した終端の欠損は成功へ補完しません。
				if( !prepared) {
					break ;
				}

				DRIVERCRATE_EXPECT(
					context,
					prepared->operationId == originalApproval.operationId &&
						prepared->preparationResult.operationId == originalApproval.operationId &&
						prepared->preparationResult.scanSessionId == plan.scanSessionId &&
						prepared->preparationResult.planId == plan.planId &&
						prepared->preparationResult.approvalError ==
							OfficialPreparationError::NONE &&
						prepared->preparationResult.controlError == 0U &&
						prepared->preparationResult.items.size() == testCase.targets &&
						prepared->indexPreparation.items.size() == testCase.targets) ;
				std::vector<UpdateCandidate>
					candidates ;	// 原publicationからだけ所有する通常候補です。
				// 元worker内の同grant/CAT/INF/native/fullrankから発行された候補だけを保持します。
				for( const auto &report : prepared->preparationResult.auditReports) {
					candidates.insert( candidates.end(), report.publishedCandidates.begin(),
									  report.publishedCandidates.end()) ;
				}

				DRIVERCRATE_EXPECT( context, candidates.size() == testCase.candidates) ;
				// SYSTEM Needsは実選択計画の前提一件で、追加INFの件数へ変換しません。
				if( std::string_view( testCase.id) == "Q12" && candidates.size() == 1U) {
					const auto &candidate = candidates.front() ;	// 元本体が発行した同候補です。
					DRIVERCRATE_EXPECT( context,
									   candidate.requiredExtensionCount == 0U &&
										   candidate.requiredDriverComponentCount == 0U &&
										   candidate.assessment &&
										   candidate.assessment->explicitRequirements.size() == 1U) ;
					// 不足したassessmentを想定値で補完せず、実一前提だけを検証します。
					if( candidate.assessment &&
					   candidate.assessment->explicitRequirements.size() == 1U) {
						const auto &requirement = candidate.assessment->explicitRequirements
													  .front() ;	// 同実選択Needsの根拠です。
						DRIVERCRATE_EXPECT(
							context,
							requirement.role == CandidateComponentRole::BASE_DRIVER &&
								requirement.required &&
								requirement.state == CandidateRequirementState::SATISFIED &&
								requirement.evidenceKind ==
									CandidateEvidenceKind::PACKAGE_INSPECTION &&
								candidate.assessment->requirements.state ==
									CandidateAssessmentState::PASSED &&
								isCandidateAssessmentReady( *candidate.assessment)) ;
					}
				}

				// 非選択OS節だけのNeedsは同graphの前提にも追加INFにも混入しません。
				if( std::string_view( testCase.id) == "Q14" && candidates.size() == 1U) {
					const auto &candidate = candidates.front() ;	// 同実選択から発行された候補です。
					DRIVERCRATE_EXPECT( context,
									   candidate.requiredExtensionCount == 0U &&
										   candidate.requiredDriverComponentCount == 0U &&
										   candidate.assessment &&
										   candidate.assessment->explicitRequirements.empty() &&
										   candidate.assessment->requirements.reason ==
											   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT &&
										   isCandidateAssessmentReady( *candidate.assessment)) ;
				}

				// 同active taskの元target identityと実byte/content結果を別に照合します。
				for( std::size_t index{}; index < prepared->preparationResult.items.size();
					++index) {
					DRIVERCRATE_EXPECT( context,
									   index < plan.targets.size() &&
										   index < prepared->indexPreparation.items.size() &&
										   prepared->preparationResult.items[index].identity ==
											   plan.targets[index].identity &&
										   prepared->indexPreparation.items[index].targetIdentity ==
											   plan.targets[index].identity) ;
				}

				// 内容正常候補は同実取得seal・CATとWindows rankを通り、参照rowから昇格していません。
				if( testCase.candidates != 0U) {
					DRIVERCRATE_EXPECT(
						context,
						!prepared->preparationResult.items.empty() &&
							!prepared->indexPreparation.items.empty() &&
							prepared->preparationResult.items.front().result.state ==
								OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
							prepared->preparationResult.items.front().result.byteCount ==
								input.payload.size() &&
							prepared->indexPreparation.items.front().inputBound &&
							prepared->indexPreparation.items.front().content ==
								IndexedDriverInspectionState::INSPECTION_COMPLETED &&
							prepared->indexPreparation.items.front().acceptedInfCount != 0U &&
							bound.observe().signature.setupCalls != 0U &&
							bound.observe().rankCalls != 0U) ;
				}

				// 共有descriptorは一取得target/一payloadを元二deviceへ結びます。
				if( testCase.shared) {
					DRIVERCRATE_EXPECT( context, plan.targets.size() == 1U &&
													plan.targets.front().deviceCount == 2U &&
													candidates.size() == 2U &&
													candidates[0].packageIdentity ==
														candidates[1].packageIdentity) ;
				}

				// 第二targetの元hash拒否を第一内容成功や全体control成功で隠しません。
				if( testCase.options.corruptSecondPayload) {
					DRIVERCRATE_EXPECT(
						context, prepared->preparationResult.items.size() == 2U &&
									 prepared->indexPreparation.items.size() == 2U &&
									 prepared->preparationResult.items[1].result.error != 0U &&
									 prepared->preparationResult.items[1].result.byteCount == 0U &&
									 prepared->indexPreparation.items[1].acquisitionError != 0U &&
									 prepared->indexPreparation.items[1].acceptedInfCount == 0U) ;
				}

				Access::dispatchIndex( window, *prepared) ;
				const auto published = std::ranges::count_if(
					Access::indexCandidates( window), []( const auto &candidate) {
						return candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
							   candidate.installable ;
					}) ; // 実通常Windowが受理したinstallable索引候補だけです。
				DRIVERCRATE_EXPECT( context,
								   static_cast<std::size_t>( published) == testCase.candidates &&
									   Access::controller( window).state() ==
										   ApplicationState::SCAN_READY) ;
			} while( false) ;
		} catch( ...) {
			Access::stopWorker( window) ;
			// 元例外時も同scopeのWindowだけを回収します。
			if( IsWindow( handle)) {
				DestroyWindow( handle) ;
			}

			throw ;
		}

		const auto http = input.observeHttp() ;	// 原終端または未開始の同期観測です。
		DRIVERCRATE_EXPECT( context, http.sends == testCase.termsGets + testCase.payloadGets &&
										http.safe && http.opens == http.closes &&
										http.cookieDisabled == testCase.termsGets &&
										http.cacheControlHeaders == testCase.termsGets) ;
		DRIVERCRATE_EXPECT( context, bound.observe().stages == 0U &&
										bound.observe().installs == 0U &&
										bound.observe().restoreBegins == 0U &&
										bound.observe().restoreCompletes == 0U &&
										bound.observeInstaller().launches == 0U) ;
		const auto observedCandidates =
			std::ranges::count_if( Access::indexCandidates( window), []( const auto &candidate) {
				return candidate.providerId == SIGNED_INDEX_PROVIDER_ID && candidate.installable ;
			}) ; // 通常Windowに保持された実publication数で、期待値を代入しません。
		std::cout << "PREPARATION_COMMAND case=" << testCase.id
				  << " failures=" << context.failureCount() - caseFailures
				  << " fakeTerms=" << testCase.termsGets << " fakePayload="
				  << (http.sends >= testCase.termsGets ? http.sends - testCase.termsGets : 0U)
				  << " expectedCandidates=" << testCase.candidates
				  << " observedCandidates=" << observedCandidates
				  << " preparationEnabled=" << preparationEnabledBeforeCommand
				  << " commandOperationPositive="
				  << (Access::indexApproval( window).operationId != 0U)
				  << " rank=" << bound.observe().rankCalls
				  << " realGet=0 realContentPositive=0 install=0 restore=0\n" ;
		Access::stopWorker( window) ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
		// 同scopeが所有するWindowだけを回収し、次の固定caseへ進みます。
		if( IsWindow( handle)) {
			DestroyWindow( handle) ;
		}

		DRIVERCRATE_EXPECT( context, state->normalCalls == 0U && state->metadataCalls == 0U &&
										state->officialCalls == 0U && state->restoreCalls == 0U &&
										state->forbiddenCalls == 0U) ;
	}

	std::cout << "Preparation command cases: " << cases.size()
			  << ", assertions: " << context.assertionCount() - before
			  << ", failures: " << context.failureCount() - failures
			  << ", actual task/publication via production guards, real content UNCONFIRMED\n" ;
}

/** @brief 元承認taskの所有copyへ一field差だけを与える固定条件です。 */
enum class ApprovedIndexTaskMutation {
	/// 同期観測を登録しない従来条件です。
	NONE,
	/// 元規約subjectだけを変更します。
	SUBJECT,
	/// 元規約revisionだけを変更します。
	REVISION,
	/// 元target collectionのcardinalityだけを変更します。
	TARGET_COLLECTION
} ;

/** @brief 同worker callbackが書き、実終端後のUIだけが読む一taskの原観測です。 */
struct ApprovedIndexTaskProbeReceipt {
	/// 実claimした元taskの所有copyです。成功DTOやgrantを構築しません。
	std::optional<OfficialPreparationTask> task ;
	/// 変更copyに対する本物adapterの原拒否HRESULTです。
	NativeError							   error{} ;
	/// 拒否後の未発行grant IDです。
	std::uint64_t						   grantId{} ;
	/// 拒否後の元grant状態です。
	OfficialDownloadGrantState			   grantState{OfficialDownloadGrantState::NOT_REQUESTED} ;
	/// 元taskがprivate active taskと一致した場合trueです。
	bool								   originalOwnedBefore{} ;
	/// 改変前の同じ所有copyもprivate active taskと完全一致した場合trueです。
	bool								   unchangedCopyOwned{} ;
	/// 変更copyのoperation/scan/planと元opaque target identityを維持した場合trueです。
	bool								   opaqueTaskIdentityPreserved{} ;
	/// 変更copyもprivate active taskと一致した場合trueです。期待はfalseです。
	bool								   changedOwned{} ;
	/// 拒否後も元taskがprivate active taskに保持された場合trueです。
	bool								   originalPreserved{} ;
	/// 拒否前後のsession stateが完全一致した場合trueです。
	bool								   stateUnchanged{} ;
	/// 元全対象のidentity/state/error/byte数が完全一致した場合trueです。
	bool								   itemsUnchanged{} ;
	/// 元総数と確定数が完全一致した場合trueです。
	bool								   progressUnchanged{} ;
	/// 同workerの同期点でHTTP全counterが完全一致した場合trueです。
	bool								   httpUnchanged{} ;
	/// 元scan summaryの対象/内容件数/権限診断が完全一致した場合trueです。
	bool								   contentUnchanged{} ;
	/// 拒否だけのHTTP送信増分です。
	std::uint32_t						   additionalHttp{} ;
	/// 拒否だけの内容結果件数増分です。
	std::size_t							   additionalContent{} ;
} ;

/** @brief Workerのstop/joinまでUIと低位fixture callbackが共有所有する同期観測です。 */
struct ApprovedIndexTaskProbeState {
	/// 元固定T03/T04/T05の一field条件です。
	ApprovedIndexTaskMutation					  mutation{ApprovedIndexTaskMutation::NONE} ;
	/// 同workerのgrant直前だけ借用する低位HTTP counter観測です。
	std::function<SignedIndexUiHttpObservation()> observeHttp ;
	/// 同workerへの一回登録が成功した場合trueです。
	bool										  registered{} ;
	/// Callback内のallocation等で例外を観測した場合trueです。未受入として残します。
	bool										  failed{} ;
	/// 登録した実workerのthread IDです。UIとは別でなければ拒否します。
	DWORD										  workerThread{} ;
	/// 同workerで観測した実claim済みtask数です。
	std::size_t									  calls{} ;
	/// 最大二targetの独立した原拒否観測です。
	std::array<ApprovedIndexTaskProbeReceipt, 2U> receipts{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 実claim済み元taskのcopyだけを変え、本物grant発行の拒否と不変状態を観測します。
 * @param[in,out] state 同workerのstop/joinまで共有所有する非null観測stateです。
 * @param[in,out] preparation 元workerがapprove/claimNextした実sessionです。同期中だけ借用します。
 * @param[in] task 同じprivate active taskの未変更所有値です。参照を保持せずcopyします。
 * @param[in,out] adapter 同原lookup/recordの実adapterです。変更copyの拒否だけを観測します。
 * @param[in] context 元worker/scan/inventoryの全contextです。
 * @param[in] nowUtcSeconds 元grant発行前に再照会した信頼UTC秒です。
 * @param[in] scan 同workerの元summary所有者です。同期中だけ借用し内容処理を開始しません。
 * @note 例外はfailedへ保存し、元状態を復元しません。UI assertionは実終端の同期後だけです。
 */
//------------------------------------------------------------------------------
void observeApprovedIndexTask( void *state, OfficialPreparationSession &preparation,
							  const OfficialPreparationTask &task,
							  SignedIndexAcquisitionAdapter &adapter, IndexLookupContext context,
							  std::uint64_t					nowUtcSeconds,
							  const SignedIndexScanSession &scan) noexcept
{
	// 登録時にworker lifetimeへ結合した非所有stateです。
	auto &probe = *static_cast<ApprovedIndexTaskProbeState *>( state) ;
	// 元固定二対象を超える実claimを無言に切り捨てません。
	if( probe.calls >= probe.receipts.size()) {
		probe.failed = true ;
		return ;
	}

	auto &receipt = probe.receipts[probe.calls++] ;	// 同期後に読む元taskの独立slotです。
	try {
		receipt.task			   = task ;
		auto changed			   = task ;	// 改変は元taskを借用せず所有copyだけへ行います。
		receipt.unchangedCopyOwned = preparation.ownsActiveTask( changed) ;
		// 元契約ごとに一fieldだけを変更し、他条件を保持します。
		switch( probe.mutation) {
			// T03は承認済み規約の出典subjectだけを変えます。
			case ApprovedIndexTaskMutation::SUBJECT:
				changed.target.eulaSourceSubject += L"changed" ;
				break ;

			// T04は承認済み規約のrevisionだけを変えます。
			case ApprovedIndexTaskMutation::REVISION:
				changed.target.eulaRevision += L"changed" ;
				break ;

			// T05は元collectionの対象数だけを変え、全taskを不一致にします。
			case ApprovedIndexTaskMutation::TARGET_COLLECTION:
				++changed.target.deviceCount ;
				break ;

			// 未指定条件から正しいtaskを試験都合で消費しません。
			default:
				probe.failed = true ;
				return ;
		}

		const auto stateBefore				= preparation.state() ;	// 元session区分です。
		receipt.opaqueTaskIdentityPreserved = changed.operationId == task.operationId &&
											  changed.scanSessionId == task.scanSessionId &&
											  changed.planId == task.planId &&
											  changed.target.identity == task.target.identity &&
											  changed.target.providerId == task.target.providerId ;
		const auto progressBefore = preparation.progress() ;	// 元選択総数/確定数です。
		const std::vector<OfficialPreparationItem> itemsBefore{	// 元全対象の所有snapshotです。
															   preparation.items().begin(),
															   preparation.items().end()} ;
		const auto httpBefore = probe.observeHttp() ;							// HTTP callと並行しない同worker同期観測です。
		const auto contentBefore = scan.preparationSummary( task.operationId) ;	// 元内容結果です。
		RecordScopedDownloadGrant rejected ;									// 本物の未発行grantです。metadataを合成しません。
		receipt.originalOwnedBefore = preparation.ownsActiveTask( task) ;
		receipt.changedOwned		= preparation.ownsActiveTask( changed) ;
		receipt.error =
			adapter.claimApprovedRecord( preparation, changed, context, nowUtcSeconds, rejected) ;
		receipt.grantId			  = rejected.metadata().grantId ;
		receipt.grantState		  = rejected.metadata().state ;
		receipt.originalPreserved = preparation.ownsActiveTask( task) && task == *receipt.task ;
		receipt.stateUnchanged	  = preparation.state() == stateBefore ;
		// 同期中だけ借用する元/現在の対象を比較し、原HRESULTとbyte数も保持します。
		receipt.itemsUnchanged = std::ranges::equal(
			itemsBefore, preparation.items(), []( const auto &before, const auto &after) {
				return before.identity == after.identity &&
					   before.result.state == after.result.state &&
					   before.result.error == after.result.error &&
					   before.result.byteCount == after.result.byteCount ;
			}) ;
		const auto progressAfter  = preparation.progress() ;	// 拒否後も元taskは進行中です。
		receipt.progressUnchanged = progressAfter.total == progressBefore.total &&
									progressAfter.completed == progressBefore.completed ;
		const auto httpAfter = probe.observeHttp() ;	// 元拒否によるHTTP増分だけを比較します。
		receipt.httpUnchanged =
			httpAfter.sends == httpBefore.sends && httpAfter.opens == httpBefore.opens &&
			httpAfter.closes == httpBefore.closes && httpAfter.safe == httpBefore.safe &&
			httpAfter.cookieDisabled == httpBefore.cookieDisabled &&
			httpAfter.cacheControlHeaders == httpBefore.cacheControlHeaders ;
		receipt.additionalHttp = httpAfter.sends - httpBefore.sends ;
		const auto contentAfter =
			// 検査未開始を保持します。
			scan.preparationSummary( task.operationId) ;
		receipt.contentUnchanged = contentAfter.items.size() == contentBefore.items.size() &&
								   contentAfter.authorityError == contentBefore.authorityError &&
								   contentAfter.plannedTargets == contentBefore.plannedTargets ;
		receipt.additionalContent = contentAfter.items.size() - contentBefore.items.size() ;
	} catch( ...) {
		// 元状態を作り直さず、観測失敗をUIのassertionへ残します。
		probe.failed = true ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 固定した規約・条件・CAB・installerを真署名/同worker/本物画面へ通します。
 * @param[in,out] context 元assertion集計先です。
 * @param[in] orderProbe 空は元29case、非空は確認要否に応じた一caseの有限順序試験です。
 * @note 原失敗や未到達を保持し、成功DTOまたは実network/起動を使用しません。
 */
//------------------------------------------------------------------------------
void runSignedIndexConsentFormatUiScenarios( TestContext			  &context,
											const std::string_view orderProbe = {})
{
	// 大きな終端値を短命なfactory内で受信し、元の検証scopeだけで所有する。
	const auto ownTerminal = []( auto make) { return std::make_unique<decltype( make())>( make()) ; } ;
	using Native		   = SignedIndexBindingNativeCase ;	// 完全低位境界の原状態です。
	using Format		   = IndexPayloadFormat ;			// 元codecの既存形式です。
	/** @brief Code前case-contractからの有限入力と原期待です。 */
	struct Case {
		/// 原固定期待の一意IDです。
		const char				 *id ;
		/// 真署名へ含める元規約/条件/形式です。
		SignedIndexUiOptions	  options ;
		/// 原低位署名/起動/現在状態です。
		Native					  native ;
		/// 原共有二deviceを明示選択する場合trueです。
		bool					  shared ;
		/// 元取得target数の期待です。
		std::size_t				  targets ;
		/// 原検査からの発行数の期待です。
		std::size_t				  candidates ;
		/// 復旧開始だけ拒否する条件です。
		bool					  restoreFailure ;
		/// 公表後に信頼UTCだけを元期限外へ移す条件です。
		bool					  expired ;
		/// 全保護workflowの原成功期待です。
		bool					  succeeded ;
		/// 元scan完了後・payload claim前だけUTCを期限外へ変更します。
		bool					  expiredBeforePreparation{} ;
		/// 元R04を同Windowの正常終端からworker stale拒否まで直接確認する場合trueです。
		bool					  verifyTerminalReuse{} ;
		/// 元E07の明示NOだけで終了し、元一覧を保持する場合trueです。
		bool					  verifyHandoffNo{} ;
		/// 同workerの実claim後に変更copyだけを照合する条件です。
		ApprovedIndexTaskMutation taskMutation{ApprovedIndexTaskMutation::NONE} ;
	} ;
	// 元scopeだけで使用する有限な検査値です。未知を成功へ補完しません。
	const std::array cases{
		Case{"T01", {.termsRequired = true}, Native::NORMAL, false, 1U, 1U, false, false, true},
		Case{"T02",
			 {.termsRequired = true, .corruptTerms = true},
			 Native::NORMAL,
			 false,
			 0U,
			 0U,
			 false,
			 false,
			 false},
		Case{"T03",
			 {.termsRequired = true},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 true,
			 false,
			 false,
			 false,
			 ApprovedIndexTaskMutation::SUBJECT},
		Case{"T04",
			 {.termsRequired = true},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 true,
			 false,
			 false,
			 false,
			 ApprovedIndexTaskMutation::REVISION},
		Case{"T05",
			 {.termsRequired = true, .secondTermsSubject = true},
			 Native::SHARED_SUCCESS,
			 true,
			 2U,
			 2U,
			 false,
			 false,
			 true,
			 false,
			 false,
			 false,
			 ApprovedIndexTaskMutation::TARGET_COLLECTION},
		Case{"T08",
			 {.termsRequired = true},
			 Native::SHARED_SUCCESS,
			 true,
			 1U,
			 2U,
			 false,
			 false,
			 true},
		Case{"T06",
			 {.termsRequired = true},
			 Native::NORMAL,
			 false,
			 1U,
			 0U,
			 false,
			 false,
			 false,
			 true},
		Case{"T07",
			 {.termsRequired = true, .secondTermsSubject = true},
			 Native::SHARED_SUCCESS,
			 true,
			 2U,
			 2U,
			 false,
			 false,
			 true},
		Case{"T09",
			 {.termsRequired = true, .secondTermsRevision = true},
			 Native::SHARED_SUCCESS,
			 true,
			 2U,
			 2U,
			 false,
			 false,
			 true},
		Case{"P01",
			 {.prerequisite = IndexPrerequisiteKind::USER_CONFIRMATION},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 true},
		Case{"P02",
			 {.prerequisite = IndexPrerequisiteKind::LOCAL_CHECK},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 true},
		Case{"P03",
			 {.prerequisite = IndexPrerequisiteKind::LOCAL_CHECK, .unknownLocal = true},
			 Native::NORMAL,
			 false,
			 0U,
			 0U,
			 false,
			 false,
			 false},
		Case{"P04",
			 {.prerequisite = IndexPrerequisiteKind::INSEPARABLE_FIRMWARE},
			 Native::NORMAL,
			 false,
			 0U,
			 0U,
			 false,
			 false,
			 false},
		Case{"P05", {}, Native::NORMAL, false, 1U, 1U, false, false, true},
		Case{"C01", {.format = Format::CABINET}, Native::NORMAL, false, 1U, 1U, false, false, true},
		Case{"C02",
			 {.format = Format::CABINET, .corruptPayload = true},
			 Native::NORMAL,
			 false,
			 1U,
			 0U,
			 false,
			 false,
			 false},
		Case{"C03",
			 {.format = Format::CABINET},
			 Native::CAB_MEMBER_FAILURE,
			 false,
			 1U,
			 0U,
			 false,
			 false,
			 false},
		Case{"E01",
			 {.format = Format::WINDOWS_EXE},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 true},
		Case{"E02",
			 {.format = Format::WINDOWS_MSI},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 true},
		Case{"E03",
			 {.format = Format::WINDOWS_EXE},
			 Native::INSTALLER_SIGNATURE_FAILURE,
			 false,
			 1U,
			 0U,
			 false,
			 false,
			 false},
		Case{"E04",
			 {.format = Format::WINDOWS_EXE},
			 Native::INSTALLER_PUBLISHER_FAILURE,
			 false,
			 1U,
			 0U,
			 false,
			 false,
			 false},
		Case{"E05",
			 {.format = Format::WINDOWS_EXE, .wrongScope = true},
			 Native::NORMAL,
			 false,
			 0U,
			 0U,
			 false,
			 false,
			 false},
		Case{"E06",
			 {.format = Format::WINDOWS_EXE},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 true,
			 false},
		Case{"E07",
			 {.format = Format::WINDOWS_EXE},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 false,
			 false,
			 false,
			 true},
		Case{"E08",
			 {.format = Format::WINDOWS_EXE},
			 Native::INSTALLER_LAUNCH_FAILURE,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 false},
		Case{"R01",
			 {.format = Format::WINDOWS_EXE},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 true,
			 false,
			 false},
		Case{"R02",
			 {.format = Format::WINDOWS_MSI},
			 Native::RESTORE_END_FAILURE,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 false},
		Case{"R03", {}, Native::NORMAL, true, 1U, 2U, false, false, false},
		Case{"R04",
			 {.termsRequired = true},
			 Native::NORMAL,
			 false,
			 1U,
			 1U,
			 false,
			 false,
			 true,
			 false,
			 true}} ;
	// 原assertion分母の開始値です。既存分母を削減しません。
	const auto	before	 = context.assertionCount() ;
	const auto	failures = context.failureCount() ;	// 原集計です。
	std::size_t executed{} ;						// 元29caseと独立T01順序試験を混同しない実行数です。
	// 全固定caseを保持し、一条件の未到達を分母から除外しません。
	for( const auto &testCase : cases) {
		// 明示NO/WM_QUITは確認必須のinstaller、他の順序は通常INFで検査します。
		const auto orderCase = orderProbe == "no" || orderProbe == "quit" ? "E01" : "T01" ;
		// 明示拒否を含む独立順序だけ対象caseを絞ります。
		if( !orderProbe.empty() && std::string_view{testCase.id} != orderCase) {
			continue ;
		}

		++executed ;
		// 元一caseの失敗開始数です。未到達を成功へ補完しません。
		const auto caseFailures = context.failureCount() ;
		MSG		   previousQuit{} ;	// 前の独立Windowが発行した終了通知です。
		// 製品の終了通知を変更せず、次caseの実modal loopへだけ持ち越しません。
		while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
		}

		// 真署名・strictschema・保護commit/reloadから生成する元入力です。
		auto input = makeSignedIndexUiInput( testCase.shared, testCase.shared, false, false, false,
											false, testCase.options) ;
		auto expired =
			std::make_shared<bool>( false) ;	// 同UIからidle workerへだけ渡す原UTC条件です。
		// 元fixtureが保持する信頼UTC callbackです。
		const auto clock = input.services.utc ;
		/** @brief 原信頼UTCだけを期限拒否の一要因へ変更します。
		 * @return 元UTCまたは元期限外UTCです。現在状態や成功DTOを変更しません。
		 */
		input.services.utc = [clock, expired]() {
			// 原UTCまたは原Windows出力です。未確認を合格へ補完しません。
			auto value = clock() ;
			// 公表後の原UTCだけを期限外へ移し、許可期限を延長しません。
			if( *expired && value) {
				*value += std::chrono::days{2} ;
			}

			return value ;
		} ;
		// 元recordのEXE/MSI方式だけを標準INFと区別します。
		const bool installer = testCase.options.format == Format::WINDOWS_EXE ||
							   testCase.options.format == Format::WINDOWS_MSI ;
		// 完全低位fakeを所有する実COM MTA workerです。
		auto probe =
			std::make_shared<ApprovedIndexTaskProbeState>() ;	// Worker停止までの共有所有です。
		probe->mutation	   = testCase.taskMutation ;
		probe->observeHttp = input.observeHttp ;
		std::function<void()> observeWorkerStart ;	// 従来条件は登録しない空callbackです。
		// 元T03/T04/T05だけで低位署名scope開始時に同workerへ観測を登録します。
		if( testCase.taskMutation != ApprovedIndexTaskMutation::NONE) {
			// 所有captureがworker停止までstateを保持し、登録は同workerから一度だけ行います。
			observeWorkerStart = [probe]() noexcept {
				probe->workerThread = GetCurrentThreadId() ;
				probe->registered =
					signed_index_task_observer_detail::registerApprovedIndexTaskObserver(
						&observeApprovedIndexTask, probe.get()) ;
			} ;
		}

		/** @brief 同workerのfake復旧前だけを所有付き信号で有限停止します。 */
		struct InstallGate {
			/// Workerが復旧前の同期点へ到達したことをUIへ通知します。
			std::binary_semaphore entered{0} ;
			/// 同期点を観測したUIだけがworkerを明示再開します。
			std::binary_semaphore resume{0} ;
			/// 五秒の内部待機を超えた場合trueです。通常成功へ補完しません。
			std::atomic_bool	  timedOut{} ;
		} ;
		auto				  installGate = orderProbe == "hold" ? std::make_shared<InstallGate>()
																 : nullptr ;	// 制御遅延だけの共有所有です。
		std::function<void()> beforeRestore ;									// 通常29caseでは空の元動作です。
		// 独立した制御遅延だけへ有限barrierを設定し、元T01入力を変更しません。
		if( orderProbe == "hold") {
			// 共有所有する信号だけを借用し、非atomic counterは読取りません。
			beforeRestore = [installGate]() {
				installGate->entered.release() ;
				installGate->timedOut =
					!installGate->resume.try_acquire_for( std::chrono::seconds{5}) ;
			} ;
		}

		// 完全低位fakeを所有する同workerを本物Windowへ結びます。
		auto bound = makeSignedIndexBindingWorker(
			input.services, input.zip, testCase.shared, testCase.restoreFailure, false,
			testCase.native, installer ? std::string_view{input.payload} : std::string_view{},
			std::move( observeWorkerStart), std::move( beforeRestore)) ;
		// 本物Windowが所有する内部の誤呼出し観測です。
		auto	   state = std::make_shared<MetadataUiState>() ;
		// 製品resourceを使用する本物MainWindowです。
		const auto windowOwner =
			std::make_unique<MainWindow>() ;	// 同じscopeだけで大きなfixtureを所有する。
		auto &window = *windowOwner ;			// 所有者と同じcaseの期間だけ本物Windowを借用する。
		Access::configure( window, state) ;
		// 本物Window生成の実結果です。未生成を未到達へ残します。
		const bool created = window.create( GetModuleHandleW( nullptr)) ;
		DRIVERCRATE_EXPECT( context, created) ;
		// 本物Windowの不成立は当該元caseの失敗へ残します。
		if( !created) {
			bound.worker->stop() ;
			continue ;
		}

		// 同試験scopeだけで借用する本物Window handleです。
		const auto handle = Access::handle( window) ;
		ShowWindow( handle, SW_HIDE) ;
		Access::attachIndexWorker( window, std::move( bound.worker)) ;
		try {
			// 有限な原対象または当該一caseだけを走査し、未到達は元失敗へ残します。
			do {
				Access::beginIndexScan( window) ;
				// 元workerが返す実scan終端です。成功DTOを作りません。
				const auto scannedOwner = ownTerminal( [&] {
					return Access::takeIndexTerminal( window, WorkerEventKind::SCAN_COMPLETED) ;
				}) ;										 // 同workerの元終端だけを所有する。
				auto	  &scanned		= *scannedOwner ;	// 元caseの期間だけ終端値を借用する。
				DRIVERCRATE_EXPECT( context,
								   scanned && scanned->scanResult.succeeded &&
									   (scanned->preparationPlan || testCase.targets == 0U)) ;
				// 元scan終端なしでは候補・plan・承認を合成しません。
				if( !scanned || !scanned->preparationPlan) {
					DRIVERCRATE_EXPECT( context, testCase.targets == 0U &&
													bound.observe().stages == 0U &&
													bound.observe().installs == 0U &&
													bound.observeInstaller().launches == 0U) ;
					break ;
				}

				Access::dispatchIndex( window, *scanned) ;
				// 同scanが発行した元取得対象の完全計画です。
				const auto &plan = *scanned->preparationPlan ;
				DRIVERCRATE_EXPECT( context, plan.targets.size() == testCase.targets) ;
				// 二元recordの同Provider・異terms条件を真署名からの実planで確認します。
				if( testCase.options.secondTermsSubject || testCase.options.secondTermsRevision) {
					DRIVERCRATE_EXPECT(
						context, plan.targets.size() == 2U &&
									 plan.targets[0].providerId == plan.targets[1].providerId &&
									 plan.targets[0].identity != plan.targets[1].identity) ;
					// 未到達の二対象を先頭の成功だけで補完しません。
					if( plan.targets.size() != 2U) {
						break ;
					}

					DRIVERCRATE_EXPECT( context,
									   testCase.options.secondTermsSubject
										   ? plan.targets[0].eulaSourceSubject !=
												 plan.targets[1].eulaSourceSubject
										   : plan.targets[0].eulaSourceSubject ==
													 plan.targets[1].eulaSourceSubject &&
												 plan.targets[0].eulaRevision == L"Original 1.0" &&
												 plan.targets[1].eulaRevision == L"Original 2.0") ;
				}

				// 理由付き保留・形式拒否を取得成功へ数えません。
				if( plan.targets.empty()) {
					DRIVERCRATE_EXPECT( context, bound.observe().installs == 0U &&
													bound.observeInstaller().launches == 0U) ;
					break ;
				}

				// 元全文・出典・revision・対象の一field差替えをgrant発行前に実拒否します。
				if( testCase.options.termsRequired) {
					Access::rejectIndexConsentChanges( window, context, plan) ;
					// 同意拒否前の低位GET数です。Payload送信0を別確認します。
					const auto	sends = input.observeHttp().sends ;
					// 本物dialogの既定拒否を操作する短命状態です。
					DialogState cancel{.context = &context,
									   .owner	= handle,
									   .mode	= DialogMode::INDEX_PREPARATION_CANCEL} ;
					cancel.secondTermsSubject  = testCase.options.secondTermsSubject ;
					cancel.secondTermsRevision = testCase.options.secondTermsRevision ;
					{
						// 同scopeの実dialog timerを終端まで所有します。
						DialogDriver driver( cancel) ;
						Access::reviewIndexPlan( window) ;
					}
					DRIVERCRATE_EXPECT(
						context,
						cancel.handled && !cancel.failed &&
							cancel.eulaDialogs == (testCase.options.secondTermsSubject ||
														   testCase.options.secondTermsRevision
													   ? 2U
													   : 1U) &&
							cancel.eulaValid && input.observeHttp().sends == sends &&
							bound.observe().installs == 0U &&
							bound.observeInstaller().launches == 0U &&
							Access::controller( window).state() == ApplicationState::SCAN_READY) ;
					std::cout << "FORMAT_EULA_NO case=" << testCase.id
							  << " groups=" << cancel.eulaDialogs << " exact=" << cancel.eulaValid
							  << " additionalHttp=" << input.observeHttp().sends - sends
							  << " install=" << bound.observe().installs
							  << " launch=" << bound.observeInstaller().launches << '\n' ;
				}

				// 元取得全文と条件への本物dialogの明示判断です。
				DialogState approval{.context = &context,
									 .owner	  = handle,
									 .mode	  = DialogMode::INDEX_PREPARATION_ACCEPT} ;
				approval.secondTermsSubject	 = testCase.options.secondTermsSubject ;
				approval.secondTermsRevision = testCase.options.secondTermsRevision ;
				*expired =
					testCase.expiredBeforePreparation ;	// 原scan後・payload claim前だけのUTC差です。
				{
					// 同scopeの実dialog timerを終端まで所有します。
					DialogDriver driver( approval) ;
					Access::reviewIndexPlan( window) ;
				}
				DRIVERCRATE_EXPECT( context,
								   approval.handled && !approval.failed && approval.eulaValid &&
									   approval.eulaDialogs ==
										   (testCase.options.termsRequired
												? (testCase.options.secondTermsSubject ||
														   testCase.options.secondTermsRevision
													   ? 2U
													   : 1U)
												: 0U)) ;
				// 原取得・内容検査の実worker終端です。
				const auto preparedOwner = ownTerminal( [&] {
					return Access::takeIndexTerminal( window,
													 WorkerEventKind::PREPARATION_COMPLETED) ;
				}) ;										   // 同workerの元終端だけを所有する。
				auto	  &prepared		 = *preparedOwner ;	// 元caseの期間だけ終端値を借用する。
				DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
				// 元worker終端を受けていなければ成功DTOを合成せず当該caseを止めます。
				if( !prepared) {
					break ;
				}

				// 原共通検査と私有bindingから発行された候補だけを保持します。
				std::vector<UpdateCandidate> candidates ;
				// 本体公開reportからだけ元候補を取得します。
				for( const auto &report : prepared->preparationResult.auditReports) {
					candidates.insert( candidates.end(), report.publishedCandidates.begin(),
									  report.publishedCandidates.end()) ;
					DRIVERCRATE_EXPECT( context, report.installerHandoff == installer &&
													(!installer || report.infCount == 0U)) ;
				}

				DRIVERCRATE_EXPECT( context, candidates.size() == testCase.candidates) ;
				Access::dispatchIndex( window, *prepared) ;
				// 元実UI承認と同workerの実claimを、終端同期後に完全照合します。
				if( testCase.taskMutation != ApprovedIndexTaskMutation::NONE) {
					const auto &originalApproval =
						// 実dialog YESの元値です。
						Access::indexApproval( window) ;
					DRIVERCRATE_EXPECT( context, probe->registered && !probe->failed &&
													probe->workerThread != GetCurrentThreadId() &&
													probe->calls == testCase.targets &&
													probe->calls <= probe->receipts.size()) ;
					// 固定二対象以内の全実taskを保持し、失敗や未実行を分母から除外しません。
					for( std::size_t ordinal = 0U;
						ordinal < std::min( probe->calls, probe->receipts.size()); ++ordinal) {
						const auto &receipt = probe->receipts[ordinal] ;	// 同期済みの元claimです。
						// 元承認の全対象snapshotとEULA判断だけを比較し、別sessionを構築しません。
						const bool	uiBound =
							receipt.task &&
							receipt.task->operationId == originalApproval.operationId &&
							receipt.task->operationId == prepared->operationId &&
							receipt.task->scanSessionId == originalApproval.scanSessionId &&
							receipt.task->planId == originalApproval.planId &&
							std::ranges::any_of(
								originalApproval.decisions, [&receipt]( const auto &decision) {
									return decision.target == receipt.task->target &&
										   decision.acquire && decision.eulaAccepted ;
								}) ;
						DRIVERCRATE_EXPECT(
							context,
							uiBound && receipt.originalOwnedBefore && receipt.unchangedCopyOwned &&
								receipt.opaqueTaskIdentityPreserved && !receipt.changedOwned &&
								receipt.error == static_cast<NativeError>( E_ACCESSDENIED) &&
								receipt.grantId == 0U &&
								receipt.grantState == OfficialDownloadGrantState::NOT_REQUESTED &&
								receipt.originalPreserved && receipt.stateUnchanged &&
								receipt.itemsUnchanged && receipt.progressUnchanged &&
								receipt.httpUnchanged && receipt.contentUnchanged &&
								receipt.additionalHttp == 0U && receipt.additionalContent == 0U) ;
						std::cout << "FORMAT_TASK_BINDING case=" << testCase.id
								  << " targetOrdinal=" << ordinal << " uiApprovedTask=" << uiBound
								  << " originalOwned=" << receipt.originalOwnedBefore
								  << " unchangedCopyOwned=" << receipt.unchangedCopyOwned
								  << " opaqueTaskIdentityPreserved="
								  << receipt.opaqueTaskIdentityPreserved
								  << " changedOwned=" << receipt.changedOwned
								  << " grantError=" << receipt.error
								  << " grantId=" << receipt.grantId
								  << " grantState=" << static_cast<unsigned>( receipt.grantState)
								  << " originalTaskPreserved=" << receipt.originalPreserved
								  << " stateUnchanged=" << receipt.stateUnchanged
								  << " itemsUnchanged=" << receipt.itemsUnchanged
								  << " progressUnchanged=" << receipt.progressUnchanged
								  << " additionalHttp=" << receipt.additionalHttp
								  << " additionalContent=" << receipt.additionalContent
								  << " httpUnchanged=" << receipt.httpUnchanged
								  << " contentUnchanged=" << receipt.contentUnchanged
								  << " reservationDirectObservation=0 realChanges=0\n" ;
					}
				}

				// 同operation終端後だけ読む完全低位HTTP観測です。
				const auto http = input.observeHttp() ;
				DRIVERCRATE_EXPECT( context, http.safe && http.opens == http.closes) ;
				const auto termsRequests = testCase.options.termsRequired
											   ? (testCase.shared ? 2U : 1U)
											   : 0U ;	// 固定された元recordごとの全文GET数です。
				DRIVERCRATE_EXPECT( context, http.cookieDisabled == termsRequests &&
												http.cacheControlHeaders == termsRequests) ;
				// 異条件二対象は元terms二GETと独立payload二GETを必要とします。
				if( testCase.options.secondTermsSubject || testCase.options.secondTermsRevision) {
					DRIVERCRATE_EXPECT( context, http.sends == 4U && candidates.size() == 2U &&
													candidates[0].packageIdentity !=
														candidates[1].packageIdentity) ;
				}

				// 原scan/terms取得後の失効はpayload取得へ進めません。
				if( testCase.expiredBeforePreparation) {
					DRIVERCRATE_EXPECT( context, http.sends == 1U && candidates.empty() &&
													bound.observe().stages == 0U &&
													bound.observe().installs == 0U &&
													bound.observeInstaller().launches == 0U) ;
				}

				// CAT実byteと固定低位署名期待の不一致を内容拒否へ結びます。
				if( testCase.native == Native::CAB_MEMBER_FAILURE) {
					DRIVERCRATE_EXPECT( context, http.sends == 1U && candidates.empty() &&
													bound.observe().signature.setupCalls > 0U &&
													bound.observe().signature.rejectedCalls > 0U &&
													bound.observe().stages == 0U &&
													bound.observe().installs == 0U) ;
				}

				std::cout << "FORMAT_PREPARED case=" << testCase.id
						  << " candidates=" << candidates.size() << " http=" << http.sends
						  << " control=" << prepared->preparationResult.controlError
						  << " safe=" << http.safe << " handles=" << http.opens << '/'
						  << http.closes << " cookiesDisabled=" << http.cookieDisabled
						  << " cacheControl=" << http.cacheControlHeaders << '\n' ;
				// 拒否・未到達のcaseから表示用成功候補を作りません。
				if( candidates.empty()) {
					break ;
				}

				// 本物Treeで明示選択する元candidate identity集合です。
				std::vector<std::wstring> selection ;
				// 有限な原対象または当該一caseだけを走査し、未到達は元失敗へ残します。
				for( const auto &candidate : candidates) {
					selection.push_back( candidate.identity) ;
				}

				Access::selectIndexCandidates( window, context, selection) ;
				const auto originalCurrentFacts =
					// 元scanの過去観測です。
					Access::currentIndexScanFacts( window) ;
				const auto beforeInstallInventory =
					// 指定node照会とは独立です。
					bound.observe().allPresentInventoryOpens ;
				const auto originalRows =
					// 明示NOで保持すべき実TreeView本文と結果columnです。
					testCase.verifyHandoffNo ? Access::indexResultView( window, context)
											 : std::vector<std::wstring>{} ;
				std::wstring originalConfirmation ;	// 追加確認のNOとYESで同じ本文を照合します。
				// 公式installerは追加確認を拒否し、通常INFは導入前のまま保ちます。
				if( installer) {
					// 追加確認を拒否する元dialog状態です。
					DialogState cancel{.context = &context,
									   .owner	= handle,
									   .mode	= DialogMode::INDEX_INSTALL_CANCEL} ;
					{
						// 同じ追加確認だけを終端まで操作します。
						DialogDriver driver( cancel) ;
						// E07だけ実Buttonと同じcommandを送ります。
						if( testCase.verifyHandoffNo) {
							Access::beginIndexInstallCommand( window) ;
						} else {
							Access::beginIndexInstall( window) ;
						}
					}
					DRIVERCRATE_EXPECT( context, cancel.handled && !cancel.failed) ;
					originalConfirmation = cancel.details ;
					DRIVERCRATE_EXPECT( context, candidates.front().version == L"1.2.3.4") ;
					Access::verifyIndexConfirmation(
						window, context, originalConfirmation, selection.size(),
						candidates.front().action == DriverAction::INITIAL_INSTALL) ;
				}

				DRIVERCRATE_EXPECT( context, bound.observe().stages == 0U &&
												bound.observe().installs == 0U &&
												bound.observeInstaller().launches == 0U &&
												bound.observe().restoreBegins == 0U &&
												Access::controller( window).state() ==
													ApplicationState::SCAN_READY) ;
				// 元E07のNO終端は取得済み候補と元選択を失効せず、そのまま保持します。
				if( testCase.verifyHandoffNo) {
					const auto native = bound.observe() ;	// 明示NO後の実低位作用数です。
					const bool retained =
						// 元controlと元scanの観測を一つずつ完全比較します。
						Access::indexResultView( window, context) == originalRows &&
						Access::currentIndexScanFacts( window) == originalCurrentFacts ;
					DRIVERCRATE_EXPECT(
						context,
						retained && !originalRows.empty() && !originalCurrentFacts.empty() &&
							native.stages == 0U && native.installs == 0U &&
							native.restoreBegins == 0U && native.restoreCompletes == 0U &&
							bound.observeInstaller().launches == 0U &&
							Access::controller( window).state() == ApplicationState::SCAN_READY &&
							Access::controller( window).scanSessionId() == plan.scanSessionId &&
							IsWindowEnabled( GetDlgItem( handle, IDC_INSTALL))) ;
					std::cout << "FORMAT_HANDOFF_NO case=E07 retainedRows=" << retained
							  << " originalSelectionEnabled="
							  << (IsWindowEnabled( GetDlgItem( handle, IDC_INSTALL)) != FALSE)
							  << " stage=" << native.stages << " install=" << native.installs
							  << " restoreBegin=" << native.restoreBegins
							  << " restoreEnd=" << native.restoreCompletes
							  << " launch=" << bound.observeInstaller().launches
							  << " realChanges=0\n" ;
					break ;
				}

				// 原installerの本物NOを元E07へ具体対応させます。
				if( installer) {
					std::cout << "FORMAT_INSTALL_NO case=E07 parent=" << testCase.id
							  << " launch=" << bound.observeInstaller().launches
							  << " restore=" << bound.observe().restoreBegins << '\n' ;
				}

				*expired = testCase.expired ;	// 公表後の元UTCだけを変更します。
				// 元T01の同意と準備を完了した後だけ、queue受付拒否の順序を固定します。
				if( orderProbe == "queue") {
					Access::stopIndexWorker( window) ;
				}

				// MessageBoxの明示非承認終了とworker遅延を区別する独立入力です。
				if( orderProbe == "quit") {
					PostQuitMessage( 0) ;
				}

				// 同元selectionの最終操作YESだけを送る短命状態です。
				DialogState accept{.context = &context,
								   .owner	= handle,
								   .mode	= orderProbe == "no" ? DialogMode::INDEX_INSTALL_CANCEL
																 : DialogMode::INDEX_INSTALL_ACCEPT} ;
				const auto	beforeOperation =
					// 元受付IDです。
					Access::controller( window).activeOperationId() ;
				const auto beforeState = Access::controller( window).state() ;	// 元受付状態です。
				{
					// 同scopeの実dialog timerを終端まで所有します。
					DialogDriver driver( accept) ;
					// R04はButtonと同じWM_COMMAND routingから元workerへ到達します。
					if( testCase.verifyTerminalReuse) {
						Access::beginIndexInstallCommand( window) ;
					} else {
						Access::beginIndexInstall( window) ;
					}
				}
				const auto afterOperation =
					// 同同期呼出し後のIDです。
					Access::controller( window).activeOperationId() ;
				const auto afterState =
					// 実begin/request後の状態です。
					Access::controller( window).state() ;
				std::cout << "FORMAT_INSTALL_BEGIN case=" << testCase.id
						  << " handled=" << accept.handled << " failed=" << accept.failed
						  << " errors=" << accept.errors << " ticks=" << accept.ticks
						  << " state=" << static_cast<unsigned>( beforeState) << '/'
						  << static_cast<unsigned>( afterState) << " operation=" << beforeOperation
						  << '/' << afterOperation
						  << " controllerAccepted=" << (afterOperation != beforeOperation)
						  << " queueAcceptedByState="
						  << (afterOperation != beforeOperation &&
							  afterState == ApplicationState::CREATING_RESTORE_POINT)
						  << " queueRejectedByState="
						  << (afterOperation != beforeOperation &&
							  afterState == ApplicationState::FAILURE)
						  << '\n' ;
				DRIVERCRATE_EXPECT( context, accept.handled == (installer && orderProbe != "quit") &&
												!accept.failed) ;
				// 追加確認のある条件だけNOとYESの本文を比較します。
				if( installer && orderProbe != "quit") {
					DRIVERCRATE_EXPECT( context, accept.details == originalConfirmation) ;
				}

				// 明示NO/WM_QUIT/停止queueを元成功終端へ読み替えず、各拒否地点を独立に照合します。
				if( orderProbe == "queue" || orderProbe == "no" || orderProbe == "quit") {
					const bool queueRejected = orderProbe == "queue" ;	// 実queue停止だけの期待です。
					DRIVERCRATE_EXPECT(
						context, (afterOperation != beforeOperation) == queueRejected &&
									 (afterState == ApplicationState::FAILURE) == queueRejected &&
									 (queueRejected || afterState == ApplicationState::SCAN_READY)) ;
					const auto pending =
						// 拒否後の実queueです。
						Access::takeReadyIndexEvents( window) ;
					DRIVERCRATE_EXPECT( context, pending.empty()) ;
					Access::stopIndexWorker( window) ;
					const auto stopped = bound.observeAfterStop() ;	// 必ずjoin後の同期観測です。
					DRIVERCRATE_EXPECT( context, stopped.stages == 0U && stopped.installs == 0U &&
													stopped.restoreBegins == 0U &&
													stopped.restoreCompletes == 0U &&
													bound.observeInstaller().launches == 0U) ;
					std::cout << "FORMAT_ORDER_REJECT probe=" << orderProbe
							  << " controllerAccepted=" << (afterOperation != beforeOperation)
							  << " queueRejected=" << queueRejected << " events=" << pending.size()
							  << " stage=" << stopped.stages << " install=" << stopped.installs
							  << " restore=" << stopped.restoreBegins << '/'
							  << stopped.restoreCompletes << " joined=1 realChanges=0\n" ;
					break ;
				}

				// Workerが復旧前に停止した事実を同期し、終端未生成のqueueを先に消費します。
				if( orderProbe == "hold") {
					const bool entered = installGate->entered.try_acquire_for(
						std::chrono::seconds{5}) ;	// 同期点の有限待機です。
					const auto pending =
						// 同期点以前の原通知です。
						Access::takeReadyIndexEvents( window) ;
					DRIVERCRATE_EXPECT(
						context, entered && !pending.empty() &&
									 std::ranges::none_of( pending, []( const auto &event) {
										 return event.kind == WorkerEventKind::INSTALL_COMPLETED ;
									 })) ;
					// 同期点前のprogressも本物handlerへ一度だけ渡し、通知を注入しません。
					for( const auto &event : pending) {
						Access::dispatchIndex( window, event) ;
					}

					installGate->resume.release() ;
					std::cout << "FORMAT_ORDER_HOLD entered=" << entered
							  << " priorEvents=" << pending.size()
							  << " priorTerminal=0 explicitRelease=1 realChanges=0\n" ;
				}

				const bool stoppedBeforeTake =
					// 終端生成をconsumerより先に確定する順序です。
					orderProbe == "terminal" ;
				// stop/joinは受理済みcommandを処理し終えてから返り、終端を実queueへ残します。
				if( stoppedBeforeTake) {
					Access::stopIndexWorker( window) ;
				}

				std::size_t				   unexpectedScans{} ;	// 導入待ちの自動scan終端だけです。
				Access::IndexTerminalTrace terminalTrace ;		// 同queueの最大64eventだけです。
				// 復旧と原Provider処理の実終端です。実導入は行いません。
				const auto				   installedOwner = ownTerminal( [&] {
					return Access::takeIndexTerminal(
						window, WorkerEventKind::INSTALL_COMPLETED,
						testCase.verifyTerminalReuse ? &unexpectedScans : nullptr, &terminalTrace) ;
				}) ;				   // 同workerの元終端だけを所有する。
				auto &installed = *installedOwner ;	// 元caseの期間だけ終端値を借用する。
				std::cout << "FORMAT_INSTALL_EVENTS case=" << testCase.id
						  << " terminal=" << installed.has_value()
						  << " count=" << terminalTrace.count
						  << " overflow=" << terminalTrace.overflow << " sequence=" ;
				// 最大64件の非機密種類/操作IDだけを元受信順で表示します。
				for( std::size_t index = 0; index < terminalTrace.count; ++index) {
					std::cout << static_cast<unsigned>( terminalTrace.kinds[index]) << ':'
							  << terminalTrace.operations[index] << ',' ;
				}

				std::cout << '\n' ;
				DRIVERCRATE_EXPECT( context, installed.has_value() && !terminalTrace.overflow &&
												installed->operationId == afterOperation &&
												(!installGate || !installGate->timedOut)) ;
				// 元worker終端を受けていなければ成功DTOを合成せず当該caseを止めます。
				if( !installed) {
					Access::stopIndexWorker( window) ;
					const auto stopped =
						// join後だけ読む低位counterです。
						bound.observeAfterStop() ;
					std::cout << "FORMAT_INSTALL_STOPPED case=" << testCase.id
							  << " stage=" << stopped.stages << " install=" << stopped.installs
							  << " restore=" << stopped.restoreBegins << '/'
							  << stopped.restoreCompletes
							  << " launch=" << bound.observeInstaller().launches << " joined=1\n" ;
					break ;
				}

				// 原個別実行結果です。引継ぎを導入済みへ換算しません。
				const auto &result = installed->installResult ;
				// 同operationのstage/指定導入/復旧の低位観測です。
				const auto	native = stoppedBeforeTake ? bound.observeAfterStop() : bound.observe() ;
				// 同operationの完全launch表の非機密観測です。
				const auto	launch = bound.observeInstaller() ;
				// 原失効・復旧拒否の条件から固定する起動到達期待です。
				const bool	launched = installer && !testCase.expired && !testCase.restoreFailure ;
				DRIVERCRATE_EXPECT( context,
								   result.succeeded == testCase.succeeded &&
									   result.updates.size() == selection.size() && launch.valid &&
									   launch.launches == (launched ? 1U : 0U) &&
									   native.installs == (installer ? 0U : testCase.candidates)) ;
				// 引継ぎ・原終了codeをdriver導入成功へ水増ししません。
				for( const auto &item : result.updates) {
					// 原引継ぎに到達した項目だけを別結果へ照合し、driver導入成功へ変換しません。
					if( launched) {
						DRIVERCRATE_EXPECT(
							context, item.installerHandoff &&
										 item.installOutcome == OutcomeCode::NOT_STARTED &&
										 item.handoffOutcome ==
											 (testCase.native == Native::INSTALLER_LAUNCH_FAILURE
												  ? OutcomeCode::FAILURE
												  : OutcomeCode::SUCCESS)) ;
					}
				}

				// 本物結果dialogの個別結果を読み取る短命状態です。
				DialogState display{
					.context = &context, .owner = handle, .mode = DialogMode::INDEX_INSTALL_RESULT} ;
				{
					// 同scopeの実dialog timerを終端まで所有します。
					DialogDriver driver( display) ;
					Access::dispatchIndex( window, *installed) ;
				}
				DRIVERCRATE_EXPECT( context, display.handled && !display.failed &&
												Access::controller( window).scanSessionId() == 0U) ;
				// 混合R03の元順序・元HRESULT・個別再起動を実worker結果と実rowへ結びます。
				if( std::string_view{testCase.id} == "R03") {
					DRIVERCRATE_EXPECT( context,
									   result.updates.size() == 2U && selection.size() == 2U) ;
					// 元二対象が欠けた場合は別の全成功結果で補完しません。
					if( result.updates.size() == 2U && selection.size() == 2U) {
						const auto &first  = result.updates[0] ;	// 第一低位callの実結果です。
						const auto &second = result.updates[1] ;	// 第二低位callの元失敗です。
						DRIVERCRATE_EXPECT(
							context,
							first.identity == selection[0] && second.identity == selection[1] &&
								first.downloadOutcome == OutcomeCode::SUCCESS &&
								second.downloadOutcome == OutcomeCode::SUCCESS &&
								first.installOutcome == OutcomeCode::SUCCESS &&
								first.installError == 0U &&
								second.installOutcome == OutcomeCode::FAILURE &&
								second.installError == static_cast<NativeError>( HRESULT_FROM_WIN32(
														   ERROR_ACCESS_DENIED)) &&
								first.rebootRequired && !second.rebootRequired &&
								result.rebootRequired && !result.succeeded &&
								result.installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS &&
								native.installs == 2U && native.deviceInstalls[0] == 1U &&
								native.deviceInstalls[1] == 1U && native.restoreBegins == 1U &&
								native.restoreCompletes == 1U) ;
						Access::verifyIndexResultRows( window, context, result) ;
						std::cout << "FORMAT_MIXED_RESULT case=R03 originalOrder="
								  << (first.identity == selection[0] &&
									  second.identity == selection[1])
								  << " firstOutcome=" << static_cast<unsigned>( first.installOutcome)
								  << " secondOutcome="
								  << static_cast<unsigned>( second.installOutcome)
								  << " firstHRESULT=" << first.installError
								  << " secondHRESULT=" << second.installError
								  << " firstReboot=" << first.rebootRequired
								  << " secondReboot=" << second.rebootRequired
								  << " rebootOR=" << result.rebootRequired
								  << " succeeded=" << result.succeeded
								  << " firstNative=" << native.deviceInstalls[0]
								  << " secondNative=" << native.deviceInstalls[1]
								  << " resultRowsVerified=1 realChanges=0\n" ;
					}
				}

				// 元R04だけを正常結果保持から実workerのstale拒否へ直接接続します。
				if( testCase.verifyTerminalReuse) {
					Access::verifyIndexResultRows( window, context, result) ;
					const auto kept =
						// 実control/modelです。
						Access::indexResultView( window, context) ;
					const auto firstOperation = installed->operationId ;	// 正常終端の元操作です。
					DRIVERCRATE_EXPECT(
						context,
						result.succeeded && result.updates.size() == 1U &&
							result.downloadOutcome == OutcomeCode::SUCCESS &&
							result.installOutcome == OutcomeCode::SUCCESS &&
							result.updates.front().downloadOutcome == OutcomeCode::SUCCESS &&
							result.updates.front().installOutcome == OutcomeCode::SUCCESS &&
							result.updates.front().requiredRoles.empty() && native.stages == 1U &&
							native.installs == 1U && native.restoreBegins == 1U &&
							native.restoreCompletes == 1U &&
							native.allPresentInventoryOpens == beforeInstallInventory &&
							unexpectedScans == 0U && !originalCurrentFacts.empty() &&
							Access::currentIndexScanFacts( window) == originalCurrentFacts &&
							Access::controller( window).state() == ApplicationState::COMPLETED) ;
					const auto firstHttp =
						// 元正常取得までの実fake呼出しです。
						input.observeHttp() ;
					Access::rejectExpiredIndexSelection( window, context, selection) ;
					DialogState refused{
						.context = &context,
						.owner	 = handle,
						.mode	 = DialogMode::
							INDEX_INSTALL_SELECTION_REQUIRED} ;	// 元commandの拒否案内です。
					{
						DialogDriver driver( refused) ;	// 同Windowの標準案内だけを閉じます。
						Access::beginIndexInstallCommand( window) ;
					}
					DRIVERCRATE_EXPECT( context, refused.handled && !refused.failed) ;
					Access::verifyExpiredIndexPrompt( window, context, refused.details) ;
					DRIVERCRATE_EXPECT(
						context,
						Access::controller( window).activeOperationId() == firstOperation &&
							Access::indexResultView( window, context) == kept &&
							Access::currentIndexScanFacts( window) == originalCurrentFacts &&
							firstOperation < std::numeric_limits<OperationId>::max()) ;
					// 操作序数の桁あふれを別のstale拒否へ読み替えません。
					if( firstOperation == std::numeric_limits<OperationId>::max()) {
						break ;
					}

					const auto staleOperation =
						firstOperation + 1U ;	// 同private probeだけの増加操作です。
					const bool queued = Access::requestExpiredIndexInstall(
						window, staleOperation, plan.scanSessionId,
						selection) ;	// 元session/identityを実queueへ渡します。
					DRIVERCRATE_EXPECT( context, queued) ;
					// Queue未到達をworker stale拒否へ読み替えません。
					if( !queued) {
						break ;
					}

					const auto rejectedOwner = ownTerminal( [&] {
						return Access::takeIndexTerminal( window, WorkerEventKind::INSTALL_COMPLETED,
														 &unexpectedScans) ;
					}) ; // 同workerの元終端だけを所有する。

					auto	  &rejected =
						*rejectedOwner ;	// 元caseの期間だけ終端値を借用する。	// 実workerが生成した拒否終端です。
					DRIVERCRATE_EXPECT( context, rejected.has_value()) ;
					// 拒否終端なしでは失敗DTOや結果保持の成功を作りません。
					if( !rejected) {
						break ;
					}

					const auto &denied = rejected->installResult ;	// 元workerの診断位置です。
					DRIVERCRATE_EXPECT(
						context,
						rejected->operationId == staleOperation && !denied.succeeded &&
							denied.downloadOutcome == OutcomeCode::FAILURE &&
							denied.downloadError == static_cast<NativeError>( E_UNEXPECTED) &&
							denied.installOutcome == OutcomeCode::NOT_STARTED &&
							denied.updates.size() == 1U &&
							denied.updates.front().identity == selection.front() &&
							denied.updates.front().downloadError ==
								static_cast<NativeError>( E_UNEXPECTED) &&
							denied.updates.front().installOutcome == OutcomeCode::NOT_STARTED &&
							denied.restorePointCreation.outcome == OutcomeCode::NOT_STARTED &&
							denied.restorePointCompletion.outcome == OutcomeCode::NOT_STARTED) ;
					const auto after = bound.observe() ;	// 第二要求後の全低位事実です。
					const auto afterHttp =
						// 第二取得を行っていない実観測です。
						input.observeHttp() ;
					DRIVERCRATE_EXPECT(
						context,
						after.stages == native.stages && after.installs == native.installs &&
							after.restoreBegins == native.restoreBegins &&
							after.restoreCompletes == native.restoreCompletes &&
							after.opens == native.opens && after.closes == native.closes &&
							after.allPresentInventoryOpens == native.allPresentInventoryOpens &&
							after.signature.setupCalls == native.signature.setupCalls &&
							after.signature.verifyCalls == native.signature.verifyCalls &&
							afterHttp.sends == firstHttp.sends &&
							afterHttp.opens == firstHttp.opens &&
							afterHttp.closes == firstHttp.closes &&
							bound.observeInstaller().launches == launch.launches &&
							unexpectedScans == 0U) ;
					Access::dispatchIndex( window, *rejected) ;
					const bool retained = Access::indexResultView( window, context) ==
										  kept ;	// 実拒否event後の一覧一致です。
					DRIVERCRATE_EXPECT(
						context,
						retained && Access::currentIndexScanFacts( window) == originalCurrentFacts &&
							Access::controller( window).state() == ApplicationState::COMPLETED &&
							Access::controller( window).scanSessionId() == 0U &&
							Access::controller( window).activeOperationId() == firstOperation &&
							IsWindowEnabled( GetDlgItem( handle, IDC_SCAN))) ;
					std::cout
						<< "FORMAT_STALE_REUSE case=R04 firstSuccess=" << result.succeeded
						<< " firstStage=" << native.stages << " firstInstall=" << native.installs
						<< " workerQueued=" << queued << " workerRejected=" << !denied.succeeded
						<< " diagnostic=" << denied.downloadError << " retainedRows=" << retained
						<< " additionalHttp=" << afterHttp.sends - firstHttp.sends
						<< " additionalStage=" << after.stages - native.stages
						<< " additionalInstall=" << after.installs - native.installs
						<< " additionalRestore=" << after.restoreBegins - native.restoreBegins
						<< " additionalFullInventory="
						<< after.allPresentInventoryOpens - native.allPresentInventoryOpens
						<< " unexpectedScanTerminals=" << unexpectedScans
						<< " freshScanRequired=1 freshObservationSynthesized=0 realChanges=0\n" ;
				}

				std::cout << "FORMAT_RESULT case=" << testCase.id
						  << " succeeded=" << result.succeeded
						  << " standardInstalls=" << native.installs
						  << " handoff=" << launch.launches << " closes=" << launch.closes
						  << " realChanges=0\n" ;
				// 同じ元taskの正規grantから本物publication/selection/resultへ続行した事実です。
				if( testCase.taskMutation != ApprovedIndexTaskMutation::NONE) {
					DRIVERCRATE_EXPECT( context, result.succeeded &&
													candidates.size() == testCase.candidates &&
													result.updates.size() == testCase.candidates &&
													native.stages == testCase.targets &&
													native.installs == testCase.candidates &&
													native.specifiedBindingMatches) ;
					Access::verifyIndexResultRows( window, context, result) ;
					std::cout << "FORMAT_TASK_CONTINUED case=" << testCase.id
							  << " approvedTasks=" << probe->calls
							  << " candidates=" << candidates.size()
							  << " results=" << result.updates.size()
							  << " succeeded=" << result.succeeded << " stage=" << native.stages
							  << " install=" << native.installs << " realChanges=0\n" ;
				}
			} while( false) ;
		} catch( ...) {
			Access::stopWorker( window) ;
			DestroyWindow( handle) ;
			throw ;
		}

		Access::stopWorker( window) ;
		DestroyWindow( handle) ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
		std::cout << "FORMAT_END case=" << testCase.id
				  << " failures=" << context.failureCount() - caseFailures << " terminal=1\n" ;
	}

	// 独立順序試験の一件を元29caseや追加UI全体の合格として表示しません。
	if( orderProbe.empty()) {
		std::cout << "Consent format UI assertions: " << context.assertionCount() - before
				  << ", failures: " << context.failureCount() - failures
				  << ", directly executed fixed cases=" << executed
				  << ", original contract=31, historicalDirect=24, addedUI=5/5"
				  << ", remainingUI NOT_RUN=0, sourceQualityObligations=2 (Q01 Q02)\n" ;
	} else {
		std::cout << "Consent format order probe=" << orderProbe
				  << ", assertions=" << context.assertionCount() - before
				  << ", failures=" << context.failureCount() - failures << ", executed=" << executed
				  << ", originalFixedCases=" << cases.size() << ", originalFormatsReplaced=0\n" ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 二初回候補の実行権限消費後に各履歴を通常の実詳細dialogから読みます。
 * @param[in,out] window 元workerの部分結果を保持するWindowです。
 * @param[in,out] context 元assertionの集計先です。
 * @param[in] result 同じ二候補の元成功・失敗と原診断です。
 * @param[in] roles 表示専用の必要構成fixtureを確認する場合trueです。
 * @param[in] expectedScanSessionId 元planが結合した非0のscanです。観測した実値から補完しません。
 */
//------------------------------------------------------------------------------
void verifyExpiredInitialDetails( MainWindow &window, TestContext &context,
								 const InstallResult &result, const bool roles,
								 const ScanSessionId expectedScanSessionId)
{
	const auto candidates = Access::indexCandidates( window) ;	// Modal中も変更しない元所有集合です。
	DRIVERCRATE_EXPECT(
		context, result.updates.size() == 2U &&
					 result.updates[0].installOutcome == OutcomeCode::SUCCESS &&
					 result.updates[0].installError == 0 &&
					 result.updates[1].installOutcome == OutcomeCode::FAILURE &&
					 result.updates[1].installError == static_cast<NativeError>( E_ACCESSDENIED) &&
					 expectedScanSessionId != 0U &&
					 Access::controller( window).scanSessionId() == expectedScanSessionId) ;
	std::wstring firstDevice ;	// 同名でも異なる実opaque deviceを要求します。
	// 元結果の同candidateを探し、別deviceの履歴が混ざらないことを実controlで確認します。
	for( std::size_t ordinal{}; ordinal < result.updates.size(); ++ordinal) {
		const auto found =
			std::ranges::find( candidates, result.updates[ordinal].identity,
							  &UpdateCandidate::identity) ;	// 同時に生存する所有要素の位置です。
		DRIVERCRATE_EXPECT( context, found != candidates.end()) ;
		// 元candidateを失った結果を任意の詳細へ表示しません。
		if( found == candidates.end()) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   found->action == DriverAction::INITIAL_INSTALL &&
							   found->deviceIdentity != firstDevice && !found->installable &&
							   found->assessment &&
							   found->audit.installReadiness == CandidateInstallReadiness::READY &&
							   !isCandidateDetailsValid( *found)) ;
		firstDevice			  = found->deviceIdentity ;
		const auto sameDevice = [&found]( const auto &candidate) {
			return candidate.deviceIdentity == found->deviceIdentity ;
		} ; // 元候補が生存する同期観測中だけ借用します。
		const auto entry =
			// 元詳細内の位置です。
			std::count_if( candidates.begin(), found, sameDevice) ;
		DialogState detail{.context				  = &context,
						   .owner				  = Access::handle( window),
						   .mode				  = DialogMode::DETAILS,
						   .captureName			  = ordinal == 0U ? L"expired-initial-success"
																  : L"expired-initial-failure",
						   .captureDetails		  = false,
						   .detailEntry			  = static_cast<int>( entry),
						   .chooseDetailCandidate = true,
						   .detailSelectable	  = false,
						   .detailEntryCount	  = static_cast<unsigned>(
								std::count_if( candidates.begin(), candidates.end(), sameDevice) +
								1U)} ;	// 失効entryと末尾の全体reportを含む総数。
		{
			DialogDriver driver( detail) ;	// 偽装選択も拒否された後に通常OKで閉じます。
			Access::openCandidateDetails(
				window, static_cast<std::size_t>( found - candidates.begin()), NM_RETURN) ;
		}

		DRIVERCRATE_EXPECT(
			context,
			detail.handled && !detail.failed &&
				detail.details.find( L"前回の実行結果（履歴）") != std::wstring::npos &&
				detail.details.find( L"導入許可ではありません") != std::wstring::npos &&
				(detail.details.find( L"80070005") != std::wstring::npos) == (ordinal == 1U)) ;
		// 拒否された検証八軸を履歴表示で合格に戻しません。
		DRIVERCRATE_EXPECT( context, detail.details.find( L"失効しています") != std::wstring::npos &&
										detail.details.size() <= 320U) ;
		// 役割fixtureと原単一方式の成否を別の期待へ固定します。
		if( roles) {
			const auto base = std::wstring(
				L"基本driver: 指定device API完了・実状態観測とは別") ;	// 元役割の期待です。
			DRIVERCRATE_EXPECT(
				context,
				detail.details.find( base) != std::wstring::npos &&
					detail.details.find(
						ordinal == 0U
							? L"必要driver component: 指定device API完了・実状態観測とは別"
							: L"必要driver component: インストール失敗") != std::wstring::npos) ;
		} else {
			DRIVERCRATE_EXPECT( context, detail.details.find( ordinal == 0U ? L"インストール成功"
																		  : L"インストール失敗") !=
											std::wstring::npos) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 固定した複数INF・共有・初回・登録先条件を元workerと本物画面へ通します。
 * @param[in,out] context 原assertion集計先です。
 * @param[in] unknownClassOnly 新しい固定24条件と既知三回帰だけを実行する場合trueです。
 * @param[in] historyResultsOnly 元U21の二候補の失効詳細だけを確認する場合trueです。
 * @note 成功candidate DTOは作らず、全入力を真RSA索引・原ZIP・完全低位fakeから生成します。
 */
//------------------------------------------------------------------------------
void runSignedIndexMultiUiScenarios( TestContext &context, const bool unknownClassOnly = false,
									const bool historyResultsOnly = false)
{
	/** @brief 実行前に保存した条件へ対応する有限入力と期待です。 */
	struct Case {
		/// 元case-contractの一意IDです。
		const char					*name ;
		/// 完全低位APIへ返す原状態です。
		SignedIndexBindingNativeCase native ;
		/// 二つの原recordとpresent deviceを含めます。
		bool						 twoDevices ;
		/// 全取得policyの完全一致を原recordへ固定します。
		bool						 shared ;
		/// 二つの実基本INF閉包を原ZIPへ含めます。
		bool						 multiInf ;
		/// 正常bindingからだけ発行される期待数です。
		std::size_t					 candidates ;
		/// 本物Treeで明示選択する元候補数です。
		std::size_t					 selected ;
		/// 隔離rootへの実fake stage期待数です。
		std::uint32_t				 stages ;
		/// 非null指定nodeのdevice別call期待数です。
		std::uint32_t				 installs ;
		/// 復旧終了を含めた全体成功の期待です。
		bool						 succeeded ;
	} ;
	using Native = SignedIndexBindingNativeCase ;	// 固定低位状態の簡潔な型名です。
	const std::array cases{
		Case{"M01", Native::NORMAL, false, false, true, 2U, 1U, 1U, 1U, true},
		Case{"M02", Native::MULTI_NONAPPLICABLE, false, false, true, 1U, 1U, 1U, 1U, true},
		Case{"M03", Native::MULTI_UNKNOWN, false, false, true, 1U, 1U, 1U, 1U, true},
		Case{"M04", Native::MULTI_ALL_NONAPPLICABLE, false, false, true, 0U, 0U, 0U, 0U, false},
		Case{"M05", Native::NORMAL, false, false, true, 33U, 1U, 1U, 1U, true},
		Case{"M06", Native::NORMAL, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"M07", Native::NORMAL, false, false, false, 128U, 0U, 0U, 0U, false},
		Case{"M08", Native::NORMAL, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"S01", Native::SHARED_SUCCESS, true, true, false, 2U, 2U, 1U, 2U, true},
		Case{"S02", Native::NORMAL, true, true, false, 2U, 2U, 1U, 2U, false},
		Case{"S03", Native::SHARED_SUCCESS, true, true, false, 2U, 1U, 1U, 1U, true},
		Case{"S04", Native::SHARED_SUCCESS, true, false, false, 2U, 2U, 2U, 2U, true},
		Case{"S05", Native::SHARED_SUCCESS, true, false, false, 2U, 2U, 2U, 2U, true},
		Case{"I01", Native::INITIAL, false, false, false, 1U, 1U, 1U, 1U, true},
		Case{"I02", Native::BLANK_CURRENT, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"I03", Native::CONTRADICTORY_NODE, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"I04", Native::DRIVER_ADDED, false, false, false, 1U, 1U, 0U, 0U, false},
		Case{"I05", Native::DISAPPEARED, false, false, false, 1U, 1U, 0U, 0U, false},
		Case{"I06", Native::PROPERTY_FAILURE, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"I07", Native::MISSING_RANK, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"R01", Native::NORMAL, false, false, false, 1U, 1U, 1U, 1U, true},
		Case{"R02", Native::STAGE_EXTERNAL, false, false, false, 1U, 1U, 1U, 0U, false},
		Case{"R03", Native::STAGE_CHANGED, false, false, false, 1U, 1U, 1U, 0U, false},
		Case{"R04", Native::STAGE_WRONG_NODE, false, false, false, 1U, 1U, 1U, 0U, false},
		Case{"R05", Native::STAGE_WRONG_RANK, false, false, false, 1U, 1U, 1U, 0U, false},
		Case{"R06", Native::STAGE_BAD_LENGTH, false, false, false, 1U, 1U, 1U, 0U, false},
		Case{"A04", Native::RESTORE_END_FAILURE, false, false, false, 1U, 1U, 1U, 1U, false},
		Case{"U01", Native::INITIAL_CLASS_MISSING, false, false, false, 1U, 1U, 1U, 1U, true},
		Case{"U02", Native::INITIAL_CLASS_UNKNOWN, false, false, false, 1U, 1U, 1U, 1U, true},
		Case{"U03", Native::CLASS_PROPERTY_FAILURE, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U04", Native::CLASS_PROPERTY_INVALID, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U05", Native::CLASS_PROPERTY_LIMIT, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U06", Native::CLASS_PROPERTY_EMPTY, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U07", Native::CLASS_CONTRADICTORY, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U08", Native::INITIAL_NOT_CODE28, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U09", Native::INITIAL_DRIVER_KEY_PRESENT, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U10", Native::INITIAL_INSTALLED_NODE, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U11", Native::INITIAL_ENUMERATION_FAILURE, false, false, false, 0U, 0U, 0U, 0U,
			 false},
		Case{"U12", Native::INITIAL_PNP_CHANGED, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U13", Native::INF_CLASS_MISMATCH, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U14", Native::NATIVE_CLASS_MISMATCH, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U15", Native::INITIAL_CLASS_CHANGED, false, false, false, 1U, 1U, 0U, 0U, false},
		Case{"U16", Native::INITIAL_DRIVER_ADDED, false, false, false, 1U, 1U, 0U, 0U, false},
		Case{"U17", Native::INITIAL_DISAPPEARED, false, false, false, 1U, 1U, 0U, 0U, false},
		Case{"U18", Native::INITIAL_CLASS_MISSING, false, false, false, 1U, 0U, 0U, 0U, false},
		Case{"U19", Native::INITIAL_CLASS_MISSING, false, false, false, 1U, 1U, 0U, 0U, false},
		Case{"U20", Native::INITIAL_RESTORE_END_FAILURE, false, false, false, 1U, 1U, 1U, 1U,
			 false},
		Case{"U21", Native::INITIAL_SHARED_PARTIAL, true, true, false, 2U, 2U, 1U, 2U, false},
		Case{"U22", Native::KNOWN_CLASS_MISMATCH, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U23", Native::CLASS_GUID_FAILURE, false, false, false, 0U, 0U, 0U, 0U, false},
		Case{"U24", Native::INITIAL_CLASS_AFTER_STAGE, false, false, false, 1U, 1U, 1U, 0U, false},
	} ; // 原25条件を残し、archive境界二件と別modeの新24条件・三回帰を固定します。
	const auto	before	 = context.assertionCount() ;	// この有限群の開始値です。
	const auto	failures = context.failureCount() ;		// 元失敗は除外せず別集計に残します。
	std::size_t executed{} ;							// 分母はunknown27/更新multi27に固定します。
	// 原条件と登録済み境界を一つの実Window/workerずつ直列実行します。
	for( const auto &testCase : cases) {
		const std::string_view caseName{testCase.name} ;	// 原case IDだけの非機密分岐です。
		// 詳細の成否/原診断だけを補完する入口では元二条件に限定します。
		if( historyResultsOnly && caseName != "U21") {
			continue ;
		}

		// 原case IDだけの非機密分岐です。
		const bool newCase = caseName.starts_with( "U") ;	// 登録した有限追加集合です。
		// 同じ原multi分母を削減せず追加modeだけに三回帰を含めます。
		if( !historyResultsOnly && (unknownClassOnly ? !(newCase || caseName == "M01" ||
														caseName == "I01" || caseName == "S02")
													: newCase)) {
			continue ;
		}

		++executed ;
		const auto caseFailures = context.failureCount() ;	// 未到達もこのcaseの失敗へ数えます。
		std::cout << "MULTI_BEGIN case=" << testCase.name
				  << " expectedCandidates=" << testCase.candidates << '\n' ;
		MSG previousQuit{} ;	// 前Windowの独立終了通知です。
		// 次の実modal loopへ古い終了通知を持ち越しません。
		while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
		}

		const auto			 archiveInfCount = caseName == "M07"   ? 128U
											   : caseName == "M08" ? 129U
																   : 0U ;	// 実archive境界の投入数です。
		SignedIndexUiOptions options{.archiveInfCount =
										 archiveInfCount} ;	// 元他条件は既定のままです。
		auto				 input =
			makeSignedIndexUiInput( testCase.twoDevices, testCase.shared || caseName == "S04",
								   testCase.multiInf, caseName == "M05", caseName == "M06",
								   // 真署名storeと原ZIPの所有です。
								   caseName == "S04", options) ;
		// 公開reportが部分閉包を破棄しても、原ZIPの全投入数と非空閉包数を独立確認します。
		if( caseName == "M05" || archiveInfCount != 0U) {
			const auto originalCount = caseName == "M05" ? 33U : archiveInfCount ;	// 投入分母です。
			DRIVERCRATE_EXPECT( context,
							   input.originalArchiveInfCount == originalCount &&
								   input.originalArchiveBasicClosureCount == originalCount) ;
			std::cout << "MULTI_ARCHIVE_INPUT case=" << testCase.name
					  << " infs=" << input.originalArchiveInfCount
					  << " completeBasicClosures=" << input.originalArchiveBasicClosureCount
					  << '\n' ;
		}

		auto bound = makeSignedIndexBindingWorker( std::move( input.services), input.zip,
												  testCase.twoDevices, caseName == "U19", false,
												  testCase.native) ;	// 実workerと完全fake境界です。
		DRIVERCRATE_EXPECT( context, bound.worker != nullptr) ;
		// 不完全低位factoryを成功candidateへ補完しません。
		if( !bound.worker) {
			continue ;
		}

		auto  state = std::make_shared<MetadataUiState>() ;		// 別Providerへの誤routingを検出します。
		auto  windowOwner = std::make_unique<MainWindow>() ;	// 同scopeの元Windowをheap所有します。
		auto &window	  = *windowOwner ;						// 製品resourceの本物通常Windowです。
		Access::configure( window, state) ;
		const bool created =
			// 同scopeの本物Window生成結果です。
			window.create( GetModuleHandleW( nullptr)) ;
		DRIVERCRATE_EXPECT( context, created) ;
		// Window不成立は未到達失敗とし同workerを停止します。
		if( !created) {
			bound.worker->stop() ;
			continue ;
		}

		const HWND handle = Access::handle( window) ;	// 同scopeだけの非所有HWNDです。
		ShowWindow( handle, SW_HIDE) ;
		Access::attachIndexWorker( window, std::move( bound.worker)) ;
		try {
			// 各未到達を元caseの失敗へ残して共通終端清掃へ進みます。
			do {
				Access::beginIndexScan( window) ;
				auto scannedOwner =
					std::make_unique<std::optional<WorkerEvent>>( Access::takeIndexTerminal(
						window,
						WorkerEventKind::SCAN_COMPLETED)) ;	// 同scopeの元eventをheap所有します。
				auto &scanned = *scannedOwner ;				// 元scan終端の所有です。
				DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
												scanned->preparationPlan) ;
				// 同scan原planがない状態から取得権限を生成しません。
				if( !scanned || !scanned->preparationPlan) {
					break ;
				}

				Access::dispatchIndex( window, *scanned) ;
				const auto &plan	 = *scanned->preparationPlan ;	// 原operation/session/planです。
				const auto	requests = testCase.twoDevices && !testCase.shared
										   ? 2U
										   : 1U ;	// 原取得policyから固定したGET分母です。
				DRIVERCRATE_EXPECT( context, plan.targets.size() == requests &&
												plan.targets.front().deviceCount ==
													(testCase.shared ? 2U : 1U)) ;
				// I06は同scan原参照を固定した後、private evidence再読取だけを失敗させます。
				if( testCase.native == Native::PROPERTY_FAILURE ||
				   (newCase && ((caseName >= "U03" && caseName <= "U14") || caseName == "U22" ||
								caseName == "U23"))) {
					bound.changeNativeState() ;
				}

				DRIVERCRATE_EXPECT( context, Access::acquireIndexPlan( window, plan)) ;
				auto preparedOwner = std::make_unique<
					std::optional<WorkerEvent>>( Access::takeIndexTerminal(
					window,
					WorkerEventKind::PREPARATION_COMPLETED)) ;	// 同scopeの元eventをheap所有します。
				auto &prepared = *preparedOwner ;				// 元取得・検査終端の所有です。
				DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
				// 元終端なしでは表示用成功DTOを作りません。
				if( !prepared) {
					break ;
				}

				std::vector<UpdateCandidate>
					original ;	// 実署名/共通検査/native binding由来だけです。
				// 共通archiveの原HRESULTは再評価reportと別の元内容summaryでも確認します。
				if( caseName == "M08") {
					DRIVERCRATE_EXPECT( context, prepared->indexPreparation.items.size() == 1U) ;
					// 元summaryがある場合だけ内容到達段階と全体失敗診断を読みます。
					if( prepared->indexPreparation.items.size() == 1U) {
						const auto &item =
							// 元内容検査結果です。
							prepared->indexPreparation.items.front() ;
						DRIVERCRATE_EXPECT(
							context,
							item.content == IndexedDriverInspectionState::INPUT_REJECTED &&
								item.contentError == static_cast<NativeError>( E_INVALIDARG) &&
								item.infCount == 0U && item.acceptedInfCount == 0U) ;
						std::cout << "MULTI_ARCHIVE_ORIGINAL case=M08 content="
								  << static_cast<unsigned>( item.content)
								  << " contentError=" << item.contentError
								  << " infCount=" << item.infCount
								  << " acceptedInf=" << item.acceptedInfCount << '\n' ;
					}
				}

				std::cout << "MULTI_PREPARED case=" << testCase.name
						  << " controlError=" << prepared->preparationResult.controlError
						  << " reports=" << prepared->preparationResult.auditReports.size() << '\n' ;
				// 全reportを保持し、拒否や原HRESULTを成功pairの裏に隠しません。
				for( const auto &report : prepared->preparationResult.auditReports) {
					DRIVERCRATE_EXPECT( context,
									   report.acceptedInfCount == (caseName == "M05"   ? 33U
																   : caseName == "M07" ? 128U
																   : caseName == "M08" ? 0U
																   : testCase.multiInf ? 2U
																					   : 1U)) ;
					// 33と128の全閉包が内容・Windows照合・公開へ到達し、旧32件で切り捨てません。
					if( caseName == "M05" || caseName == "M07") {
						const auto expectedCount =
							// 正常全入力数です。
							caseName == "M05" ? 33U : 128U ;
						DRIVERCRATE_EXPECT(
							context, report.infCount == expectedCount && report.contentError == 0 &&
										 report.content == CandidateAuditGateState::PASSED &&
										 report.examinedPairCount == expectedCount &&
										 report.applicablePairCount == expectedCount &&
										 report.failedPairCount == 0U &&
										 report.publication.publishedCount == expectedCount &&
										 report.publishedCandidates.size() == expectedCount &&
										 report.publication.firstError == 0) ;
					}

					// selected集合の129件を署名前に拒否し、128部分合格も公開せず元HRESULTを保持します。
					if( caseName == "M08") {
						DRIVERCRATE_EXPECT( context,
										   report.infCount == 0U &&
											   report.content == CandidateAuditGateState::FAILURE &&
											   report.contentError ==
												   static_cast<NativeError>( E_INVALIDARG) &&
											   report.examinedPairCount == 0U &&
											   report.applicablePairCount == 0U &&
											   report.publication.publishedCount == 0U &&
											   report.publishedCandidates.empty()) ;
					}

					// 具体的外部依存の未確認は元共通拒否を保持します。
					if( caseName == "M06") {
						DRIVERCRATE_EXPECT( context,
										   report.content == CandidateAuditGateState::PASSED &&
											   report.publication.publishedCount == 0U &&
											   report.publication.excludedPairCount == 1U &&
											   report.publication.state ==
												   OfficialPreparationCandidatePublicationState::
													   NO_ELIGIBLE_CANDIDATES &&
											   report.publication.firstError ==
												   static_cast<NativeError>(
													   HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
					}

					original.insert( original.end(), report.publishedCandidates.begin(),
									report.publishedCandidates.end()) ;
					std::cout << "MULTI_AUDIT case=" << testCase.name
							  << " infCount=" << report.infCount
							  << " acceptedInf=" << report.acceptedInfCount
							  << " content=" << static_cast<unsigned>( report.content)
							  << " contentError=" << report.contentError
							  << " examined=" << report.examinedPairCount
							  << " applicable=" << report.applicablePairCount
							  << " failed=" << report.failedPairCount
							  << " firstPairError=" << report.firstPairError
							  << " publicationError=" << report.publication.firstError
							  << " published=" << report.publication.publishedCount << '\n' ;
					// 一pairの元ACCESS_DENIEDを別正常pairの合格で消しません。
					if( testCase.native == Native::MULTI_UNKNOWN ||
					   testCase.native == Native::PROPERTY_FAILURE) {
						DRIVERCRATE_EXPECT( context,
										   report.failedPairCount == 1U &&
											   report.firstPairError ==
												   static_cast<NativeError>( E_ACCESSDENIED)) ;
					}
				}

				DRIVERCRATE_EXPECT( context,
								   original.size() == testCase.candidates &&
									   prepared->preparationResult.auditReports.size() == requests) ;
				Access::dispatchIndex( window, *prepared) ;
				const auto http = input.observeHttp() ;	// 元grant限定HTTP低位receiptです。
				DRIVERCRATE_EXPECT( context, http.sends == requests && http.safe &&
												http.opens == http.closes) ;
				const auto roots =
					caseName == "M08"		? 0U
					: caseName == "M05"		? 33U
					: archiveInfCount != 0U ? 128U
					: testCase.multiInf
						? 2U
						: requests ;	// 内容閉包所有数であり再検査API数ではありません。
				DRIVERCRATE_EXPECT( context, bound.observe().signature.inspectionRoots == roots) ;
				// 拒否までの共通内容検査回数は元129全入力数と区別して観測します。
				if( archiveInfCount != 0U) {
					std::cout << "MULTI_ARCHIVE_BOUNDARY case=" << testCase.name
							  << " inputInf=" << input.originalArchiveInfCount
							  << " inspectionRoots=" << bound.observe().signature.inspectionRoots
							  << " candidates=" << original.size() << '\n' ;
				}

				// 拒否分母は0候補と理由付き原reportのまま保持し、実行へ進めません。
				if( testCase.candidates == 0U) {
					DRIVERCRATE_EXPECT(
						context, bound.observe().stages == 0U && bound.observe().installs == 0U &&
									 !prepared->preparationResult.auditReports.empty()) ;
					std::cout << "MULTI_REJECTION case=" << testCase.name
							  << " candidates=" << original.size()
							  << " stage=0 specifiedInstall=0 fakeHttp=" << http.sends << '\n' ;
					break ;
				}

				// 未到達候補を都合のよい一件へ置換しません。
				if( original.size() != testCase.candidates) {
					break ;
				}

				const bool initial =
					newCase || testCase.native == Native::INITIAL ||
					testCase.native == Native::DRIVER_ADDED ||
					testCase.native ==
						Native::DISAPPEARED ;	// 本体NO_DRIVERから発行される期待Actionです。
				// 原candidateのAction/非推奨をそのまま本物selectionへ渡します。
				for( const auto &candidate : original) {
					DRIVERCRATE_EXPECT( context, candidate.installable && !candidate.recommended &&
													candidate.action ==
														(initial ? DriverAction::INITIAL_INSTALL
																 : DriverAction::UPDATE)) ;
				}

				// 共有根拠あり/なしを表示名でなく元opaque packageの同一性として確認します。
				if( testCase.twoDevices) {
					DRIVERCRATE_EXPECT(
						context, original[0].deviceIdentity != original[1].deviceIdentity &&
									 (original[0].packageIdentity == original[1].packageIdentity) ==
										 testCase.shared) ;
				}

				std::vector<std::wstring> selected ;	// 未選択候補を実行へ追加しない元ID集合です。
				// M01は後側の代替INF一つだけ、共有は指定したdevice数だけ選択します。
				for( std::size_t index = 0U; index < testCase.selected; ++index) {
					selected.push_back( testCase.multiInf && original.size() == 2U
										   ? original.back().identity
										   : original[index].identity) ;
				}

				Access::verifyIndexSelectionBoundary( window, context, selected) ;
				Access::selectIndexCandidates( window, context, selected) ;
				// 元候補を未選択のまま保ち、実Treeと復旧/導入の0callを確認します。
				if( testCase.selected == 0U) {
					const auto unselected = bound.observe() ;	// 元低位counterだけです。
					DRIVERCRATE_EXPECT( context, unselected.stages == 0U &&
													unselected.installs == 0U &&
													unselected.restoreBegins == 0U &&
													unselected.restoreCompletes == 0U) ;
					std::cout << "MULTI_UNSELECTED case=" << testCase.name
							  << " candidates=" << original.size()
							  << " selection=0 stage=0 install=0 restore=0\n" ;
					break ;
				}

				// 通常INFは重複確認を出さないため、単一Install前の未作用を観測します。
				DRIVERCRATE_EXPECT( context, bound.observe().stages == 0U &&
												bound.observe().installs == 0U &&
												bound.observe().restoreBegins == 0U &&
												Access::controller( window).state() ==
													ApplicationState::SCAN_READY) ;
				// 公表後の変化条件だけを原native再列挙へ与え、DTOやtokenを変更しません。
				if( testCase.native == Native::DRIVER_ADDED ||
				   testCase.native == Native::DISAPPEARED || caseName == "U15" ||
				   caseName == "U16" || caseName == "U17") {
					bound.changeNativeState() ;
				}

				DialogState accept{
					.context = &context,
					.owner	 = handle,
					.mode	 = DialogMode::INDEX_INSTALL_ACCEPT} ;	// 予期しない確認も観測します。
				// 単一Install前の元operationです。
				const auto beforeOperation = Access::controller( window).activeOperationId() ;
				{
					// 予期しない確認dialogも検出します。
					DialogDriver driver( accept) ;
					Access::beginIndexInstall( window) ;
				}
				DRIVERCRATE_EXPECT( context, !accept.handled && !accept.failed &&
												Access::controller( window).activeOperationId() !=
													beforeOperation) ;
				auto installedOwner =
					std::make_unique<std::optional<WorkerEvent>>( Access::takeIndexTerminal(
						window,
						WorkerEventKind::INSTALL_COMPLETED)) ;	// 同scopeの元eventをheap所有します。
				auto &installed = *installedOwner ;				// 元復旧/個別導入結果の所有です。
				DRIVERCRATE_EXPECT( context, installed.has_value()) ;
				// 終端がなければ導入成功として画面へ送信しません。
				if( !installed) {
					break ;
				}

				const auto &result = installed->installResult ;	// 実復旧境界とProvider個別結果です。
				const auto	observed = bound.observe() ;		// 同operation終端後だけの低位値です。
				// 真の初回正例はscan後・準備・直前のinstalled-only照会を実際に通します。
				if( caseName == "I01" || newCase) {
					DRIVERCRATE_EXPECT( context, observed.installedOnlyQueries >= 3U) ;
				}

				DRIVERCRATE_EXPECT( context, observed.stages == testCase.stages &&
												observed.installs == testCase.installs &&
												observed.specifiedBindingMatches &&
												result.succeeded == testCase.succeeded &&
												result.updates.size() == selected.size()) ;
				// 一deviceだけを選択した共有操作で二番目deviceへ呼出しません。
				if( caseName == "S03") {
					DRIVERCRATE_EXPECT( context, observed.deviceInstalls[0] == 1U &&
													observed.deviceInstalls[1] == 0U) ;
				}

				// 全選択共有でも各deviceへ一度だけ指定導入します。
				if( caseName == "S01" || caseName == "S02") {
					DRIVERCRATE_EXPECT( context, observed.deviceInstalls[0] == 1U &&
													observed.deviceInstalls[1] == 1U) ;
				}

				// 原選択と各HRESULT/再起動を保持し、二番目失敗を全体成功へ変換しません。
				for( std::size_t index = 0U; index < result.updates.size(); ++index) {
					const auto &item	= result.updates[index] ;	// 元device別結果です。
					const bool	success = testCase.installs == testCase.selected &&
										 !((caseName == "S02" || caseName == "U21") &&
										   // 個別APIから固定した成功分母です。
										   index == 1U) ;
					// 復旧開始拒否ではProvider取得/導入へ到達しない元結果を保持します。
					if( caseName == "U19") {
						DRIVERCRATE_EXPECT(
							context,
							item.identity == selected[index] &&
								item.installOutcome == OutcomeCode::NOT_STARTED &&
								result.restorePointCreation.outcome == OutcomeCode::FAILURE &&
								Access::controller( window).scanSessionId() ==
									scanned->scanResult.scanSessionId &&
								result.restorePointCreation.error ==
									static_cast<NativeError>( E_ACCESSDENIED) &&
								observed.restoreBegins == 1U && observed.restoreCompletes == 0U) ;
					} else {
						DRIVERCRATE_EXPECT(
							context, item.identity == selected[index] &&
										 item.downloadOutcome == OutcomeCode::SUCCESS &&
										 item.installOutcome == (success ? OutcomeCode::SUCCESS
																		 : OutcomeCode::FAILURE) &&
										 (item.installError == 0) == success) ;
					}

					std::cout << "MULTI_ITEM case=" << testCase.name << " index=" << index
							  << " originalIdentity=" << (item.identity == selected[index])
							  << " install=" << static_cast<unsigned>( item.installOutcome)
							  << " hresult=" << item.installError
							  << " reboot=" << item.rebootRequired << '\n' ;
				}

				// 共有の部分結果は別HRESULTとORを維持します。
				if( caseName == "S02" || caseName == "U21") {
					DRIVERCRATE_EXPECT( context, result.installOutcome ==
														OutcomeCode::SUCCEEDED_WITH_ERRORS &&
													result.rebootRequired &&
													result.updates[1].installError ==
														static_cast<NativeError>( E_ACCESSDENIED)) ;
				}

				// 復旧終了失敗が個別成功を消さず全体成功だけを拒否します。
				if( testCase.native == Native::RESTORE_END_FAILURE || caseName == "U20") {
					DRIVERCRATE_EXPECT( context, !result.succeeded &&
													result.restorePointCompletion.outcome ==
														OutcomeCode::FAILURE &&
													result.restorePointCompletion.error ==
														static_cast<NativeError>( E_ACCESSDENIED)) ;
				}

				DialogState display{
					.context = &context,
					.owner	 = handle,
					.mode	 = DialogMode::INDEX_INSTALL_RESULT} ;	// 元結果を読む実dialogです。
				{
					DialogDriver driver( display) ;	// 実個別結果dialogの内容を保持して閉じます。
					Access::dispatchIndex( window, *installed) ;
				}
				DRIVERCRATE_EXPECT( context, display.handled && !display.failed) ;
				Access::verifyIndexResultRows( window, context, result) ;
				// 利用者が遭遇した二初回partial終端を実詳細本文まで通します。
				if( caseName == "U21") {
					verifyExpiredInitialDetails( window, context, result, false, plan.scanSessionId) ;
					Access::verifyExpiredHistoryBoundary( window, context, result) ;
					Access::displayRoleHistoryFixture( window, result) ;
					verifyExpiredInitialDetails( window, context, result, true, plan.scanSessionId) ;
					DialogState rejected{
						.context = &context,
						.owner	 = handle,
						.mode	 = DialogMode::
							INDEX_INSTALL_SELECTION_REQUIRED} ;	// 失効後の再導入案内です。
					{
						DialogDriver driver(
							rejected) ;	// 無効button相当のcommandも選択要求で止まります。
						Access::beginIndexInstallCommand( window) ;
					}
					DRIVERCRATE_EXPECT( context, rejected.handled && !rejected.failed) ;
					Access::verifyExpiredIndexPrompt( window, context, rejected.details) ;
					const auto unchanged =
						// 表示と拒否だけでは低位実行を増やしません。
						bound.observe() ;
					DRIVERCRATE_EXPECT(
						context, unchanged.stages == observed.stages &&
									 unchanged.installs == observed.installs &&
									 unchanged.restoreBegins == observed.restoreBegins &&
									 unchanged.restoreCompletes == observed.restoreCompletes &&
									 input.observeHttp().sends == http.sends) ;
				}

				const auto retained =
					// 古い通知で消してはいけない実結果です。
					Access::displayText( window) ;
				Access::dispatchIndex( window, *prepared) ;
				// U21は元ownerを保ち、他caseの従来の全失効条件は変更しません。
				const ScanSessionId expectedLateSession =
					caseName == "U21" ? plan.scanSessionId : 0U ;
				DRIVERCRATE_EXPECT( context, Access::displayText( window) == retained &&
												(caseName != "U21" || plan.scanSessionId != 0U) &&
												Access::controller( window).scanSessionId() ==
													expectedLateSession) ;
				// 代表三条件はUI拒否だけでなく失効した元worker権限へ実要求を送り直します。
				if( caseName == "M01" || caseName == "S01" || caseName == "I01" ||
				   caseName == "U01" || caseName == "U02") {
					DRIVERCRATE_EXPECT( context, Access::requestExpiredIndexInstall(
													window, installed->operationId + 1U,
													plan.scanSessionId, selected)) ;
					const auto stale = Access::takeIndexTerminal(
						window, WorkerEventKind::INSTALL_COMPLETED) ;	// 実拒否要求の終端だけです。
					DRIVERCRATE_EXPECT( context, stale.has_value()) ;
					// 拒否終端がない場合は未到達を成功として補完しません。
					if( stale) {
						DRIVERCRATE_EXPECT(
							context,
							!stale->installResult.succeeded &&
								stale->installResult.downloadOutcome == OutcomeCode::FAILURE &&
								stale->installResult.downloadError ==
									static_cast<NativeError>( E_UNEXPECTED) &&
								stale->installResult.installOutcome == OutcomeCode::NOT_STARTED &&
								stale->installResult.installError == 0 &&
								stale->installResult.updates.size() == selected.size()) ;
						// 失効拒否は元選択identityごとの未導入と元HRESULTを全件へ残します。
						for( std::size_t index = 0U; index < stale->installResult.updates.size();
							++index) {
							const auto &item =
								stale->installResult.updates[index] ;	// 元拒否結果一件です。
							DRIVERCRATE_EXPECT(
								context,
								index < selected.size() && item.identity == selected[index] &&
									item.downloadOutcome == OutcomeCode::FAILURE &&
									item.downloadError == static_cast<NativeError>( E_UNEXPECTED) &&
									item.installOutcome == OutcomeCode::NOT_STARTED &&
									item.installError == 0) ;
						}

						Access::dispatchIndex( window, *stale) ;
					}

					const auto afterStale = bound.observe() ;	// 拒否終端後だけの低位値です。
					DRIVERCRATE_EXPECT(
						context, afterStale.stages == observed.stages &&
									 afterStale.installs == observed.installs &&
									 afterStale.restoreBegins == observed.restoreBegins &&
									 afterStale.restoreCompletes == observed.restoreCompletes &&
									 input.observeHttp().sends == http.sends &&
									 Access::displayText( window) == retained) ;
					std::cout << "MULTI_STALE case=" << testCase.name
							  << " workerRejected=" << (stale && !stale->installResult.succeeded)
							  << " mutationUnchanged=" << (afterStale.installs == observed.installs)
							  << " resultRetained=" << (Access::displayText( window) == retained)
							  << '\n' ;
				}

				DRIVERCRATE_EXPECT( context, observed.signature.verifyCalls ==
													observed.signature.closeCalls &&
												observed.signature.rejectedCalls == 0U) ;
				std::cout << "MULTI_RESULT case=" << testCase.name
						  << " candidates=" << original.size() << " selected=" << selected.size()
						  << " fakeHttp=" << http.sends
						  << " inspectionRoots=" << observed.signature.inspectionRoots
						  << " stage=" << observed.stages
						  << " specifiedInstall=" << observed.installs
						  << " installedOnlyQueries=" << observed.installedOnlyQueries
						  << " succeeded=" << result.succeeded
						  << " rebootOR=" << result.rebootRequired
						  << " scanExpired=" << (Access::controller( window).scanSessionId() == 0U)
						  << " realOSChanges=0\n" ;
				// 明示した次のfake scan開始/受理で、旧結果を新候補へ継承しません。
				if( caseName == "U21") {
					Access::beginIndexScan( window) ;
					DRIVERCRATE_EXPECT( context, Access::count( window) == 0U) ;
					auto rescanned = Access::takeIndexTerminal(
						window,
						WorkerEventKind::SCAN_COMPLETED) ;	// 非通信の明示再検索だけです。
					DRIVERCRATE_EXPECT( context, rescanned.has_value()) ;
					// 元終端がある場合だけ新scan候補を通常表示へ渡します。
					if( rescanned) {
						Access::dispatchIndex( window, *rescanned) ;
						// 元候補とIDが再び現れても過去の実行履歴を付けません。
						for( const auto &candidate : Access::indexCandidates( window)) {
							DRIVERCRATE_EXPECT( context, Access::candidateDetails( window, candidate)
																.find( L"前回の実行結果（履歴）") ==
															std::wstring::npos) ;
						}
					}

					std::cout << "EXPIRED_INITIAL_HISTORY workerPartial=1 rolesDisplayFixture=1"
							  << " fakeRescanReset=1 realOSChanges=0\n" ;
				}
			} while( false) ;
		} catch( ...) {
			Access::stopWorker( window) ;
			DestroyWindow( handle) ;
			throw ;
		}

		Access::stopWorker( window) ;
		DestroyWindow( handle) ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed() && !IsWindow( handle) &&
										state->forbiddenCalls == 0U && state->restoreCalls == 0U &&
										state->normalCalls == 0U) ;
		std::cout << "MULTI_END case=" << testCase.name
				  << " failures=" << context.failureCount() - caseFailures << " terminal=1\n" ;
	}

	std::cout << "Multi UI assertions: " << context.assertionCount() - before
			  << ", failures: " << context.failureCount() - failures << ", cases=" << executed
			  << ", mode="
			  << (historyResultsOnly ? "history-results"
				  : unknownClassOnly ? "unknown"
									 : "multi")
			  << ", acquisition approval private fixture only, native CAT positive UNCONFIRMED\n" ;
	DRIVERCRATE_EXPECT( context, executed == (historyResultsOnly ? 1U : 27U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元141/root-onlyと固定19依存条件を本物通常画面/dialog/製品workerへ直列に通します。
 * @param[in,out] context 元未到達と失敗も保持する集計先です。
 * @param[in] needsOnly trueの場合は同固定表の追加19依存条件だけを実行します。既存分母を変更しません。
 * @param[in] extensionOnly trueの場合は登録Extension保持の固定八条件だけを実行します。
 * @note CAT/native低位は隔離完全fakeです。実CAT/実device/実導入成功を意味しません。
 */
//------------------------------------------------------------------------------
void runSignedIndexRequiredComponentUiScenarios( TestContext &context, const bool needsOnly = false,
												const bool extensionOnly = false)
{
	// 大きな終端値を短命なfactory内で受信し、元の検証scopeだけで所有する。
	const auto ownTerminal = []( auto make) { return std::make_unique<decltype( make())>( make()) ; } ;

	using Native = SignedIndexBindingNativeCase ;	// 元低位状態です。
	/** @brief 元141/root-onlyと事前固定した19依存条件の期待です。 */
	struct Case {
		/// 原caseの1起点IDです。
		unsigned	id ;
		/// 完全低位へ返す元拒否/初回条件です。
		Native		native ;
		/// 一device一計画の元公開候補数です。
		std::size_t candidates ;
		/// 同保護packageのstage API期待数です。
		unsigned	stages ;
		/// 選択親/必要子だけの指定API期待数です。
		unsigned	installs ;
		/// pending/部分失敗/復旧失敗を含めない全完了期待です。
		bool		succeeded ;
	} ;
	const std::array cases{
		Case{1U, Native::NORMAL, 1U, 2U, 1U, false},
		Case{2U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{3U, Native::NORMAL, 1U, 3U, 2U, false},
		Case{4U, Native::SHARED_SUCCESS, 2U, 3U, 4U, false},
		Case{5U, Native::INITIAL_CLASS_MISSING, 1U, 3U, 2U, false},
		Case{6U, Native::NORMAL, 1U, 3U, 2U, false},
		Case{7U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{8U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{9U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{10U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{11U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{12U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{13U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{14U, Native::NORMAL, 1U, 0U, 0U, false},
		Case{15U, Native::KNOWN_CLASS_MISMATCH, 1U, 0U, 0U, false},
		Case{16U, Native::NORMAL, 1U, 0U, 0U, false},
		Case{17U, Native::NORMAL, 1U, 0U, 0U, false},
		Case{18U, Native::NORMAL, 1U, 0U, 0U, false},
		Case{19U, Native::RESTORE_END_FAILURE, 1U, 2U, 1U, false},
		Case{20U, Native::REQUIRED_STAGE_PARTIAL, 1U, 2U, 0U, false},
		Case{21U, Native::REQUIRED_BASE_FAILURE, 1U, 2U, 1U, false},
		Case{22U, Native::REQUIRED_CHILD_FAILURE, 1U, 2U, 2U, false},
		Case{23U, Native::REQUIRED_CHILD_PENDING, 1U, 2U, 1U, false},
		Case{24U, Native::REQUIRED_WRONG_PARENT, 1U, 2U, 1U, false},
		Case{25U, Native::NORMAL, 1U, 2U, 1U, false},
		Case{26U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{27U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{28U, Native::NORMAL, 1U, 2U, 1U, false},
		Case{29U, Native::NORMAL, 1U, 2U, 1U, false},
		Case{30U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{31U, Native::REQUIRED_BASE_DIAGNOSTIC_MISSING, 1U, 2U, 1U, false},
		Case{32U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{33U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{34U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{35U, Native::IMPORT_MEMBER_FAILURE, 0U, 0U, 0U, false},
		Case{36U, Native::SECTION_EMPTY, 0U, 0U, 0U, false},
		Case{37U, Native::SECTION_INVALID, 0U, 0U, 0U, false},
		Case{38U, Native::SECTION_MISSING_FALLBACK, 0U, 0U, 0U, false},
		Case{39U, Native::SECTION_OTHER_INF, 0U, 0U, 0U, false},
		Case{40U, Native::SECTION_OTHER_MODEL, 1U, 2U, 2U, true},
		Case{41U, Native::SECTION_DECORATED, 0U, 0U, 0U, false},
		Case{42U, Native::SECTION_OTHER_OS, 0U, 0U, 0U, false},
		Case{43U, Native::SECTION_UNTERMINATED, 0U, 0U, 0U, false},
		Case{44U, Native::SECTION_DETAIL_INCOMPLETE, 0U, 0U, 0U, false},
		Case{45U, Native::SECTION_INF_UNTERMINATED, 0U, 0U, 0U, false},
		Case{46U, Native::SECTION_CHANGED, 1U, 0U, 0U, false},
		Case{47U, Native::NORMAL, 1U, 0U, 0U, false},
		Case{48U, Native::SHARED_SECTION_SUCCESS, 2U, 2U, 4U, true},
		Case{49U, Native::IMPORT_HASH_CHANGED, 1U, 0U, 0U, false},
		Case{50U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{51U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{52U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{53U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{54U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{55U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{56U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{57U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{58U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{59U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{60U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{61U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{62U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{63U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{64U, Native::SERVICE_EXE_MEMBER_FAILURE, 0U, 0U, 0U, false},
		Case{65U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{66U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{67U, Native::REQUIRED_CHILD_PENDING, 1U, 2U, 1U, false},
		Case{68U, Native::REQUIRED_WRONG_PARENT, 1U, 2U, 1U, false},
		Case{69U, Native::REQUIRED_CHILD_AMBIGUOUS, 1U, 2U, 1U, false},
		Case{70U, Native::REQUIRED_PARENT_NOT_STARTED, 1U, 2U, 1U, false},
		Case{71U, Native::SECTION_CHANGED, 1U, 0U, 0U, false},
		Case{72U, Native::NORMAL, 1U, 0U, 0U, false},
		Case{73U, Native::NORMAL, 1U, 0U, 0U, false},
		Case{74U, Native::NORMAL, 1U, 0U, 0U, false},
		Case{75U, Native::RESTORE_END_FAILURE, 1U, 2U, 2U, false},
		Case{76U, Native::REQUIRED_STAGE_PARTIAL, 1U, 2U, 0U, false},
		Case{77U, Native::REQUIRED_CHILD_FAILURE, 1U, 2U, 2U, false},
		Case{78U, Native::SERVICE_EXE_HASH_CHANGED, 1U, 0U, 0U, false},
		Case{79U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{80U, Native::SHARED_SECTION_SUCCESS, 2U, 2U, 4U, true},
		Case{81U, Native::INITIAL_CLASS_MISSING, 1U, 2U, 2U, true},
		Case{82U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{83U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{84U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{85U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{86U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{87U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{88U, Native::SERVICE_EXE_OTHER_OWNER, 0U, 0U, 0U, false},
		Case{89U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{90U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{91U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{100U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{101U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{102U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{103U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{104U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{105U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{106U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{107U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{108U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{109U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{110U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{111U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{112U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{113U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{114U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{115U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{116U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{117U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{118U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{119U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{120U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{121U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{122U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{123U, Native::REQUIRED_WRONG_PARENT, 1U, 2U, 1U, false},
		Case{124U, Native::SERVICE_EXE_OTHER_OWNER, 0U, 0U, 0U, false},
		Case{125U, Native::SERVICE_EXE_MEMBER_FAILURE, 0U, 0U, 0U, false},
		Case{126U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{127U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{128U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{129U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{130U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{131U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{132U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{133U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{134U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{135U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{136U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{137U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{138U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{139U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{140U, Native::SERVICE_EXE_OTHER_OWNER, 0U, 0U, 0U, false},
		Case{141U, Native::SERVICE_EXE_MEMBER_FAILURE, 0U, 0U, 0U, false},
		Case{142U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{143U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{144U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{145U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{146U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{147U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{148U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{149U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{150U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{151U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{152U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{153U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{154U, Native::DEPENDENCY_NOT_OBSERVED, 0U, 0U, 0U, false},
		Case{155U, Native::DEPENDENCY_AMBIGUOUS, 0U, 0U, 0U, false},
		Case{156U, Native::NORMAL, 0U, 0U, 0U, false},
		Case{157U, Native::DEPENDENCY_PAYLOAD_CHANGED, 0U, 0U, 0U, false},
		Case{158U, Native::DEPENDENCY_PACKAGE_CHANGED, 1U, 0U, 0U, false},
		Case{159U, Native::DEPENDENCY_SIGNATURE_REJECTED, 0U, 0U, 0U, false},
		Case{160U, Native::DEPENDENCY_CONTEXT_CHANGED, 0U, 0U, 0U, false},
		Case{161U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{162U, Native::NORMAL, 1U, 2U, 2U, true},
		Case{163U, Native::DEPENDENCY_ARCHITECTURE_CHANGED, 0U, 0U, 0U, false},
		Case{164U, Native::DEPENDENCY_SERVER_CHANGED, 0U, 0U, 0U, false},
		Case{165U, Native::DEPENDENCY_OS_CHANGED, 0U, 0U, 0U, false},
		Case{166U, Native::DEPENDENCY_SIGNER_UNTERMINATED, 0U, 0U, 0U, false},
		Case{167U, Native::DEPENDENCY_SIGNER_EMPTY, 0U, 0U, 0U, false},
		Case{168U, Native::DEPENDENCY_SIGNER_RECHECK_UNTERMINATED, 0U, 0U, 0U, false},
		Case{169U, Native::DEPENDENCY_SIGNER_RECHECK_EMPTY, 0U, 0U, 0U, false},
		Case{170U, Native::EXTENSION_REGISTERED_WRITE_PROBE, 1U, 2U, 1U, false},
		Case{171U, Native::EXTENSION_REGISTERED_DELETE_PROBE, 1U, 2U, 1U, false},
		Case{172U, Native::NORMAL, 1U, 2U, 1U, false},
		Case{173U, Native::EXTENSION_BASE_ALREADY_CURRENT, 1U, 2U, 1U, false},
		Case{174U, Native::REQUIRED_BASE_FAILURE, 1U, 2U, 1U, false},
		Case{175U, Native::REQUIRED_STAGE_PARTIAL, 1U, 2U, 0U, false},
		Case{176U, Native::STAGE_CHANGED, 1U, 1U, 0U, false},
		Case{177U, Native::STAGE_WRONG_NODE, 1U, 2U, 0U,
			 false}} ;											// 元161と追加八を分離して保持します。
	const auto	startAssertions = context.assertionCount() ;	// 本群だけの開始値です。
	const auto	startFailures	= context.failureCount() ;		// 元失敗を削除しません。
	std::size_t executed{} ;									// この入口で実行した固定条件数です。全条件数とは別に保持します。
	// 各条件を一Window/一workerの独立寿命へ限定します。
	for( const auto &testCase : cases) {
		// 有限diagnostic入口も同じ固定表と元期待を使い、元157条件を変更しません。
		if( (needsOnly && testCase.id < 151U) || (extensionOnly && testCase.id < 170U) ||
		   (!extensionOnly && testCase.id >= 170U)) {
			continue ;
		}

		++executed ;
		const auto caseFailures = context.failureCount() ;	// 未到達もcase失敗です。
		std::cout << "COMPONENT_BEGIN case=C" << (testCase.id < 10U ? "0" : "") << testCase.id
				  << '\n' ;
		MSG previousQuit{} ;	// 旧Windowの終了通知です。
		// 次modal loopへ旧WM_QUITを持ち越しません。
		while( PeekMessageW( &previousQuit, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
		}

		const bool shared =
			// 元共有と事前固定別節共有です。
			testCase.id == 4U || testCase.id == 48U || testCase.id == 80U ;
		auto input = makeSignedIndexUiInput(
			shared, shared, false, false, false, false,
			{.requiredComponentCase =
				 testCase.id >= 170U ? 1U : testCase.id}) ;	// 元ZIPを変更しません。
		std::wstring inputHashBefore ;						// 同原ZIP全byteのfixture構築前hashです。
		DRIVERCRATE_EXPECT( context, computeBytesSha256( input.zip, inputHashBefore) == 0) ;
		auto	   expired = std::make_shared<bool>( false) ;	// Idle間だけ変更するUTC条件です。
		const auto clock   = input.services.utc ;				// 元信頼UTCです。
		input.services.utc = [clock, expired]() {
			auto value = clock() ;	// 元時計だけを変更します。
			// 原taskの期限を延長せず期限外へ移します。
			if( *expired && value) {
				*value += std::chrono::days{2} ;
			}

			return value ;
		} ;
		auto bound = makeSignedIndexBindingWorker( std::move( input.services), input.zip, shared,
												  testCase.id == 18U || testCase.id == 74U, false,
												  testCase.native) ;	// 完全native/CAT低位です。
		std::wstring inputHashAfter ;									// 期待表補足後の同原ZIP全byteです。
		DRIVERCRATE_EXPECT( context, computeBytesSha256( input.zip, inputHashAfter) == 0 &&
										inputHashBefore == inputHashAfter &&
										input.payload == input.zip) ;
		std::wcout << L"COMPONENT_INPUT id=" << testCase.id << L" bytes=" << input.zip.size()
				   << L" before=" << inputHashBefore << L" after=" << inputHashAfter << L'\n' ;
		DRIVERCRATE_EXPECT( context, bound.worker != nullptr) ;
		// 不成立workerを成功DTOで補完しません。
		if( !bound.worker) {
			continue ;
		}

		auto	   state = std::make_shared<MetadataUiState>() ;	// 別Providerroutingの観測です。
		const auto windowOwner =
			std::make_unique<MainWindow>() ;	// 同じscopeだけで大きなfixtureを所有する。
		auto &window = *windowOwner ;			// 本物製品Windowです。
		Access::configure( window, state) ;
		const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 実生成結果です。
		DRIVERCRATE_EXPECT( context, created) ;
		// Window未到達も分母へ保持します。
		if( !created) {
			bound.worker->stop() ;
			continue ;
		}

		const auto handle = Access::handle( window) ;	// Scope内の非所有HWNDです。
		ShowWindow( handle, SW_HIDE) ;
		Access::attachIndexWorker( window, std::move( bound.worker)) ;
		// 元未到達を失敗へ残し、共通終端でworkerを停止します。
		do {
			Access::beginIndexScan( window) ;
			const auto scannedOwner = ownTerminal( [&] {
				return Access::takeIndexTerminal( window, WorkerEventKind::SCAN_COMPLETED) ;
			}) ; // 同workerの元終端だけを所有する。
			auto	  &scanned =
				*scannedOwner ;	// 元caseの期間だけ終端値を借用する。	// 元scanの実worker終端です。
			std::cout << "COMPONENT_SCAN id=" << testCase.id << " event=" << scanned.has_value()
					  << " kind=" << (scanned ? static_cast<int>( scanned->kind) : -1)
					  << " succeeded=" << (scanned && scanned->scanResult.succeeded)
					  << " scanError=" << (scanned ? scanned->scanResult.error : 0)
					  << " indexStatus="
					  << (scanned ? static_cast<int>( scanned->indexSummary.status) : -1)
					  << " preparationError=" << (scanned ? scanned->preparationError : 0)
					  << " plan=" << (scanned && scanned->preparationPlan.has_value()) << '\n' ;
			DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
											scanned->preparationPlan) ;
			// 元scanがなければ取得へ進みません。
			if( !scanned || !scanned->preparationPlan) {
				break ;
			}

			Access::dispatchIndex( window, *scanned) ;
			const auto &plan = *scanned->preparationPlan ;	// 元取得planです。
			DRIVERCRATE_EXPECT( context, Access::acquireIndexPlan( window, plan)) ;
			// 元取得/内容検査の実worker終端です。
			const auto preparedOwner = ownTerminal( [&] {
				return Access::takeIndexTerminal( window, WorkerEventKind::PREPARATION_COMPLETED) ;
			}) ;										   // 同workerの元終端だけを所有する。
			auto	  &prepared		 = *preparedOwner ;	// 元caseの期間だけ終端値を借用する。
			DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
			// 元終端がない結果を成功にしません。
			if( !prepared) {
				break ;
			}

			std::vector<UpdateCandidate> candidates ;	// 実元bytes/native binderからだけです。
			// 拒否行を含め元reportを保持します。
			for( const auto &report : prepared->preparationResult.auditReports) {
				candidates.insert( candidates.end(), report.publishedCandidates.begin(),
								  report.publishedCandidates.end()) ;
				std::cout << "COMPONENT_AUDIT id=" << testCase.id
						  << " accepted=" << report.acceptedInfCount
						  << " contentError=" << report.contentError
						  << " firstRejection=" << report.firstContentRejection
						  << " publicationError=" << report.publication.firstError << '\n' ;
			}

			DRIVERCRATE_EXPECT( context, candidates.size() == testCase.candidates) ;
			Access::dispatchIndex( window, *prepared) ;
			const auto http = input.observeHttp() ;	// 共有を含む一GETの実低位です。
			DRIVERCRATE_EXPECT( context, http.sends == 1U && http.safe && http.opens == http.closes) ;
			// 欠損/曖昧/未対応をbaseだけの正常へ代替しません。
			if( candidates.size() != testCase.candidates || candidates.empty()) {
				DRIVERCRATE_EXPECT( context,
								   bound.observe().stages == 0U && bound.observe().installs == 0U) ;
				break ;
			}

			std::vector<std::wstring> selected ;	// 元parent一候補だけです。
			// 一device一計画と必要role件数を本物Treeへ渡します。
			for( const auto &candidate : candidates) {
				DRIVERCRATE_EXPECT(
					context,
					candidate.requiredExtensionCount + candidate.requiredDriverComponentCount > 0U) ;
				selected.push_back( candidate.identity) ;
			}

			Access::verifyIndexSelectionBoundary( window, context, selected) ;
			// 未選択では復旧/導入を呼びません。
			if( testCase.id == 16U) {
				break ;
			}

			Access::selectIndexCandidates( window, context, selected) ;
			// 本物確認dialogで必ず一度NOを操作する観測先です。
			DialogState cancel{
				.context = &context, .owner = handle, .mode = DialogMode::INDEX_INSTALL_CANCEL} ;
			{
				DialogDriver driver( cancel) ;	// 本物確認dialog NOです。
				Access::beginIndexInstall( window) ;
			}
			DRIVERCRATE_EXPECT( context, cancel.handled && !cancel.failed &&
											bound.observe().restoreBegins == 0U &&
											cancel.details.find( L"必要構成") != std::wstring::npos) ;
			// 明示拒否を導入権限にしません。
			if( testCase.id == 17U || testCase.id == 73U) {
				break ;
			}

			// 元UTCだけを期限外へ移す固定入力です。
			if( testCase.id == 14U || testCase.id == 47U || testCase.id == 72U) {
				*expired = true ;
			}

			// 元native Class状態の変化を復旧前に拒否します。
			if( testCase.id == 15U || testCase.id == 46U || testCase.id == 49U ||
			   testCase.id == 71U || testCase.id == 78U || testCase.id == 158U) {
				bound.changeNativeState() ;
			}

			// 元選択の明示YESだけを操作する観測先です。
			DialogState accept{
				.context = &context, .owner = handle, .mode = DialogMode::INDEX_INSTALL_ACCEPT} ;
			{
				DialogDriver driver( accept) ;	// 本物確認dialog YESです。
				Access::beginIndexInstall( window) ;
			}
			const auto installedOwner = ownTerminal( [&] {
				return Access::takeIndexTerminal( window, WorkerEventKind::INSTALL_COMPLETED) ;
			}) ; // 同workerの元終端だけを所有する。
			auto	  &installed =
				*installedOwner ;	// 元caseの期間だけ終端値を借用する。	// 同保護operationの実終端です。
			DRIVERCRATE_EXPECT( context, installed.has_value()) ;
			// 実終端がない結果は未到達です。
			if( !installed) {
				break ;
			}

			const auto &result = installed->installResult ;	// 製品保護経路の元結果です。
			DRIVERCRATE_EXPECT( context, result.succeeded == testCase.succeeded &&
											result.updates.size() == selected.size()) ;
			// 復旧開始失敗は役割APIより前であり元診断を保持します。
			if( testCase.id == 18U || testCase.id == 74U) {
				DRIVERCRATE_EXPECT( context, !result.updates.empty() &&
												result.restorePointCreation.outcome ==
													OutcomeCode::FAILURE &&
												result.restorePointCreation.error != 0 &&
												result.updates.front().requiredRoles.empty()) ;
			}

			// 復旧終了失敗で既に実行した基本APIの結果を消しません。
			if( testCase.id == 19U || testCase.id == 75U) {
				DRIVERCRATE_EXPECT(
					context, result.restorePointCreation.outcome == OutcomeCode::SUCCESS &&
								 result.restorePointCompletion.outcome == OutcomeCode::FAILURE &&
								 result.restorePointCompletion.error != 0 && !result.succeeded) ;
			}

			// 復旧前拒否と復旧開始拒否以外は必要role結果を保持します。
			for( const auto &item : result.updates) {
				const auto completed = std::ranges::count(
					item.requiredRoles, DriverPlanReflectionState::INSTALL_API_COMPLETED,
					&DriverPlanRoleExecutionResult::reflection) ;	// 推測なしAPI完了数です。
				const auto pending = std::ranges::count(
					item.requiredRoles, DriverPlanReflectionState::WINDOWS_PENDING,
					&DriverPlanRoleExecutionResult::reflection) ;	// 未確認数です。
				// Extensionの個別反映は全追加条件でも独立未確認を維持します。
				if( testCase.id >= 170U) {
					DRIVERCRATE_EXPECT( context, item.requiredRoles.size() == 2U &&
													item.requiredRoles.back().role ==
														DriverPlanRole::EXTENSION &&
													!result.succeeded) ;
					// base指定APIの正常完了だけをWindows反映未確認と併記します。
					if( testCase.id <= 173U) {
						DRIVERCRATE_EXPECT( context, completed == 1 && pending == 1 &&
														item.requiredRoles.back().installOutcome ==
															OutcomeCode::NOT_STARTED) ;
					} else {
						DRIVERCRATE_EXPECT(
							context,
							completed == 0 && pending == 0 &&
								std::ranges::all_of( item.requiredRoles, []( const auto &role) {
									return role.installOutcome != OutcomeCode::SUCCESS ;
								})) ; // stage/指定API拒否を適用未確認の成功へ昇格しません。
						const auto &base =
							// 原順の個別結果を借用します。
							item.requiredRoles.front() ;
						const auto &extension = item.requiredRoles.back() ;	// 元必要役割だけです。
						// 登録byte拒否ではbase指定前の未実行とExtension失敗を区別します。
						if( testCase.id == 176U) {
							DRIVERCRATE_EXPECT( context,
											   base.stageOutcome == OutcomeCode::NOT_STARTED &&
												   extension.stageOutcome == OutcomeCode::FAILURE &&
												   extension.reflection ==
													   DriverPlanReflectionState::FAILED) ;
						} else {
							DRIVERCRATE_EXPECT(
								context,
								base.reflection == DriverPlanReflectionState::FAILED &&
									extension.stageOutcome == OutcomeCode::SUCCESS &&
									extension.reflection == DriverPlanReflectionState::STAGED &&
									extension.installOutcome == OutcomeCode::NOT_STARTED) ;
						}
					}
				}

				DRIVERCRATE_EXPECT( context, testCase.id == 14U || testCase.id == 15U ||
												testCase.id == 18U || testCase.id == 46U ||
												testCase.id == 47U || testCase.id == 49U ||
												testCase.id == 71U || testCase.id == 72U ||
												testCase.id == 74U || testCase.id == 78U ||
												testCase.id == 158U || !item.requiredRoles.empty()) ;
				// 正常SWCはbaseと子のAPI完了を実際に必要とします。
				if( testCase.succeeded) {
					DRIVERCRATE_EXPECT( context, completed == 2 && pending == 0) ;
					DRIVERCRATE_EXPECT( context, item.requiredRoles.size() == 2U &&
													item.requiredRoles.back().role ==
														DriverPlanRole::DRIVER_COMPONENT) ;
				}

				// Win32 serviceの復旧終了失敗でも両指定API完了を保持し、全体成功へ上げません。
				if( testCase.id == 75U) {
					DRIVERCRATE_EXPECT( context,
									   completed == 2 && pending == 0 && !result.succeeded) ;
				}

				// 必要Extensionの全成功をbase API完了から補完しません。
				if( testCase.id == 1U || testCase.id == 3U || testCase.id == 28U ||
				   testCase.id == 29U) {
					DRIVERCRATE_EXPECT( context, pending >= 1 && !result.succeeded &&
													result.installOutcome ==
														OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
				}

				// 復旧終了失敗でも元base APIとExtension適用未確認を保持します。
				if( testCase.id == 19U) {
					DRIVERCRATE_EXPECT( context, completed == 1 && pending == 1) ;
				}

				// 一部stageの失敗では先行stage事実と未実行installを区別します。
				if( testCase.id == 20U || testCase.id == 76U) {
					DRIVERCRATE_EXPECT(
						context,
						std::ranges::count( item.requiredRoles, OutcomeCode::SUCCESS,
										   &DriverPlanRoleExecutionResult::stageOutcome) == 1 &&
							std::ranges::count( item.requiredRoles, OutcomeCode::FAILURE,
											   &DriverPlanRoleExecutionResult::stageOutcome) == 1 &&
							completed == 0 &&
							std::ranges::all_of( item.requiredRoles, []( const auto &role) {
								return role.installOutcome == OutcomeCode::NOT_STARTED ;
							})) ;
				}

				// base失敗から子のAPI完了を補完しません。
				if( testCase.id == 21U || testCase.id == 31U) {
					DRIVERCRATE_EXPECT(
						context,
						completed == 0 && item.requiredRoles.size() == 2U &&
							item.requiredRoles.front().role == DriverPlanRole::BASE_DRIVER &&
							item.requiredRoles.front().installOutcome == OutcomeCode::FAILURE &&
							item.requiredRoles.back().installOutcome == OutcomeCode::NOT_STARTED) ;
				}

				// FALSEの欠落診断をAPI完了へ変換せず明示不正として保持します。
				if( testCase.id == 31U) {
					DRIVERCRATE_EXPECT(
						context, item.installError == static_cast<NativeError>(
														  HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) &&
									 item.requiredRoles.front().installError == item.installError &&
									 item.requiredRoles.front().installDiagnosticMissing &&
									 result.installOutcome == OutcomeCode::FAILURE) ;
				}

				// child失敗ではbase API完了を保持し、全体を部分結果へ分類します。
				if( testCase.id == 22U || testCase.id == 77U) {
					DRIVERCRATE_EXPECT(
						context,
						completed == 1 && item.requiredRoles.size() == 2U &&
							item.requiredRoles.front().reflection ==
								DriverPlanReflectionState::INSTALL_API_COMPLETED &&
							item.requiredRoles.back().role == DriverPlanRole::DRIVER_COMPONENT &&
							item.requiredRoles.back().installOutcome == OutcomeCode::FAILURE &&
							item.requiredRoles.back().installError != 0 &&
							result.installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
				}

				// absent/wrong-parentではbase APIだけを認定し子の適用を推測しません。
				if( testCase.id == 23U || testCase.id == 24U || testCase.id == 67U ||
				   testCase.id == 68U || testCase.id == 70U || testCase.id == 123U) {
					DRIVERCRATE_EXPECT( context,
									   completed == 1 && pending == 1 && !result.succeeded) ;
				}

				// 同親/同IDの曖昧子は元DUP_NAMEを個別失敗へ残し、一つを導入しません。
				if( testCase.id == 69U) {
					DRIVERCRATE_EXPECT(
						context,
						completed == 1 && item.requiredRoles.size() == 2U &&
							item.requiredRoles.back().installError ==
								static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_DUP_NAME)) &&
							item.requiredRoles.back().installOutcome == OutcomeCode::FAILURE &&
							!result.succeeded) ;
				}

				std::cout << "COMPONENT_ITEM id=" << testCase.id
						  << " roles=" << item.requiredRoles.size() << " apiCompleted=" << completed
						  << " pending=" << pending << " hresult=" << item.installError << '\n' ;
			}

			// 元状態/期限不足は復旧開始より前です。
			if( testCase.id == 14U || testCase.id == 15U || testCase.id == 46U ||
			   testCase.id == 47U || testCase.id == 49U || testCase.id == 71U ||
			   testCase.id == 72U || testCase.id == 78U || testCase.id == 158U) {
				DRIVERCRATE_EXPECT( context, bound.observe().restoreBegins == 0U) ;
			}

			// 本物結果dialogと保持Treeの観測先です。
			DialogState display{
				.context = &context, .owner = handle, .mode = DialogMode::INDEX_INSTALL_RESULT} ;
			{
				DialogDriver driver( display) ;	// 本物結果dialogを閉じます。
				Access::dispatchIndex( window, *installed) ;
			}
			DRIVERCRATE_EXPECT( context, display.handled && !display.failed &&
											Access::controller( window).scanSessionId() == 0U) ;
			const auto retained = Access::displayText( window) ;	// 元結果表示です。
			// 新八条件はDTOだけでなく本物TreeViewの役割別結果を検証します。
			if( testCase.id >= 170U) {
				const UINT baseStatus = testCase.id <= 173U ? IDS_INDEX_ROLE_API_COMPLETED
										: testCase.id == 176U
											? IDS_NOT_INSTALLED
											: IDS_INSTALL_FAILED ;	// 固定期待の原役割です。
				const UINT extensionStatus =
					testCase.id <= 173U	  ? IDS_INDEX_ROLE_PENDING
					: testCase.id == 176U ? IDS_INSTALL_FAILED
										  : IDS_INDEX_ROLE_STAGED ;	// 元登録/失敗を区別します。
				Access::verifyExtensionRoleRows( window, context, selected.front(), baseStatus,
												extensionStatus) ;
			}

			Access::dispatchIndex( window, *prepared) ;
			DRIVERCRATE_EXPECT( context, retained == Access::displayText( window)) ;
			// 終端失効は元worker権限へ実要求を送って確認します。
			if( testCase.id == 25U) {
				DRIVERCRATE_EXPECT(
					context, Access::requestExpiredIndexInstall( window, installed->operationId + 1U,
																plan.scanSessionId, selected)) ;
				// 終端済み元sessionの再要求に対する実worker拒否です。
				const auto	staleOwner = ownTerminal( [&] {
					 return Access::takeIndexTerminal( window, WorkerEventKind::INSTALL_COMPLETED) ;
				 }) ;								  // 同workerの元終端だけを所有する。
				const auto &stale	   = *staleOwner ;	// 元caseの期間だけ終端値を借用する。
				DRIVERCRATE_EXPECT( context, stale && !stale->installResult.succeeded) ;
			}
		} while( false) ;
		const auto observed = bound.observe() ;	// 元終端後・署名scope生存中の確定低位です。
		// 同版baseの計画でもstageだけで終了せず、明示された指定API一回を確認します。
		if( testCase.id == 173U) {
			DRIVERCRATE_EXPECT( context,
							   observed.baseInitiallySameVersion && observed.installs == 1U) ;
		}

		// 元登録Extensionの保持を実file共有拒否と全byteへ結合します。
		if( testCase.id == 170U || testCase.id == 171U) {
			DRIVERCRATE_EXPECT( context,
							   observed.registeredExtensionProbes == 2U &&
								   observed.registeredExtensionBlocked == 2U &&
								   observed.registeredExtensionError == ERROR_SHARING_VIOLATION &&
								   observed.registeredExtensionBytesUnchanged) ;
			std::cout << "EXTENSION_PIN id=" << testCase.id
					  << " probes=" << observed.registeredExtensionProbes
					  << " blocked=" << observed.registeredExtensionBlocked
					  << " error=" << observed.registeredExtensionError
					  << " bytesUnchanged=" << observed.registeredExtensionBytesUnchanged << '\n' ;
		}

		// 正常PACKAGEの必要節は同元INFの独立署名観測へ到達しなければ成功ではありません。
		if( testCase.id == 151U || testCase.id == 158U) {
			DRIVERCRATE_EXPECT( context, observed.dependencyPackageObservations > 0U) ;
		}

		// SYSTEMの正常効果は全payload/既存宛先CATを検査し、SYSTEMをstageしません。
		if( testCase.id == 152U) {
			DRIVERCRATE_EXPECT( context, observed.dependencySystemEffectChecks > 0U &&
											observed.dependencySystemStageCalls == 0U) ;
		}

		Access::stopWorker( window) ;
		DRIVERCRATE_EXPECT(
			context, observed.stages == testCase.stages && observed.installs == testCase.installs &&
						 observed.opens == observed.closes && observed.specifiedBindingMatches &&
						 bound.allNativeHandlesClosed()) ;
		DestroyWindow( handle) ;
		std::cout << "COMPONENT_END case=C" << (testCase.id < 10U ? "0" : "") << testCase.id
				  << " stage=" << observed.stages << " specifiedInstall=" << observed.installs
				  << " dependencyPackage=" << observed.dependencyPackageObservations
				  << " systemEffect=" << observed.dependencySystemEffectChecks
				  << " systemStage=" << observed.dependencySystemStageCalls
				  << " dependencyVersion=" << observed.dependencyVersionCalls
				  << " dependencyInf=" << observed.dependencyInfCalls
				  << " dependencyCatalog=" << observed.dependencyCatalogCalls
				  << " dependencyWindows=" << observed.dependencyWindowsDirectoryCalls
				  << " dependencyStore=" << observed.dependencyDriverStoreCalls
				  << " dependencySignerResponse=" << observed.dependencySignerResponsesValid
				  << " dependencySignerMask=" << observed.dependencySignerMask
				  << " failures=" << context.failureCount() - caseFailures << '\n' ;
	}

	std::cout
		<< "Component UI assertions: " << context.assertionCount() - startAssertions
		<< ", failures: " << context.failureCount() - startFailures << ", cases=" << executed
		<< ", totalFixedCases=" << cases.size()
		<< ", originalCases=28, originalSupplement=3, selectedSectionCases=19, serviceCases=41, requiredFormCases=26, newMediaCases=24, rootOnlyCases=1, needsCases=19, real CAT/device/install UNCONFIRMED\n" ;
}

} // namespace
} // namespace test
} // namespace drivercrate

namespace drivercrate::test {

/** @brief 追加制御だけの名前付き期待を元UI assertionから分離して保持します。 */
struct NativeControlChecks {
	/// この新しい制御群で到達した期待数です。
	unsigned assertions{} ;
	/// 不成立だった追加期待数です。
	unsigned failures{} ;
	/**
	 * @brief 名前付き期待の実値を記録します。
	 * @param[in] name 固定した非機密な期待名です。
	 * @param[in] value 実API観測から求めた結果です。
	 */
	void	 check( const char *name, const bool value)
	{
		++assertions ;
		failures += value ? 0U : 1U ;
		std::cout << "NATIVE_CONTROL name=" << name << " passed=" << value << '\n' ;
	}
} ;

/** @brief 同threadの実MessageBoxを20ms timerで操作する有限借用状態です。 */
struct NativeModalState {
	/// Modal中だけ借用する自作owner HWNDです。
	HWND	 owner{} ;
	/// 直接返却後に生存を確認する実popupです。
	HWND	 popup{} ;
	/// 今回の実button IDです。YESまたはNOだけを指定します。
	int		 button{} ;
	/// 実timerで確認したdefault-NOと所有境界です。
	bool	 observed{} ;
	/// 実callbackへ到達した回数です。
	unsigned ticks{} ;
} ;
// 同期MessageBox scopeだけを借用し、timer回収後に解除します。
thread_local NativeModalState *nativeModal{} ;

//------------------------------------------------------------------------------
/**
 * @brief Message照会前にpopupのprocessとthreadを現在の所有scopeへ照合します。
 * @param[in] process 観測したpopupのPIDです。
 * @param[in] thread 観測したpopupのthread IDです。
 * @param[in] expectedProcess 現在の試験PIDです。0は許可しません。
 * @param[in] expectedThread 現在の試験thread IDです。0は許可しません。
 * @return 非0の期待PIDとthreadが両方一致する場合trueです。
 * @note 数値だけの純粋判定であり、window照会やmessage送信は行いません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool			   nativeModalIdentityAllowed( const DWORD process, const DWORD thread,
														  const DWORD expectedProcess,
														  const DWORD expectedThread) noexcept
{
	return expectedProcess != 0U && expectedThread != 0U && process == expectedProcess &&
		   thread == expectedThread ;
}

//------------------------------------------------------------------------------
/**
 * @brief 所有関係とmodalの観測が揃った場合だけYESまたはNOを許可します。
 * @param[in] ownedPopup 自作ownerと異なるpopupがそのownerへ属する場合trueです。
 * @param[in] ownerDisabled Modalにより自作ownerが無効の場合trueです。
 * @param[in] defaultButton 実DM_GETDEFIDで観測したbutton IDです。
 * @param[in] button 今回要求するbutton IDです。
 * @return 所有modal・既定NO・YESまたはNOの条件が揃う場合trueです。
 * @pre 実windowに使う場合はnativeModalIdentityAllowedの成功後であること。
 * @note 数値だけの純粋判定であり、window照会やmessage送信は行いません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool nativeModalClickAllowed( const bool ownedPopup, const bool ownerDisabled,
										   const UINT defaultButton, const int button) noexcept
{
	return ownedPopup && ownerDisabled && defaultButton == IDNO &&
		   (button == IDYES || button == IDNO) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自作ownerの実popupだけを元と同じ20ms timerから操作します。
 * @param[in] window Thread timerの未使用HWNDです。
 * @param[in] message 未使用のmessageです。
 * @param[in] timer 当該scopeが所有するtimer IDです。
 * @param[in] ticks 未使用のtick値です。
 */
//------------------------------------------------------------------------------
void CALLBACK nativeModalTimer( HWND window, UINT message, UINT_PTR timer, DWORD ticks) noexcept
{
	static_cast<void>( window) ;
	static_cast<void>( message) ;
	static_cast<void>( ticks) ;
	// Scope外の遅延callbackでは借用pointerを参照しません。
	if( !nativeModal) {
		return ;
	}

	auto &state = *nativeModal ;	// 同UI threadだけが更新する借用状態です。
	++state.ticks ;
	const HWND popup = GetLastActivePopup( state.owner) ;	// 自作ownerのpopupだけを参照します。
	// 実popup生成を待ち、無関係なwindowへ入力しません。
	if( !popup || popup == state.owner || GetWindow( popup, GW_OWNER) != state.owner) {
		return ;
	}

	DWORD		process{} ;												// 実popupのPIDです。
	const DWORD thread = GetWindowThreadProcessId( popup, &process) ;	// 実popupのthreadです。
	// 他processまたは他threadにはdefault照会を含むmessageを一切送りません。
	if( !nativeModalIdentityAllowed( process, thread, GetCurrentProcessId(), GetCurrentThreadId())) {
		return ;
	}

	const UINT defaultButton =
		// 所有確認後の実既定値です。
		LOWORD( SendMessageW( popup, DM_GETDEFID, 0, 0)) ;
	const bool ownedPopup = GetWindow( popup, GW_OWNER) == state.owner ;	// Click直前の所有関係です。
	// 既定NOと自作ownerのmodal状態が欠ける場合もclickを許可しません。
	if( !nativeModalClickAllowed( ownedPopup, !IsWindowEnabled( state.owner), defaultButton,
								state.button)) {
		return ;
	}

	state.popup	   = popup ;
	state.observed = true ;
	static_cast<void>( KillTimer( nullptr, timer)) ;
	SendDlgItemMessageW( popup, state.button, BM_CLICK, 0, 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 起動・実UI/workerと元の終了手順を新制御だけで確認します。
 * @param[in,out] checks 元UI期待とは独立した集計先です。
 */
//------------------------------------------------------------------------------
void nativeStartupControl( NativeControlChecks &checks)
{
	auto	   state = std::make_shared<MetadataUiState>() ;	// 既存fakeだけの共有状態です。
	MainWindow window ;											// 製品と同じ本物UIです。
	Access::configure( window, state) ;
	const bool created = window.create( GetModuleHandleW( nullptr)) ;	// 元resourceで生成します。
	checks.check( "startup-real-MainWindow", created) ;
	// 作成失敗時に未定義HWNDへ操作しません。
	if( !created) {
		return ;
	}

	const HWND handle = Access::handle( window) ;	// 本scopeの実HWNDです。
	ShowWindow( handle, SW_SHOWNOACTIVATE) ;
	checks.check( "startup-real-HWND-desktop",
				 IsWindow( handle) && privateUiObserved && !privateLifecycleFailed) ;
	checks.check( "startup-real-worker-factory",
				 pumpUntil( [] { return privateWorkerObservations.load() > 0U ; })) ;
	checks.check( "startup-worker-nonInput",
				 privateWorkerObservations > 0U && !privateLifecycleFailed) ;
	SendMessageW( handle, WM_CLOSE, 0, 0) ;
	checks.check( "startup-WM_CLOSE-destroy", !IsWindow( handle)) ;
	checks.check( "startup-no-real-operations",
				 state->forbiddenCalls == 0U && state->restoreCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実YES/NO・既定NOとWM_CLOSE後の所有HWND消失を確認します。
 * @param[in,out] checks 追加期待の集計先です。
 */
//------------------------------------------------------------------------------
void nativeModalControl( NativeControlChecks &checks)
{
	HWND owner = CreateWindowExW( 0U, L"STATIC", L"DriverCrate synthetic modal owner",
								 WS_OVERLAPPEDWINDOW, 0, 0, 320, 180, nullptr, nullptr,
								 // 自作ownerです。
								 GetModuleHandleW( nullptr), nullptr) ;
	checks.check( "modal-owner-created", owner != nullptr) ;
	// Ownerがない状態でdesktop全体のmodalを作りません。
	if( !owner) {
		return ;
	}

	ShowWindow( owner, SW_SHOWNOACTIVATE) ;
	// 元と同じ実modalをYESとNOでそれぞれ一回だけ操作します。
	for( const int button : {IDYES, IDNO}) {
		NativeModalState state{owner, nullptr, button, false, 0U} ;	// Modal終了まで生存します。
		nativeModal			 = &state ;
		const UINT_PTR timer = SetTimer( nullptr, 0U, 20U, nativeModalTimer) ;	// 実20ms timerです。
		checks.check( button == IDYES ? "YES-real20ms-timer" : "NO-real20ms-timer", timer != 0U) ;
		// Timer生成失敗時は自動操作不能なmodalへ入りません。
		if( timer == 0U) {
			nativeModal = nullptr ;
			break ;
		}

		const int result =
			MessageBoxW( owner, L"Synthetic lifecycle control", L"DriverCrate test",
						MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) ;	// 実APIの直接返却値です。
		std::cout << "PRIVATE_MODAL requested=" << button << " actual=" << result
				  << " defaultNoOwned=" << state.observed << " ticks=" << state.ticks << '\n' ;
		const bool timerStopped =
			// Callback側で解除済みでも再入を防ぎます。
			KillTimer( nullptr, timer) != FALSE ;
		static_cast<void>( timerStopped) ;
		nativeModal = nullptr ;
		checks.check( button == IDYES ? "YES-direct6-defaultNO-owner" : "NO-direct7-defaultNO-owner",
					 result == button && state.observed && state.ticks > 0U) ;
		checks.check( button == IDYES ? "YES-popup-destroy-owner-enabled"
									 : "NO-popup-destroy-owner-enabled",
					 !IsWindow( state.popup) && IsWindowEnabled( owner)) ;
	}

	SendMessageW( owner, WM_CLOSE, 0, 0) ;
	checks.check( "standalone-WM_CLOSE-owned-HWND-gone", !IsWindow( owner)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通の環境key・modal許可判定の固定正負例と実YES/NOを確認します。
 * @param[in,out] checks 元UI期待と独立した新boundaryの集計先です。
 * @note 全entryとIDは架空です。外部windowと実環境値は負例に使用しません。
 */
//------------------------------------------------------------------------------
void nativeBoundaryControl( NativeControlChecks &checks)
{
	// 共通選択predicateへ渡す架空entryと除去可否です。順序と分母を固定します。
	constexpr std::array<std::pair<std::wstring_view, bool>, 10U> KEY_CASES{
		{{L"DRIVERCRATE_UI_PRIVATE_DESKTOP=synthetic", true},
		 {L"drivercrate_ui_private_desktop=synthetic", true},
		 {L"DriverCrate_Ui_Private_Desktop=synthetic", true},
		 {L"DRIVERCRATE_UI_PRIVATE_DESKTOP=", true},
		 {L"DRIVERCRATE_UI_PRIVATE_DESKTOP_EXTRA=synthetic", false},
		 {L"XDRIVERCRATE_UI_PRIVATE_DESKTOP=synthetic", false},
		 {L"=C:=synthetic", false},
		 {L"DRIVERCRATE_UI_PRIVATE_DESKTOP", false},
		 {L"DRIVERCRATE_UI_PRIVATE_DESKTOP=synthetic=tail", true},
		 {L"OTHER=DRIVERCRATE_UI_PRIVATE_DESKTOP", false}}} ;
	// 実環境を変更せず、起動環境copyと同じ判定を全10件へ一回ずつ適用します。
	for( const auto &testCase : KEY_CASES) {
		checks.check( "boundary-environment-exact-key",
					 nativePrivateMarkerEntry( testCase.first) == testCase.second) ;
	}

	// 観測PID/thread、期待PID/thread、期待許可を持つ純粋判定の架空6件です。
	constexpr std::array<std::array<DWORD, 5U>, 6U> IDENTITY_CASES{{{11U, 22U, 11U, 22U, 1U},
																	{12U, 22U, 11U, 22U, 0U},
																	{11U, 23U, 11U, 22U, 0U},
																	{0U, 22U, 11U, 22U, 0U},
																	{11U, 0U, 11U, 22U, 0U},
																	{0U, 0U, 0U, 0U, 0U}}} ;
	// Foreign相当の数値でも実windowを作成・照会せず共通guardの拒否を確認します。
	for( const auto &testCase : IDENTITY_CASES) {
		checks.check( "boundary-modal-identity-before-message",
					 nativeModalIdentityAllowed( testCase[0], testCase[1], testCase[2],
												testCase[3]) == (testCase[4] != 0U)) ;
	}

	// 所有関係、owner無効、既定button、要求button、期待許可の架空6件です。
	constexpr std::array<std::array<UINT, 5U>, 6U> CLICK_CASES{{{1U, 1U, IDNO, IDYES, 1U},
																{1U, 1U, IDNO, IDNO, 1U},
																{0U, 1U, IDNO, IDYES, 0U},
																{1U, 0U, IDNO, IDYES, 0U},
																{1U, 1U, IDYES, IDYES, 0U},
																{1U, 1U, IDNO, IDOK, 0U}}} ;
	// Clickを実行しない純粋判定で各modal前提の欠落を一回ずつ確認します。
	for( const auto &testCase : CLICK_CASES) {
		checks.check( "boundary-modal-permission-before-click",
					 nativeModalClickAllowed( testCase[0] != 0U, testCase[1] != 0U, testCase[2],
											 static_cast<int>( testCase[3])) == (testCase[4] != 0U)) ;
	}

	nativeModalControl( checks) ;
}

//------------------------------------------------------------------------------
/**
 * @brief live HWND時の所属拒否と実cleanupエラーの伝播を検査します。
 * @param[in,out] checks 追加期待の集計先です。
 * @param[in] errors Launch失敗とcleanup拒否も検査する場合trueです。
 */
//------------------------------------------------------------------------------
void nativeReassignControl( NativeControlChecks &checks, const bool errors)
{
	const HDESK original  = GetThreadDesktop( GetCurrentThreadId()) ;	// 子初期desktopを借用します。
	const auto	name	  = privateDesktopName + L"_secondary" ;		// 同子だけの第二desktop名です。
	HDESK		secondary = CreateDesktopW( name.c_str(), nullptr, nullptr, 0U,
										   DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW |
											   DESKTOP_CREATEMENU | DESKTOP_WRITEOBJECTS,
										   nullptr) ;	// 所有資源です。
	checks.check( "secondary-created-nonInput", secondary && nativeNonInput( secondary)) ;
	// 取得失敗時は借用desktopを操作しません。
	if( !secondary) {
		return ;
	}

	HWND window = CreateWindowExW( 0U, L"STATIC", L"Synthetic reassignment", WS_OVERLAPPED, 0, 0, 32,
								  32, nullptr, nullptr, GetModuleHandleW( nullptr),
								  nullptr) ;	// 同threadの所有HWNDです。
	checks.check( "reassign-live-HWND", window != nullptr) ;
	SetLastError( ERROR_SUCCESS) ;
	const bool reassigned = SetThreadDesktop( secondary) != FALSE ;	// live HWNDでの実拒否を測ります。
	const DWORD error	  = GetLastError() ;						// 他API前に保持します。
	checks.check( "live-HWND-reassignment-refused170", !reassigned && error == ERROR_BUSY) ;
	// 作成できた自作HWNDだけを破棄します。
	if( window) {
		checks.check( "reassign-owned-HWND-destroy", DestroyWindow( window) != FALSE) ;
	}

	const bool	assigned = SetThreadDesktop( secondary) != FALSE ;			// Window破棄後の明示所属です。
	const DWORD assignedError = assigned ? ERROR_SUCCESS : GetLastError() ;	// 実再所属のエラーです。
	const auto	assignedName =
		// 変更後の実所属です。
		nativeDesktopName( GetThreadDesktop( GetCurrentThreadId())) ;
	std::cout << "PRIVATE_REASSIGN assigned=" << assigned << " error=" << assignedError
			  << " actualMatchesSecondary=" << (assignedName == name) << '\n' ;
	checks.check( "reassign-after-destroy", assigned && assignedName == name) ;
	// 採用cleanup APIの実拒否とlaunch失敗を限定scopeで観測します。
	if( errors) {
		const bool closedWhileAssigned =
			// 利用中なので失敗を要求します。
			CloseDesktop( secondary) != FALSE ;
		checks.check( "cleanup-active-desktop-error-propagated", !closedWhileAssigned) ;
		STARTUPINFOW		startup{sizeof( STARTUPINFOW)} ;				// 存在しない自作子の起動条件です。
		PROCESS_INFORMATION child{} ;										// 失敗時も空であることを確認します。
		std::wstring command = L"DriverCrate-no-such-lifecycle-child.exe" ;	// 不在の有限入力です。
		const bool	 launched =
			CreateProcessW( L"?:\\DriverCrate-no-such-lifecycle-child.exe", command.data(), nullptr,
						   nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &startup,
						   &child) != FALSE ;		// 同子だけの起動です。
		const DWORD launchError = GetLastError() ;	// 実API失敗値です。
		checks.check( "launch-invalid-path-error-propagated", !launched &&
																 launchError != ERROR_SUCCESS &&
																 !child.hProcess && !child.hThread) ;
	}

	const bool	restored	 = SetThreadDesktop( original) != FALSE ;		// 借用元へ明示復帰します。
	const DWORD restoreError = restored ? ERROR_SUCCESS : GetLastError() ;	// 復帰APIの実errorです。
	const auto	restoredName =
		// 復帰後の実所属です。
		nativeDesktopName( GetThreadDesktop( GetCurrentThreadId())) ;
	std::cout << "PRIVATE_RESTORE restored=" << restored << " error=" << restoreError
			  << " actualMatchesOriginal=" << (restoredName == privateDesktopName) << '\n' ;
	checks.check( "reassign-original-restored", restored && restoredName == privateDesktopName) ;
	checks.check( "reassign-secondary-closed", CloseDesktop( secondary) != FALSE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示control familyを元UI期待と独立して実行します。
 * @param[in] mode 起動前に固定したcontrol名です。
 * @return 新controlの成功は0、失敗は1です。held-childは親が74で終端します。
 */
//------------------------------------------------------------------------------
int runNativeControl( const std::string_view mode)
{
	NativeControlChecks checks ;	// 元453期待に追加しない独立分母です。
	// Held-childは固定sleepでなく所有eventで待機到達を通知します。
	if( mode == "lifecycle-expiry") {
		const auto name = L"Local\\" + privateDesktopName + L"_ready" ;	// 親が作ったevent名です。
		HANDLE	   ready =
			// 同scopeの所有handleです。
			OpenEventW( EVENT_MODIFY_STATE, FALSE, name.c_str()) ;
		HANDLE hold = CreateEventW( nullptr, TRUE, FALSE, nullptr) ;	// 誰もsignalしない所有待機です。
		// 失敗した同期を期限切れ成功へ数えません。
		if( !ready || !hold || !SetEvent( ready)) {
			return 1 ;
		}

		std::cout << "NATIVE_CONTROL owned-held-child-ready=1\n" << std::flush ;
		static_cast<void>( WaitForSingleObject( hold, INFINITE)) ;
		static_cast<void>( CloseHandle( hold)) ;
		static_cast<void>( CloseHandle( ready)) ;
		return 1 ;
	}

	// 実MainWindowと実factory worker所属を確認します。
	if( mode == "lifecycle-startup") {
		nativeStartupControl( checks) ;
	}
	// 本物modalの直接返却と破棄を確認します。
	else if( mode == "lifecycle-modal") {
		nativeModalControl( checks) ;
	}
	// 限定boundary群は共通の純粋判定と実modalを同一private環境で確認します。
	else if( mode == "lifecycle-boundary") {
		nativeBoundaryControl( checks) ;
	} else {
		nativeReassignControl( checks, mode == "lifecycle-errors") ;
		// API-onlyのerrors familyだけで実Assign拒否・未resume・同handle回収を確認します。
		if( mode == "lifecycle-errors") {
			checks.check( "unassigned-child-failure75-never-resumed-cleanup",
						 supervisePrivateUi( "lifecycle-assignment-error") == 75 &&
							 !privateLifecycleFailed) ;
		}
	}

	std::cout << "NATIVE_CONTROL_SUMMARY assertions=" << checks.assertions
			  << " failures=" << checks.failures << '\n' ;
	return checks.assertions > 0U && checks.failures == 0U && !privateLifecycleFailed ? 0 : 1 ;
}

} // namespace drivercrate::test

//------------------------------------------------------------------------------
/**
 * @brief 明示optionでだけ非通信Win32画面試験を実行する。
 * @param[in] argc 引数数。
 * @param[in] argv Process開始時の引数。試験option以外は拒否する。
 * @return 外部起動はprivate子の実終了値を転送し、監督固有の拒否・失敗も返します。
 * @retval 0 試験と所有後始末が成功しました。
 * @retval 1 初期化・試験・子のlifecycle観測が失敗しました。
 * @retval 2 明示optionを満たさない入力を拒否しました。
 * @retval 73 内部markerまたは起動desktopの照合を拒否しました。
 * @retval 74 所有子が期限切れとなり、同作成handleの終端を確認しました。
 * @retval 75 監督の初期化・起動・所有後始末または例外処理が失敗しました。
 */
//------------------------------------------------------------------------------
int main( const int argc, char **argv)
{
	const std::string_view mode = argc == 3 ? argv[2] : "default" ;	// 元の外部modeです。
	const bool nativeControl	= mode == "lifecycle-startup" || mode == "lifecycle-modal" ||
							   mode == "lifecycle-marker" || mode == "lifecycle-reassign" ||
							   mode == "lifecycle-expiry" ||
							   // 旧六群と限定boundary群だけを明示許可します。
							   mode == "lifecycle-errors" || mode == "lifecycle-boundary" ;
	// 通常起動やdouble clickではWindow・worker・成果物を作らない。
	if( argc < 2 || argc > 3 || std::string_view( argv[1]) != "--run-ui-tests" ||
	   (argc == 3 && std::string_view( argv[2]) != "close" && std::string_view( argv[2]) != "queue" &&
		std::string_view( argv[2]) != "app-update" && std::string_view( argv[2]) != "index" &&
		std::string_view( argv[2]) != "binding" && std::string_view( argv[2]) != "multi" &&
		std::string_view( argv[2]) != "formats" && std::string_view( argv[2]) != "format-order" &&
		std::string_view( argv[2]) != "unknown" && std::string_view( argv[2]) != "components" &&
		std::string_view( argv[2]) != "needs" && std::string_view( argv[2]) != "extension" &&
		std::string_view( argv[2]) != "preparation" && std::string_view( argv[2]) != "hardware" &&
		std::string_view( argv[2]) != "refresh" && std::string_view( argv[2]) != "refresh-probe" &&
		std::string_view( argv[2]) != "refresh-render-evidence" &&
		std::string_view( argv[2]) != "history" && std::string_view( argv[2]) != "history-keys" &&
		std::string_view( argv[2]) != "history-initial" &&
		std::string_view( argv[2]) != "history-images" &&
		std::string_view( argv[2]) != "history-results" &&
		std::string_view( argv[2]) != "diagnostics" &&
		std::string_view( argv[2]) != "preparation-failure" &&
		std::string_view( argv[2]) != "install-view" && std::string_view( argv[2]) != "target-only" &&
		std::string_view( argv[2]) != "latest-view" &&
		std::string_view( argv[2]) != "diagnostics-failure" && !nativeControl)) {
		std::cout
			<< "Internal fake UI only. Use --run-ui-tests. No network or driver operations.\n" ;
		return 2 ;
	}

	try {
		wchar_t		marker[256]{} ;	// 環境の過大markerを拒否する有限領域です。
		const DWORD length = GetEnvironmentVariableW( drivercrate::test::PRIVATE_DESKTOP_MARKER,
													 marker, 256U) ;	// Process-local値です。
		// Markerなしの外部起動だけがwindowless supervisorへ入ります。
		if( length == 0U && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
			return drivercrate::test::supervisePrivateUi( mode) ;
		}

		// 不正markerと誤desktopをCOM/common controls/HWND生成前に拒否します。
		if( length == 0U || length >= 256U || !drivercrate::test::validatePrivateStartup( marker)) {
			return 73 ;
		}
	} catch( const std::exception &error) {
		std::cerr << "Private UI supervision failed: " << error.what() << '\n' ;
		return 75 ;
	} catch( ...) {
		std::cerr << "Private UI supervision failed.\n" ;
		return 75 ;
	}

	// 所属変更のAPI-only制御はCOM/controlに依存しないwindowless条件で実行します。
	if( mode == "lifecycle-expiry" || mode == "lifecycle-reassign" || mode == "lifecycle-errors") {
		return drivercrate::test::runNativeControl( mode) ;
	}

	const HRESULT apartment =
		// WICとUIのCOM lifetime。
		CoInitializeEx( nullptr, COINIT_APARTMENTTHREADED) ;
	// UI threadのCOM初期化に失敗したまま試験を継続しない。
	if( FAILED( apartment)) {
		return 1 ;
	}

	static_cast<void>( SetProcessDpiAwarenessContext( DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) ;
	INITCOMMONCONTROLSEX		   controls{sizeof( INITCOMMONCONTROLSEX),
									ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES |
										ICC_STANDARD_CLASSES} ;	// 製品と同じ標準control集合。
	drivercrate::test::TestContext context ;					// Assertionと失敗の集計先。
	const bool					   initialized =
		// 外部frameworkを要求しない。
		InitCommonControlsEx( &controls) != FALSE ;
	DRIVERCRATE_EXPECT( context, initialized) ;
	// 新controlは元UI assertion数と混ぜずに独立した結果を返します。
	if( nativeControl) {
		const int result =
			initialized ? drivercrate::test::runNativeControl( mode) : 1 ;	// 新制御だけの終了値です。
		CoUninitialize() ;
		return result ;
	}

	try {
		// 標準controlの初期化が成功した場合にだけWindowを操作する。
		if( initialized) {
			// 製品と同じ一process一MainWindowの終了単位で各試験を分離する。
			if( argc == 2) {
				drivercrate::test::runUiScenarios( context) ;
			}
			// App更新は完全fakeだけで通常busy/modalと同意/closeを確認します。
			else if( mode == "app-update") {
				drivercrate::test::runAppUpdateUiTests( context) ;
			}
			// 元行の表示保持と正常な準備二条件だけを同private HWNDで確認します。
			else if( mode == "latest-view") {
				drivercrate::test::runTargetOnlyLocalUiScenario( context, true) ;
				drivercrate::test::runLatestBoundaryUiScenarios( context) ;
			}
			// 既存の対象限定三経路は元の条件を維持します。
			else if( mode == "target-only") {
				drivercrate::test::runTargetOnlyLocalUiScenario( context) ;
				drivercrate::test::runTargetOnlySharedUiScenario( context) ;
				drivercrate::test::runTargetOnlySharedUiScenario( context, true) ;
			}
			// 元item/scrollを保持する既view契約だけを確認します。
			else if( mode == "install-view") {
				drivercrate::test::runInstallTreeViewUiScenarios( context) ;
				drivercrate::test::runSearchPreparationUiScenarios( context, true) ;
			}
			// 新準備失敗の九入力だけを同private desktopで有限確認します。
			else if( mode == "preparation-failure") {
				drivercrate::test::runPreparationFailureUiScenarios( context) ;
			}
			// 新匿名診断の保存状態だけを同private desktopで有限確認します。
			else if( mode == "diagnostics" || mode == "diagnostics-failure") {
				drivercrate::test::runDiagnosticUiScenarios( context, mode == "diagnostics-failure") ;
			}
			// 新しい詳細tableと旧版filterだけを元private desktopで有限実行します。
			else if( std::string_view( argv[2]) == "history" ||
					std::string_view( argv[2]) == "history-keys") {
				drivercrate::test::runHistoryUiScenarios( context, std::string_view( argv[2]) ==
																	  "history-keys") ;
			}
			// 二画像だけは既fixtureを同じ所有Windowで再取得します。
			else if( std::string_view( argv[2]) == "history-images") {
				drivercrate::test::historyImagesOnly = true ;
				drivercrate::test::runHistoryUiScenarios( context) ;
			}
			// 初回だけは元低位fakeとfresh Windowで独立確認します。
			else if( std::string_view( argv[2]) == "history-initial") {
				drivercrate::test::runHistoryInitialUiScenarios( context) ;
			}
			// 索引専用群も同じ明示optionの内部targetからだけ実行します。
			else if( std::string_view( argv[2]) == "index") {
				drivercrate::test::runIndexUiScenarios( context) ;
			}
			// ハードウェア再検出の新表示とmetadata案内だけを内部fixtureで確認します。
			else if( std::string_view( argv[2]) == "hardware") {
				drivercrate::test::runHardwareRefreshUiScenarios( context) ;
				drivercrate::test::runSearchPreparationUiScenarios( context) ;
			}
			// 固定refresh/実隔離store/通常queueとWindowだけを明示実行します。
			else if( std::string_view( argv[2]) == "refresh") {
				drivercrate::test::runRefreshUiScenarios( context) ;
				drivercrate::test::runVisibleRefreshUiScenarios( context) ;
				drivercrate::test::runCaptureGuardRegression( context) ;
			}
			// 元formatterの生成/copy/geometryを観測する新条件だけを明示実行します。
			else if( std::string_view( argv[2]) == "refresh-probe") {
				drivercrate::test::runVisibleRefreshUiScenarios( context, true) ;
				drivercrate::test::runUnchangedRefreshUiScenario( context) ;
			}
			// 元fresh/cache二入力の四dialogだけで独立描画と保存段階を一回ずつ比較します。
			else if( std::string_view( argv[2]) == "refresh-render-evidence") {
				drivercrate::test::independentRenderEvidence = true ;
				drivercrate::test::runVisibleRefreshUiScenarios( context, true) ;
				DRIVERCRATE_EXPECT( context, drivercrate::test::independentRasterCaptures == 8U) ;
				std::cout << "INDEPENDENT_RENDER_END inputCases=2 phases=4 rasterCaptures="
						  << drivercrate::test::independentRasterCaptures << " boundaryAssertions="
						  << drivercrate::test::independentRenderAssertions << '\n' ;
			}
			// 真署名から通常候補・指定導入へ通す群も明示optionの内部targetだけです。
			else if( std::string_view( argv[2]) == "binding") {
				drivercrate::test::runSignedIndexBindingUiScenarios( context) ;
			}
			// 複数INF/共有/初回/登録先の有限群も内部target明示optionだけで実行します。
			else if( std::string_view( argv[2]) == "history-results") {
				drivercrate::test::runSignedIndexMultiUiScenarios( context, false, true) ;
			}
			// 元の全条件は既明示入口のまま保持します。
			else if( std::string_view( argv[2]) == "multi") {
				drivercrate::test::runSignedIndexMultiUiScenarios( context) ;
			}
			// Class未確定初回の追加固定27条件だけを内部targetで実行します。
			else if( std::string_view( argv[2]) == "unknown") {
				drivercrate::test::runSignedIndexMultiUiScenarios( context, true) ;
			}
			// 元141とC150と追加19を合わせた必要役割の固定161条件を通常UIへ通します。
			else if( std::string_view( argv[2]) == "components") {
				drivercrate::test::runSignedIndexRequiredComponentUiScenarios( context) ;
			}
			// 局所化用の固定19依存条件も同じ通常worker/UI経路へ通します。
			else if( std::string_view( argv[2]) == "extension") {
				drivercrate::test::runSignedIndexRequiredComponentUiScenarios( context, false, true) ;
			}
			// 追加依存条件も同じ元固定表から実行します。
			else if( std::string_view( argv[2]) == "needs") {
				drivercrate::test::runSignedIndexRequiredComponentUiScenarios( context, true) ;
			}
			// 固定した同意・追加形式群だけを明示optionで実行します。
			else if( std::string_view( argv[2]) == "formats") {
				drivercrate::test::runSignedIndexConsentFormatUiScenarios( context) ;
			}
			// 独立した五順序を、原formats全体の分母の代わりに数えません。
			else if( std::string_view( argv[2]) == "format-order") {
				// 拒否・生産先行・consumer先行を固定順で各一回だけ実行します。
				for( const std::string_view order : {"no", "quit", "queue", "hold", "terminal"}) {
					drivercrate::test::runSignedIndexConsentFormatUiScenarios( context, order) ;
				}
			}
			// 原HTML全文と通常取得commandの固定11条件は同内部targetの明示optionだけです。
			else if( std::string_view( argv[2]) == "preparation") {
				drivercrate::test::runPreparationCommandUiScenarios( context) ;
			} else {
				drivercrate::test::runCloseAndQueue( context, std::string_view( argv[2]) == "queue") ;
			}
		}
	} catch( const std::exception &error) {
		std::cerr << "Internal UI fixture exception: " << error.what() << '\n' ;
		DRIVERCRATE_EXPECT( context, false) ;
	} catch( ...) {
		std::cerr << "Internal UI fixture exception.\n" ;
		DRIVERCRATE_EXPECT( context, false) ;
	}

	CoUninitialize() ;
	drivercrate::test::printCaptureTelemetry() ;
	std::cout << "UI assertions: " << context.assertionCount()
			  << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 && !drivercrate::test::privateLifecycleFailed ? 0 : 1 ;
}
