//------------------------------------------------------------------------------
/**
 * @file main_window.cpp
 * @brief DriverCrateメインウィンドウ実装。
 * @version 01.27.01
 * @date 2026/10/24
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  UI選択loopの目的を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Install確認結果をoperation契約へ接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Server NICの最終確認を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  公式pageの概算size表示を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測差分表示を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得確認と独立した操作状態を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  TreeTable表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元ポイント状態表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  TreeTable font拡大。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Device class icon表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  TreeTable column sort追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Application icon設定。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  推奨更新表示filter追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Filter checkbox背景透過。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  上下message font拡大。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  上下message垂直中央表示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  更新候補一括選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Filter有効化時背景補正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  決定型進捗と自動再scan追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  下部全幅progress帯追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Install結果保持と自動再scan廃止。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  公式vendor catalog進捗表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Manufacturer intake状態表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider取得元設定と状態表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  同一版取得元選択表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider coverage表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local候補到達dialog追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Windows Server install確認追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  候補別既定選択根拠対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Silicon Labs CP210x ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  公式探索経路表示と確認追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者指定Intel ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択候補の到達件数表示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Prolific DCHU ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH341SER ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH342／CH343系ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用署名済みINF ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ZIP選択pathを動的領域へ移動。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補監査状態列追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  段階別scan計測と失効状態の表示を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の条件・取消し・表示専用結果を接続。
 * Ver.01.01.00 Shunji Ogawa  2026/09/14  Windows種類別の三階層一覧と件数を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  登録状態・候補検証理由と詳細画面を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  共通package入力と内容検査の説明を更新。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  公式探索の一scan統一確認を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/09/15  通常scanの協調取消しUIを接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/12  索引読取りと同計画の独立内容summaryを表示。
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  有限索引画面fixtureと同じ私有event dispatchを使用。
 * Ver.01.08.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.09.00 Shunji Ogawa  2026/10/12  同scan私有根拠付き初回候補を通常最終確認へ接続。
 * Ver.01.10.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.10.01 Shunji Ogawa  2026/10/12  実指定導入結果の分岐説明を制御文へ結合。
 * Ver.01.11.00 Shunji Ogawa  2026/10/13  一候補の必要構成確認と役割別結果を通常画面へ表示。
 * Ver.01.12.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * Ver.01.13.00 Shunji Ogawa  2026/10/16  索引通信結果の可視導線と同版publicationの画面受入を追加。
 * Ver.01.14.00 Shunji Ogawa  2026/10/16  索引通信詳細の全文と数値末尾の実control観測を追加。
 * Ver.01.14.01 Shunji Ogawa  2026/10/24  索引時刻拒否の理由を既存通信結果へ表示。
 * Ver.01.15.00 Shunji Ogawa  2026/10/27  一device一行の四列一覧と詳細内の候補選択を接続。
 * Ver.01.16.00 Shunji Ogawa  2026/10/28  通常検索前の再検出と取得前案内の境界を追加。
 * Ver.01.16.01 Shunji Ogawa  2026/10/28  他候補が混在する取得待ちの案内を保持。
 * Ver.01.17.00 Shunji Ogawa  2026/10/28  選択対象の導入後実観測と現在行の自動更新を接続。
 * Ver.01.18.00 Shunji Ogawa  2026/10/28  検索から取得確認へ続け、初回候補を通常行で選択可能にする。
 * Ver.01.19.00 Shunji Ogawa  2026/10/28  三列一覧と最下段案内へ整理し、取得取消しを主操作へ集約。
 * Ver.01.20.00 Shunji Ogawa  2026/10/28  元選択に結合した取得・検査と導入の二段階操作へ接続。
 * Ver.01.21.00 Shunji Ogawa  2026/11/02  公式規約の画面内案内と明示Install・任意全文閲覧を接続。
 * Ver.01.21.01 Shunji Ogawa  2026/11/02  取得前参照と未導入の確認・検査済み更新の表示分類を分離。
 * Ver.01.22.00 Shunji Ogawa  2026/11/03  元scanと表示predicateの匿名件数診断を接続。
 * Ver.01.23.00 Shunji Ogawa  2026/11/03  新版の取得前参照を通常の確認・選択へ接続。
 * Ver.01.24.00 Shunji Ogawa  2026/11/08  匿名導入診断と保存状態・元数値の有限確認を追加。
 * Ver.01.25.00 Shunji Ogawa  2026/11/08  同一署名索引の取得省略と通信失敗cacheを区別。
 * Ver.01.26.00 Shunji Ogawa  2026/11/08  準備不成立後の元表示保持と段階別匿名診断を追加。
 * Ver.01.27.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続。
 * Ver.01.27.01 Shunji Ogawa  2026/11/09  導入終端のfilterと既存ツリー行・表示位置を保持。
 * </pre>
 *
 * @note Win32 TreeTable、候補選択、およびworker eventの表示を実装します。全UI操作はUI threadで実行します。
 */
//------------------------------------------------------------------------------

#include "app/main_window.h"

#include "app/resource.h"
#include "core/candidate_audit.h"
#include "core/candidate_selection.h"
#include "core/device_observation.h"
#include "core/provider_registry.h"
#include "core/pending_reference_version.h"
#include "platform/windows_error.h"
#include "platform/windows_product_type.h"
#include "platform/signed_index_manifest.h"
#include "platform/local_diagnostic_log.h"
#include "platform/local_scan_diagnostics.h"

#include <CommCtrl.h>
#include <CommDlg.h>
#include <Objbase.h>
#include <Uxtheme.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <numeric>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr wchar_t WINDOW_CLASS_NAME[] = L"DriverCrate.MainWindow" ;	// RegisterClass用の固有名。
/** @brief 保存状態だけを固定resourceと数値で表示します。
 * @param[in] instance 製品resourceを持つmoduleです。
 * @return 既loggerの保存/未保存案内。未開始は空です。
 */
std::wstring	  diagnosticStorageText( const HINSTANCE instance)
{
	const auto storage = localDiagnosticStatus() ;	// 非待機の数値snapshotです。
	// 内部UIの未開始loggerを偽の保存済みにしません。
	if( storage.state == DiagnosticStorageState::NOT_STARTED) {
		return {} ;
	}

	const bool failed = storage.state == DiagnosticStorageState::FAILED ||
						// driver成否とは別です。
						storage.state == DiagnosticStorageState::STOP_TIMEOUT ;
	std::wstring counts = std::to_wstring( storage.saved) + L"/" + std::to_wstring( storage.pending) +
						  L"/" + std::to_wstring( storage.dropped) ;	// 匿名件数です。
	// 保存不能には最初の固定段階と元code有無を付けます。
	if( failed) {
		counts = std::to_wstring( static_cast<unsigned>( storage.state)) + L"/" +
				 std::to_wstring( static_cast<unsigned>( storage.stage)) + L"/" +
				 std::to_wstring( storage.codeKnown) + L"/" + std::to_wstring( storage.code) + L"/" +
				 counts ;
	}

	const UINT	 id = failed ? IDS_DIAGNOSTIC_STORAGE_FAILED
					  : storage.pending != 0U || storage.dropped != 0U || !storage.startupFlushed
						  ? IDS_DIAGNOSTIC_STORAGE_PENDING
						  : IDS_DIAGNOSTIC_STORAGE_SAVED ;			// 未保存を保存成功へ換算しません。
	wchar_t		 text[512]{} ;										// 固定resourceだけです。
	const int	 length = LoadStringW( instance, id, text, 512) ;	// I/Oは発生しません。
	std::wstring message( text,
						 length > 0 ? static_cast<std::size_t>( length) : 0U) ;	// 所有表示値です。
	const auto	 marker = message.find( L"%1") ;								// 既一引数formatと同じ置換です。
	// 不明な位置へ書き込みません。
	if( marker != std::wstring::npos) {
		message.replace( marker, 2U, counts) ;
	}

	return message ;
}
constexpr int		  DEFAULT_WINDOW_WIDTH	= 1280 ;	// 初回Window幅（logical pixel）。
constexpr int		  DEFAULT_WINDOW_HEIGHT = 720 ;		// 初回Window高さ（logical pixel）。
constexpr int		  MINIMUM_WINDOW_WIDTH	= 960 ;		// 利用者が縮小できる最小幅（logical pixel）。
constexpr int		  MINIMUM_WINDOW_HEIGHT = 560 ;		// 利用者が縮小できる最小高さ（logical pixel）。
constexpr std::size_t MAXIMUM_CONFIRMATION_TITLES = 5 ;	// 確認dialogへ列挙する候補数の上限。
// TreeTable column titleを左から定義するresource ID群。
constexpr std::array<UINT, 3> TREE_COLUMN_RESOURCE_IDS{
	IDS_COLUMN_DEVICE_DRIVER, IDS_COLUMN_CURRENT_VERSION, IDS_COLUMN_CANDIDATE_VERSION} ;
// 96 DPIにおけるTreeTable columnの初期幅とWindow resize時の比率。
constexpr std::array<int, 3> TREE_COLUMN_LOGICAL_WIDTHS{650, 210, 280} ;
constexpr int		  MESSAGE_FONT_POINT_SIZE = 10 ;			// 上下messageで保証する最小font size（point）。
constexpr int		  TREE_FONT_POINT_SIZE	  = 11 ;			// TreeTableで保証する最小font size（point）。
constexpr int		  TREE_ROW_LOGICAL_HEIGHT = 26 ;			// 96 DPIにおけるTreeTable一行の高さ。
constexpr UINT_PTR	  RECOMMENDED_FILTER_SUBCLASS_ID  = 1U ;	// Filter checkboxのsubclass識別子。
constexpr std::size_t MAXIMUM_FILTER_LABEL_CHARACTERS = 128U ;	// Filter labelの文字数上限。
constexpr std::size_t MAXIMUM_STATUS_CHARACTERS		  = 2048U ;	// Status帯へ描画する文字数上限。
constexpr UINT		  PROVIDER_MENU_COMMAND_BASE	  = 3000U ;	// Provider popup内の先頭command ID。
constexpr UINT	 LOCAL_COVERAGE_MENU_COMMAND = 3100U ;			// Local coverage dialogを開くcommand ID。

/** @brief 索引通信結果の同期read-only dialogだけを制御します。
 * @param[in] dialog 呼出し元MainWindowが所有する同期dialogです。
 * @param[in] message 処理するWin32通知です。
 * @param[in] wordParameter 終了buttonのcommand IDです。
 * @param[in] longParameter 初期化時だけ有効な所有本文への非所有pointerです。
 * @return 処理済みならTRUE、標準処理へ委譲する場合FALSEです。
 * @note 本文はDialogBoxParamWの終了まで呼出し元が保持し、ここでは保存しません。
 */
INT_PTR CALLBACK indexRefreshDetailsProc( HWND dialog, UINT message, WPARAM wordParameter,
										 LPARAM longParameter) noexcept
{
	// 同期初期化中だけ呼出し元の本文を借用して標準controlへcopyします。
	if( message == WM_INITDIALOG) {
		// LPARAMはこのdialogを生成した同UI threadのstd::wstringを指します。
		const auto *body = reinterpret_cast<const std::wstring *>( longParameter) ;
		// 不正な初期化で空の成功表示を作りません。
		if( body == nullptr) {
			EndDialog( dialog, IDCANCEL) ;
			return TRUE ;
		}

		wchar_t title[128]{} ;	// Resourceから読む有限なdialog名称です。
		LoadStringW( GetModuleHandleW( nullptr), IDS_INDEX_REFRESH_DETAILS, title, 128) ;
		SetWindowTextW( dialog, title) ;
		SetDlgItemTextW( dialog, IDC_METADATA_DETAIL_TEXT, body->c_str()) ;
		return TRUE ;
	}

	// 閉じる操作だけを受理し、取得や状態変更を開始しません。
	if( message == WM_CLOSE || (message == WM_COMMAND && (LOWORD( wordParameter) == IDOK ||
														 LOWORD( wordParameter) == IDCANCEL))) {
		EndDialog( dialog, IDOK) ;
		return TRUE ;
	}

	return FALSE ;
}
// Local coverage dialogへ表示するmanufacturer／class組合せの上限。
constexpr std::size_t MAXIMUM_COVERAGE_DIALOG_ENTRIES = 100U ;
// 外部device property一項目をdialogへ表示する文字数上限。
constexpr std::size_t MAXIMUM_COVERAGE_LABEL_CHARACTERS = 128U ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief logical pixel を現在 DPI の physical pixel へ変換する。
 *
 * @param[in] value 96 DPI 基準の値。
 * @param[in] dpi 対象 Window DPI。
 * @return scale 済み pixel 値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] int	  scaleForDpi( const int value, const UINT dpi) noexcept
{
	return MulDiv( value, static_cast<int>( dpi), USER_DEFAULT_SCREEN_DPI) ;
}

//------------------------------------------------------------------------------
/**
 * @brief byte 数を B/KB/MB/GB の表示文字列へ変換する。
 *
 * @param[in] bytes 表示する最大 download byte 数。
 * @param[in] unknownText 0 または変換失敗時に使用する文字列。
 * @return locale 非依存の簡潔な size 表示。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatByteSize( const std::uint64_t	  bytes,
										  const std::wstring_view unknownText)
{
	// sizeの未確定値を0 byteの確定表示にせず、不明を示すresource文字列へ置き換える。
	if( bytes == 0) {
		return std::wstring( unknownText) ;
	}

	constexpr double			UNIT_SCALE = 1024.0 ;								// 隣接するbinary size単位間の倍率。
	constexpr std::wstring_view UNITS[]	   = {L"B", L"KB", L"MB", L"GB", L"TB"} ;	// 単位表。
	double						value = static_cast<double>( bytes) ;				// 選択単位へscale中のsize値。
	std::size_t					unitIndex{} ;										// kUnits内で現在使用する単位index。

	// 最大 TB 表示まで有限回 scale し、過大な単位 index を生成しない。
	while( value >= UNIT_SCALE && unitIndex + 1 < std::size( UNITS)) {
		value /= UNIT_SCALE ;
		++unitIndex ;
	}

	std::wostringstream output ;	// Locale非依存のsize表示を構築するstream。
	// byte単位では整数をそのまま表示し、不要な小数丸めで実数値を変えない。
	if( unitIndex == 0) {
		output << bytes << L' ' << UNITS[unitIndex] ;
	} else {
		output << std::fixed << std::setprecision( 1) << value << L' ' << UNITS[unitIndex] ;
	}

	return output.str() ;
}

//------------------------------------------------------------------------------
/**
 * @brief COM operation result を診断用の固定名称へ変換する。
 *
 * @param[in] outcome 変換対象の core 分類。
 * @return locale に依存しない診断名称。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring_view outcomeName( const OutcomeCode outcome) noexcept
{
	// 終了区分を固定の診断名へ変換し、未知の値を成功と表示しない。
	switch( outcome) {
		// 未開始の結果を固定の診断名称で表示する。
		case OutcomeCode::NOT_STARTED:
			return L"NotStarted" ;
		// 実行中の結果を完了状態と区別して表示する。
		case OutcomeCode::IN_PROGRESS:
			return L"InProgress" ;
		// 全成功を固定の診断名称で表示する。
		case OutcomeCode::SUCCESS:
			return L"Succeeded" ;
		// 一部 error を伴う成功を全成功と区別して表示する。
		case OutcomeCode::SUCCEEDED_WITH_ERRORS:
			return L"SucceededWithErrors" ;
		// 実行失敗を固定の診断名称で表示する。
		case OutcomeCode::FAILURE:
			return L"Failed" ;
		// 中止された結果を失敗や未開始と区別して表示する。
		case OutcomeCode::ABORTED:
			return L"Aborted" ;
		// 未知の結果 code を既知の成功・失敗へ推測変換しない。
		default:
			return L"Unknown" ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief native error がない operation failureを含めた診断文字列を作成する。
 *
 * @param[in] error WUA/Win32 error code。
 * @param[in] outcome operation result 分類。
 * @return result code を失わない表示文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatOperationError( const NativeError error, const OutcomeCode outcome)
{
	// native診断がある場合はそれを優先し、一般的なoperation失敗文で原因を隠さない。
	if( error != 0) {
		return formatNativeError( error) ;
	}

	return std::wstring( L"Windows Update result: ") + std::wstring( outcomeName( outcome)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 外部 metadata の制御文字を空白へ置換して一行表示にする。
 *
 * @param[in] text ProviderまたはWindows APIが返した表示文字列。
 * @return dialog と TreeTable で改行などに解釈されない文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring makeSingleLine( const std::wstring_view text)
{
	std::wstring result( text) ;	// 制御文字を置換するmutable表示文字列。
	// C0 制御文字と DEL を空白にし、確認画面の項目境界を metadata が変更できないようにする。
	std::replace_if(
		result.begin(), result.end(),
		[]( const wchar_t character) { return character < L' ' || character == 0x7F ; }, L' ') ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief TreeTableの表示文字列を数字部分を考慮して比較する。
 *
 * Windowsの利用者localeとSORT_DIGITSASNUMBERSを使用し、versionやdevice名の数字部分を文字列の位取りとして誤比較しない。API制限を超える入力は
 * ordinal比較へ縮退する。
 *
 * @param[in] left 左側の表示文字列。
 * @param[in] right 右側の表示文字列。
 * @return leftが先なら負、等しければ0、rightが先なら正の値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] int compareTreeText( const std::wstring_view left,
								  const std::wstring_view right) noexcept
{
	// 同一文字列には比較APIを呼ばず、等価な行の並びを不要に変えない。
	if( left == right) {
		return 0 ;
	}

	constexpr DWORD COMPARISON_FLAGS =
		NORM_IGNORECASE | SORT_DIGITSASNUMBERS ;	// 表示値のnatural sort flag。
	constexpr std::size_t MAXIMUM_API_CHARACTERS =
		// CompareStringExの上限。
		static_cast<std::size_t>( (std::numeric_limits<int>::max)()) ;
	// 文字数をWindows APIの引数型へ安全に渡せる場合だけ、localeを考慮した比較を行う。
	if( left.size() <= MAXIMUM_API_CHARACTERS && right.size() <= MAXIMUM_API_CHARACTERS) {
		// CompareStringExが返すCSTR_LESS_THAN、CSTR_EQUAL、CSTR_GREATER_THAN。
		const int comparison = CompareStringEx(
			LOCALE_NAME_USER_DEFAULT, COMPARISON_FLAGS, left.data(), static_cast<int>( left.size()),
			right.data(), static_cast<int>( right.size()), nullptr, nullptr, 0) ;
		// Windowsが比較結果を返した場合だけ採用し、API失敗を大小関係へ変換しない。
		if( comparison != 0) {
			return comparison - CSTR_EQUAL ;
		}
	}

	return left.compare( right) < 0 ? -1 : 1 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
MainWindow::~MainWindow()
{
	// このWindow用に作ったstate画像だけを解放します。
	if( checkboxImages_) {
		ImageList_Destroy( checkboxImages_) ;
	}

	// 作成したmessage用fontだけを破棄し、未作成のGDI objectを解放しない。
	if( messageFont_ != nullptr) {
		DeleteObject( messageFont_) ;
	}

	// TreeTable専用fontの所有を終了し、未作成のhandleをGDIへ渡さない。
	if( treeFont_ != nullptr) {
		DeleteObject( treeFont_) ;
	}

	// SetupAPIが作成したclass image listだけを、対応する解放APIで破棄する。
	if( deviceClassImages_.ImageList != nullptr) {
		SetupDiDestroyClassImageList( &deviceClassImages_) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::create( const HINSTANCE instance)
{
	instance_ = instance ;

	// Window classが共有する通常サイズのapplication icon。解放はsystemが行う。
	HICON applicationIcon = static_cast<HICON>(
		LoadImageW( instance_, MAKEINTRESOURCEW( IDI_DRIVERCRATE), IMAGE_ICON,
				   GetSystemMetrics( SM_CXICON), GetSystemMetrics( SM_CYICON), LR_SHARED)) ;
	// 専用iconが読めなくても本来の操作を利用できるよう、Windows標準iconへ縮退する。
	if( applicationIcon == nullptr) {
		// Resource破損時もmain機能を利用できるようWindows標準iconへfallbackする。
		applicationIcon = LoadIconW( nullptr, IDI_APPLICATION) ;
	}

	// Title bar等へ表示する小サイズのapplication icon。解放はsystemが行う。
	HICON applicationSmallIcon = static_cast<HICON>(
		LoadImageW( instance_, MAKEINTRESOURCEW( IDI_DRIVERCRATE), IMAGE_ICON,
				   GetSystemMetrics( SM_CXSMICON), GetSystemMetrics( SM_CYSMICON), LR_SHARED)) ;
	// 小iconだけが欠ける場合は通常iconを再利用し、Window作成全体を失敗にしない。
	if( applicationSmallIcon == nullptr) {
		// 小サイズだけ取得できない場合は通常サイズを縮小表示させる。
		applicationSmallIcon = applicationIcon ;
	}

	WNDCLASSEXW windowClass{} ;	// RegisterClassExへ渡すWindow class定義。
	windowClass.cbSize		  = sizeof( windowClass) ;
	windowClass.style		  = CS_HREDRAW | CS_VREDRAW ;
	windowClass.lpfnWndProc	  = windowProc ;
	windowClass.hInstance	  = instance_ ;
	windowClass.hIcon		  = applicationIcon ;
	windowClass.hCursor		  = LoadCursorW( nullptr, IDC_ARROW) ;
	windowClass.hbrBackground = reinterpret_cast<HBRUSH>( COLOR_WINDOW + 1) ;
	windowClass.lpszClassName = WINDOW_CLASS_NAME ;
	windowClass.hIconSm		  = applicationSmallIcon ;

	// 既登録の場合を除くWindow class登録失敗では、未登録classによるWindow作成を続けない。
	if( RegisterClassExW( &windowClass) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
		return false ;
	}

	const std::wstring title = loadString( IDS_APP_TITLE) ;	// Versionを含むtop-level Window title。
	window_ =
		CreateWindowExW( 0, WINDOW_CLASS_NAME, title.c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
						CW_USEDEFAULT, CW_USEDEFAULT, DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT,
						nullptr, nullptr, instance_, this) ;
	return window_ != nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
int MainWindow::run( const int showCommand)
{
	ShowWindow( window_, showCommand) ;
	UpdateWindow( window_) ;

	MSG message{} ;	// GetMessageWが格納する一件のUI message。
	// GetMessage が 0 または error を返すまで、UI thread の全 top-level message を処理する。
	while( true) {
		const BOOL getResult = GetMessageW( &message, nullptr, 0, 0) ;	// 受信状態またはerror。
		// 終了通知とmessage取得失敗を区別し、正常終了codeまたは失敗codeでloopを終える。
		if( getResult <= 0) {
			return getResult == 0 ? static_cast<int>( message.wParam) : 1 ;
		}

		TranslateMessage( &message) ;
		DispatchMessageW( &message) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
LRESULT CALLBACK MainWindow::windowProc( const HWND window, const UINT message,
										const WPARAM wordParameter,
										const LPARAM longParameter) noexcept
{
	MainWindow *self = nullptr ;	// HWNDへ関連付けた非所有MainWindow pointer。
	// Window生成時にだけinstanceを関連付け、以後のmessageを同じUI状態へ転送する。
	if( message == WM_NCCREATE) {
		// CREATESTRUCT の lifetime は callback 中だけなので、所有しない pointer を即時に取り出す。
		// WM_NCCREATE callback中だけ有効なWindow作成metadata。
		const auto *create = reinterpret_cast<const CREATESTRUCTW *>( longParameter) ;
		self			   = static_cast<MainWindow *>( create->lpCreateParams) ;
		self->window_	   = window ;
		SetWindowLongPtrW( window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>( self)) ;
	} else {
		// GWLP_USERDATA には WM_NCCREATE で登録した同じ MainWindow pointer だけを保存する。
		self = reinterpret_cast<MainWindow *>( GetWindowLongPtrW( window, GWLP_USERDATA)) ;
	}

	// instance関連付け前のmessageは標準処理へ渡し、未作成のUI状態を参照しない。
	if( self == nullptr) {
		return DefWindowProcW( window, message, wordParameter, longParameter) ;
	}

	try {
		return self->handleMessage( message, wordParameter, longParameter) ;
	} catch( ...) {
		// Win32 callback boundary から C++ exception を漏らさず、標準処理へ安全に縮退する。
		return DefWindowProcW( window, message, wordParameter, longParameter) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
LRESULT CALLBACK MainWindow::recommendedFilterProc( const HWND window, const UINT message,
												   const WPARAM	   wordParameter,
												   const LPARAM	   longParameter,
												   const UINT_PTR  subclassId,
												   const DWORD_PTR referenceData) noexcept
{
	// SetWindowSubclassへ登録したMainWindow pointer以外を解釈しない。
	const auto *const self = reinterpret_cast<const MainWindow *>( referenceData) ;
	// 描画通知だけを独自描画へ振り分け、標準Buttonの操作状態は維持する。
	switch( message) {
		case WM_ERASEBKGND:
			// WM_PAINTでcontrol全体を描くため、Button既定の灰色背景を抑止する。
			return 1 ;

		// 有効状態変更の標準処理後に checkbox の独自描画を更新する。
		case WM_ENABLE: {
			// Button既定処理が有効状態変更時に直接描く背景を完了後の独自描画で置き換える。
			const LRESULT result = DefSubclassProc( window, message, wordParameter,
												   longParameter) ;	// 標準状態変更結果。
			RedrawWindow( window, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW) ;
			return result ;
		}

		// 通常の再描画要求では更新領域へ checkbox を描画する。
		case WM_PAINT: {
			PAINTSTRUCT paint{} ;										// BeginPaintとEndPaintの間だけ有効な描画情報。
			const HDC	deviceContext = BeginPaint( window, &paint) ;	// 更新領域用device context。
			// 有効なinstanceと描画contextがそろった場合だけ、checkboxの独自描画を行う。
			if( self != nullptr && deviceContext != nullptr) {
				self->drawRecommendedFilter( deviceContext) ;
			}

			EndPaint( window, &paint) ;
			return 0 ;
		}

		// 外部への client 描画要求には渡された描画先を使用する。
		case WM_PRINTCLIENT: {
			// WPARAMはPrintWindow等の呼出し中だけ有効な描画先device context。
			const HDC deviceContext = reinterpret_cast<HDC>( wordParameter) ;
			// 外部描画要求のcontextが有効なら独自描画で完了し、背景付きの標準描画を重ねない。
			if( self != nullptr && deviceContext != nullptr) {
				self->drawRecommendedFilter( deviceContext) ;
				return 0 ;
			}

			break ;
		}

		// Control の最終破棄時に subclass 登録を解除する。
		case WM_NCDESTROY:
			RemoveWindowSubclass( window, recommendedFilterProc, subclassId) ;
			break ;

		// 専用処理を持たない message は標準 subclass 処理へ渡す。
		default:
			break ;
	}

	return DefSubclassProc( window, message, wordParameter, longParameter) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::drawRecommendedFilter( const HDC deviceContext) const noexcept
{
	RECT bounds{} ;	// Checkbox client領域のphysical pixel矩形。
	// controlや描画範囲を取得できない場合は、未確定の座標で描画しない。
	if( recommendedOnlyCheckbox_ == nullptr ||
	   GetClientRect( recommendedOnlyCheckbox_, &bounds) == FALSE) {
		return ;
	}

	FillRect( deviceContext, &bounds, GetSysColorBrush( COLOR_WINDOW)) ;
	const UINT dpi			= GetDpiForWindow( recommendedOnlyCheckbox_) ;		// Glyph配置へ使用するDPI。
	const int  glyphSize	= scaleForDpi( 13, dpi) ;							// 標準check記号の一辺（physical pixel）。
	const int  leftPadding	= scaleForDpi( 2, dpi) ;							// Control左端からcheck記号までの余白。
	const int  labelGap		= scaleForDpi( 5, dpi) ;							// Check記号とlabel間の余白。
	const int  clientHeight = bounds.bottom - bounds.top ;						// Control client高さ。
	const int  glyphTop		= std::max( 0, (clientHeight - glyphSize) / 2) ;	// Check記号上端。
	RECT	   glyph{leftPadding, glyphTop, leftPadding + glyphSize,
				 glyphTop + glyphSize} ;	// DrawFrameControlへ渡すcheck記号矩形。

	const bool enabled = IsWindowEnabled( recommendedOnlyCheckbox_) != FALSE ;	// 操作可能状態。
	const bool checked =
		// Check状態。
		SendMessageW( recommendedOnlyCheckbox_, BM_GETCHECK, 0, 0) == BST_CHECKED ;
	const LRESULT buttonState =
		// 押下中を含むButton状態。
		SendMessageW( recommendedOnlyCheckbox_, BM_GETSTATE, 0, 0) ;
	UINT glyphState = DFCS_BUTTONCHECK ;	// DrawFrameControlへ渡すcheck記号状態。
	// 選択中であることをcheck記号にも反映し、色だけに状態を依存させない。
	if( checked) {
		glyphState |= DFCS_CHECKED ;
	}

	// 操作不可の状態をglyphへ反映し、利用者が押せるcontrolと誤認しないようにする。
	if( !enabled) {
		glyphState |= DFCS_INACTIVE ;
	}

	// 標準Buttonの押下状態を反映し、独自描画でも操作時の応答を保つ。
	if( (buttonState & BST_PUSHED) != 0) {
		glyphState |= DFCS_PUSHED ;
	}

	DrawFrameControl( deviceContext, &glyph, DFC_BUTTON, glyphState) ;

	// Controlが保持するresource labelを読み取る固定長buffer。
	std::array<wchar_t, MAXIMUM_FILTER_LABEL_CHARACTERS> label{} ;
	const int	labelLength = GetWindowTextW( recommendedOnlyCheckbox_, label.data(),
											 // 終端を除く文字数。
											 static_cast<int>( label.size())) ;
	RECT		labelBounds{glyph.right + labelGap, bounds.top, bounds.right,
						bounds.bottom} ;	// Label描画領域。
	const HFONT controlFont = reinterpret_cast<HFONT>(
		// 非所有control font。
		SendMessageW( recommendedOnlyCheckbox_, WM_GETFONT, 0, 0)) ;
	HGDIOBJ previousFont{} ;	// 描画後にdevice contextへ戻すfont。
	// controlに設定されたfontがある場合だけ選択し、標準contextのfontを不用意に外さない。
	if( controlFont != nullptr) {
		previousFont = SelectObject( deviceContext, controlFont) ;
	}

	const int previousBackgroundMode =
		// 描画前のbackground mode。
		SetBkMode( deviceContext, TRANSPARENT) ;
	const COLORREF previousTextColor =
		SetTextColor( deviceContext,
					 // 描画前のtext color。
					 GetSysColor( enabled ? COLOR_WINDOWTEXT : COLOR_GRAYTEXT)) ;
	const LRESULT uiState =
		// Keyboard cue状態。
		SendMessageW( recommendedOnlyCheckbox_, WM_QUERYUISTATE, 0, 0) ;
	UINT textFormat = DT_LEFT | DT_VCENTER | DT_SINGLELINE ;	// Labelの基本描画format。
	// WindowsのUI状態に合わせてaccess keyの下線を隠し、標準controlと表示をそろえる。
	if( (uiState & UISF_HIDEACCEL) != 0) {
		textFormat |= DT_HIDEPREFIX ;
	}

	DrawTextW( deviceContext, label.data(), labelLength, &labelBounds, textFormat) ;

	// 有効なfocusと表示可能なlabelがある場合だけ、keyboard操作のfocus枠を描く。
	if( enabled && GetFocus() == recommendedOnlyCheckbox_ && (uiState & UISF_HIDEFOCUS) == 0 &&
	   labelLength > 0) {
		SIZE labelSize{} ;	// Focus枠をlabelの実寸へ限定するpixel size。
		// labelの実寸を測定できた場合だけ枠を作り、未確定sizeで描画しない。
		if( GetTextExtentPoint32W( deviceContext, label.data(), labelLength, &labelSize) != FALSE) {
			const int focusTop =
				// Focus枠上端。
				std::max( 0, (clientHeight - static_cast<int>( labelSize.cy)) / 2) ;
			RECT focusBounds{labelBounds.left - 1, focusTop - 1,
							 labelBounds.left + labelSize.cx + 1,
							 focusTop + labelSize.cy + 1} ;	// Labelだけを囲むfocus矩形。
			DrawFocusRect( deviceContext, &focusBounds) ;
		}
	}

	SetTextColor( deviceContext, previousTextColor) ;
	SetBkMode( deviceContext, previousBackgroundMode) ;
	// 一時的に変更したfontを戻し、借用した描画contextの状態を呼出し元へ残さない。
	if( previousFont != nullptr) {
		SelectObject( deviceContext, previousFont) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::drawStatusBand( const DRAWITEMSTRUCT &drawItem) const noexcept
{
	// status controlや描画contextがない通知を無視し、破棄中のUIを描画しない。
	if( status_ == nullptr || drawItem.hDC == nullptr) {
		return ;
	}

	RECT bounds = drawItem.rcItem ;	// Status control全体の描画矩形。
	FillRect( drawItem.hDC, &bounds, GetSysColorBrush( COLOR_WINDOW)) ;

	RECT progressBounds = bounds ;	// Border内へ完了率を塗るprogress矩形。
	// 処理中だけ確定率の背景を描き、通常messageを進捗表示と混同させない。
	if( statusBusy_) {
		FrameRect( drawItem.hDC, &progressBounds, GetSysColorBrush( COLOR_3DSHADOW)) ;
		InflateRect( &progressBounds, -1, -1) ;
		const LONG progressWidth =	// 極小Windowでも負値にしない塗布可能幅。
			std::max<LONG>( 0, progressBounds.right - progressBounds.left) ;
		progressBounds.right =
			progressBounds.left + MulDiv( progressWidth, static_cast<int>( statusPercentage_), 100) ;
		FillRect( drawItem.hDC, &progressBounds, GetSysColorBrush( COLOR_HIGHLIGHT)) ;
	}

	std::array<wchar_t, MAXIMUM_STATUS_CHARACTERS> text{} ;	// Controlが保持するmessage受信領域。
	const int									   textLength =
		// 終端を除く文字数。
		GetWindowTextW( status_, text.data(), static_cast<int>( text.size())) ;
	// 表示文字列を取得できない場合は、背景だけを維持して文字描画を終了する。
	if( textLength <= 0) {
		return ;
	}

	const UINT dpi		  = GetDpiForWindow( status_) ;	// Text左右余白へ使用する現在DPI。
	const int  padding	  = scaleForDpi( 6, dpi) ;		// Status帯端からtextまでの余白。
	RECT	   textBounds = bounds ;					// 全体で共通するtext layout矩形。
	textBounds.left += padding ;
	textBounds.right = std::max( textBounds.left, textBounds.right - padding) ;
	// 一行中央表示と右端省略を行うtext描画format。
	const UINT	textFormat = DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX ;
	const HFONT font	   = reinterpret_cast<HFONT>(
		  // Status controlが参照する非所有font。
		  SendMessageW( status_, WM_GETFONT, 0, 0)) ;
	const int savedContext = SaveDC( drawItem.hDC) ;	// 全描画前のdevice context状態。
	// 描画状態を保存できない場合は変更せず、呼出し元のcontext状態を壊さない。
	if( savedContext == 0) {
		return ;
	}

	// status用fontが設定されている場合だけ描画へ反映し、未作成handleを使用しない。
	if( font != nullptr) {
		SelectObject( drawItem.hDC, font) ;
	}

	SetBkMode( drawItem.hDC, TRANSPARENT) ;

	// 通常状態は単色messageとして描き、保存したcontextを戻して進捗用の処理を終了する。
	if( !statusBusy_) {
		SetTextColor( drawItem.hDC, GetSysColor( COLOR_WINDOWTEXT)) ;
		DrawTextW( drawItem.hDC, text.data(), textLength, &textBounds, textFormat) ;
		RestoreDC( drawItem.hDC, savedContext) ;
		return ;
	}

	RECT unfilledClip = bounds ;	// 未完了領域だけに通常色textを描くclip矩形。
	unfilledClip.left = progressBounds.right ;
	IntersectClipRect( drawItem.hDC, unfilledClip.left, unfilledClip.top, unfilledClip.right,
					  unfilledClip.bottom) ;
	SetTextColor( drawItem.hDC, GetSysColor( COLOR_WINDOWTEXT)) ;
	DrawTextW( drawItem.hDC, text.data(), textLength, &textBounds, textFormat) ;
	RestoreDC( drawItem.hDC, savedContext) ;

	const int filledContext = SaveDC( drawItem.hDC) ;	// 完了領域描画前のcontext状態。
	// 塗りつぶし領域の描画状態を保存できなければ、clipや文字色を変更しない。
	if( filledContext == 0) {
		return ;
	}

	// 進捗背景上でも通常messageと同じfontを使用し、二重描画の位置をそろえる。
	if( font != nullptr) {
		SelectObject( drawItem.hDC, font) ;
	}

	SetBkMode( drawItem.hDC, TRANSPARENT) ;
	IntersectClipRect( drawItem.hDC, bounds.left, bounds.top, progressBounds.right, bounds.bottom) ;
	SetTextColor( drawItem.hDC, GetSysColor( COLOR_HIGHLIGHTTEXT)) ;
	DrawTextW( drawItem.hDC, text.data(), textLength, &textBounds, textFormat) ;
	RestoreDC( drawItem.hDC, filledContext) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
int CALLBACK MainWindow::compareTreeItems( const LPARAM leftParameter, const LPARAM rightParameter,
										  const LPARAM contextParameter) noexcept
{
	// Callbackは同期sortの間だけ生存する非所有contextを受ける。
	const auto *context = reinterpret_cast<const TreeSortContext *>( contextParameter) ;
	// 不正な比較要求を表示順の根拠へ使用しない。
	if( context == nullptr || context->window == nullptr ||
	   context->columnIndex >= TREE_COLUMN_COUNT) {
		return 0 ;
	}

	const auto *left  = context->window->treeRowFromParameter( leftParameter) ;		// 左の表示行。
	const auto *right = context->window->treeRowFromParameter( rightParameter) ;	// 右の表示行。
	// 両行を解決できなければ配列を推測して参照しない。
	if( left == nullptr || right == nullptr) {
		return 0 ;
	}

	// 分類はdeviceのsort方向から独立させ、不明を末尾へ保持する。
	if( left->kind == TreeRowKind::DEVICE_CLASS && right->kind == TreeRowKind::DEVICE_CLASS) {
		// 名前が同じでも分類未解決を既知の分類へ混ぜない。
		if( left->unknownClass != right->unknownClass) {
			return left->unknownClass ? 1 : -1 ;
		}

		return compareTreeText( left->className, right->className) ;
	}

	const std::array<std::wstring_view, TREE_COLUMN_COUNT> leftValues{
		left->primaryText, left->currentVersion, left->candidateVersion} ;	// 左の三列。
	const std::array<std::wstring_view, TREE_COLUMN_COUNT> rightValues{
		right->primaryText, right->currentVersion, right->candidateVersion} ;	// 右の三列。
	const int comparison = compareTreeText( leftValues[context->columnIndex],
										   rightValues[context->columnIndex]) ;	// 表示列の比較結果。
	// 同値の補助比較は常に名前順とし、方向変更でもidentityを失わない。
	if( comparison == 0) {
		return compareTreeText( left->primaryText, right->primaryText) ;
	}

	return context->ascending ? comparison : -comparison ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
LRESULT MainWindow::handleMessage( const UINT message, const WPARAM wordParameter,
								  const LPARAM longParameter)
{
	// Windowの生成・描画・利用者操作・worker通知をUI threadの対応処理へ振り分ける。
	switch( message) {
		// Window 作成時に control を初期化し、失敗は作成拒否として返す。
		case WM_CREATE:
			return onCreate() ? 0 : -1 ;

		// Window size の変更に合わせて control を再配置する。
		case WM_SIZE:
			layoutControls() ;
			return 0 ;

		// DPI に応じた最小 Window size を Windows へ返す。
		case WM_GETMINMAXINFO: {
			// LPARAM は Win32 が callback 中だけ保証する MINMAXINFO buffer である。
			auto *minimums =
				reinterpret_cast<MINMAXINFO *>( longParameter) ;		// 書込み先の非所有buffer。
			const UINT dpi			   = GetDpiForWindow( window_) ;	// 現在Windowへ適用されるDPI値。
			minimums->ptMinTrackSize.x = scaleForDpi( MINIMUM_WINDOW_WIDTH, dpi) ;
			minimums->ptMinTrackSize.y = scaleForDpi( MINIMUM_WINDOW_HEIGHT, dpi) ;
			return 0 ;
		}

		// DPI 変更時に font と推奨 Window 位置を更新する。
		case WM_DPICHANGED: {
			// WPARAM上位wordは新しいvertical DPIであり、fontのpixel高さへ使用する。
			const UINT newDpi = HIWORD( wordParameter) ;	// 移動先monitorのvertical DPI。
			static_cast<void>( updateMessageFont( newDpi)) ;
			static_cast<void>( updateTreeFont( newDpi)) ;
			// LPARAM の推奨 RECT は callback 中だけ参照し、直ちに Window 位置へ反映する。
			// 新DPIに対してWindowsが推奨する非所有Window矩形。
			const auto *suggested = reinterpret_cast<const RECT *>( longParameter) ;
			SetWindowPos( window_, nullptr, suggested->left, suggested->top,
						 suggested->right - suggested->left, suggested->bottom - suggested->top,
						 SWP_NOACTIVATE | SWP_NOZORDER) ;
			return 0 ;
		}

		case WM_COMMAND:
			// Modal取得確認中は外部からのcommand再入も拒否する。
			if( preparationReviewOpen_ || metadataReviewOpen_) {
				return 0 ;
			}

			// Buttonのclick通知だけを操作開始へ結び付け、その他のcontrol通知で実行しない。
			if( HIWORD( wordParameter) == BN_CLICKED) {
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
				// 内部fixtureの専用要求は通常scanの同意へ変換しない。
				if( LOWORD( wordParameter) == IDC_METADATA_SEARCH) {
					handleMetadataSearchCommand() ;
					return 0 ;
				}
#endif

				// 明示された検索操作を開始し、このcommandを標準Window処理へ重ねて渡さない。
				if( LOWORD( wordParameter) == IDC_SCAN) {
					handleScanCommand() ;
					return 0 ;
				}

#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
				// 内部fixtureだけが検査用取得を独立して要求できる。
				if( LOWORD( wordParameter) == IDC_PREPARATION) {
					handlePreparationCommand() ;
					return 0 ;
				}
#endif

				// 利用者が導入Buttonを押した場合だけ、選択対象の最終確認へ進める。
				if( LOWORD( wordParameter) == IDC_INSTALL) {
					beginInstall() ;
					return 0 ;
				}

				// 任意全文閲覧は選択・取得・同意を変更しません。
				if( LOWORD( wordParameter) == IDC_INSTALL_TERMS) {
					showInstallTerms() ;
					return 0 ;
				}

				// 推奨通常更新だけを一括選択する操作へ渡し、過去版を自動選択しない。
				if( LOWORD( wordParameter) == IDC_SELECT_ALL_RECOMMENDED) {
					selectAllRecommendedUpdates() ;
					return 0 ;
				}

				// 選択解除の要求を候補集合へ反映し、検索や取得を新しく開始しない。
				if( LOWORD( wordParameter) == IDC_CLEAR_SELECTION) {
					clearCandidateSelection() ;
					return 0 ;
				}

				// 表示filterの変更だけを処理し、候補の導入操作と混同しない。
				if( LOWORD( wordParameter) == IDC_RECOMMENDED_ONLY) {
					handleRecommendedFilterChange() ;
					return 0 ;
				}

				// 取得元の設定menuを表示し、選択変更と実際の検索開始を分離する。
				if( LOWORD( wordParameter) == IDC_PROVIDER_SOURCES) {
					showProviderSourcesMenu() ;
					return 0 ;
				}

				// coverageの表示だけを行い、同processからのcommandでも導入状態を変更しない。
				if( LOWORD( wordParameter) == LOCAL_COVERAGE_MENU_COMMAND) {
					// Read-only UI smokeを含む同process commandも表示以外の状態変更を行わない。
					showLocalCoverageDialog() ;
					return 0 ;
				}

				// 取得計画と独立した前回通信結果の閲覧だけを行います。
				if( LOWORD( wordParameter) == IDM_INDEX_REFRESH_DETAILS) {
					showIndexRefreshDetails() ;
					return 0 ;
				}
			}

			break ;

		// Status 帯の owner draw 通知を専用描画へ渡す。
		case WM_DRAWITEM: {
			// LPARAMは親Windowによるowner draw中だけ有効な描画情報である。
			const auto *drawItem = reinterpret_cast<const DRAWITEMSTRUCT *>( longParameter) ;
			// status control向けの有効な描画通知だけを、全幅message帯の描画へ渡す。
			if( drawItem != nullptr && drawItem->CtlID == IDC_STATUS) {
				drawStatusBand( *drawItem) ;
				return TRUE ;
			}

			break ;
		}

		// 標準 control の描画・操作通知を送信元と通知種類に従って処理する。
		case WM_NOTIFY: {
			// NMHDR は SendMessage の同期 callback 中だけ有効であり、member へ保存しない。
			// WM_NOTIFY送信元を示すcallback中だけのheader。
			const auto *notification = reinterpret_cast<const NMHDR *>( longParameter) ;
			// Deviceの詳細をEnter・double clickへ割り当て、分類の展開は標準動作に残す。
			if( notification->hwndFrom == updateTree_ &&
			   (notification->code == NM_DBLCLK || notification->code == NM_RETURN) &&
			   showSelectedCandidateDetails()) {
				return TRUE ;
			}

			// 候補TreeViewからの描画通知にだけ応答し、別controlのbufferを誤解釈しない。
			if( notification->hwndFrom == updateTree_ && notification->code == NM_CUSTOMDRAW) {
				// TreeViewが現在描画中のitemとdevice contextを示す非所有通知buffer。
				const auto *customDraw = reinterpret_cast<const NMTVCUSTOMDRAW *>( longParameter) ;
				// 各行の描画通知を要求し、標準TreeViewの描画段階と独自列の描画を連携させる。
				if( customDraw->nmcd.dwDrawStage == CDDS_PREPAINT) {
					return CDRF_NOTIFYITEMDRAW ;
				}

				// 標準の行描画が済んだ後に追加列を描けるよう、後処理通知を要求する。
				if( customDraw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
					return CDRF_NOTIFYPOSTPAINT ;
				}

				// 標準の行背景と選択表示を保ち、その後にTreeTableの列を重ねて描く。
				if( customDraw->nmcd.dwDrawStage == CDDS_ITEMPOSTPAINT) {
					drawTreeRow( *customDraw) ;
					return CDRF_DODEFAULT ;
				}
			}

			// 列幅の変更後に全行を再描画し、clip範囲と罫線を新しい幅へそろえる。
			if( notification->hwndFrom == treeHeader_ &&
			   (notification->code == HDN_ITEMCHANGEDW || notification->code == HDN_ENDTRACKW)) {
				// 利用者がcolumn幅を変更した直後に全行のclip位置とgridを再描画する。
				InvalidateRect( updateTree_, nullptr, TRUE) ;
				return 0 ;
			}

			// headerの列clickを列ソートへ渡し、TreeView本体の通知と区別する。
			if( notification->hwndFrom == treeHeader_ && notification->code == HDN_ITEMCLICKW) {
				// Header controlがclickされたcolumnを示すcallback中だけの通知buffer。
				const auto *headerClick = reinterpret_cast<const NMHEADERW *>( longParameter) ;
				// 左Buttonのclickだけを列ソートの要求として扱い、右clickで並び順を変えない。
				if( headerClick->iButton == 0) {
					handleHeaderClick( headerClick->iItem) ;
				}

				return 0 ;
			}

			// readonly枠の短い固定説明を標準tooltipへ渡します。
			if( notification->hwndFrom == updateTree_ && notification->code == TVN_GETINFOTIPW) {
				auto *tip = reinterpret_cast<NMTVGETINFOTIPW *>(
					longParameter) ;									// 通知中だけのWindows bufferです。
				const auto *row = treeRowFromParameter( tip->lParam) ;	// 同Windowの行だけです。
				// readonlyの元枠にだけ固定説明を付けます。
				if( row && row->readonlyCheckbox && tip->pszText && tip->cchTextMax > 0 &&
				   tip->cchTextMax <= 2048) {
					const auto text =
						// 元選択の再実行を案内しません。
						loadString( IDS_RETAINED_CHECKBOX_TIP) ;
					wcsncpy_s( tip->pszText, static_cast<std::size_t>( tip->cchTextMax), text.c_str(),
							  _TRUNCATE) ;
				}

				return 0 ;
			}

			// 候補TreeViewの状態変更だけを選択同期へ渡し、他controlの状態を参照しない。
			if( notification->hwndFrom == updateTree_ && notification->code == TVN_ITEMCHANGEDW) {
				// TreeView itemの新旧状態を保持する非所有通知buffer。
				const auto *change = reinterpret_cast<const NMTVITEMCHANGE *>( longParameter) ;
				// 内部のcheck同期を再入力とせず、利用者によるcheck状態の変化だけを処理する。
				if( !updatingTreeChecks_ && (change->uChanged & TVIF_STATE) != 0 &&
				   (change->uStateOld & TVIS_STATEIMAGEMASK) !=
					   (change->uStateNew & TVIS_STATEIMAGEMASK)) {
					// 1がunchecked、2がcheckedを示すstate image index。
					const UINT stateImage = (change->uStateNew & TVIS_STATEIMAGEMASK) >> 12U ;
					handleTreeCheckChange( change->hItem, stateImage == 2U) ;
				}

				updateCommandState() ;
				return 0 ;
			}

			break ;
		}

		// Worker 通知を受けたら所有 queue から結果を取り出す。
		case WORKER_NOTIFICATION_MESSAGE:
			processWorkerEvents() ;
			return 0 ;

		// Close 要求は安全な worker 終了を伴う終了手順へ渡す。
		case WM_CLOSE:
			requestClose() ;
			return 0 ;

		// Window の破棄完了時に UI message loop の終了を通知する。
		case WM_DESTROY:
			PostQuitMessage( 0) ;
			return 0 ;

		// 専用処理のない message は既定 Window 処理へ渡す。
		default:
			break ;
	}

	return DefWindowProcW( window_, message, wordParameter, longParameter) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::onCreate()
{
	uiFont_ = static_cast<HFONT>( GetStockObject( DEFAULT_GUI_FONT)) ;

	treeHeader_ = CreateWindowExW(
		0, WC_HEADERW, L"", WS_CHILD | WS_VISIBLE | HDS_HORZ | HDS_FULLDRAG | HDS_BUTTONS, 0, 0, 0,
		0, window_, reinterpret_cast<HMENU>( IDC_TREE_HEADER), instance_, nullptr) ;
	updateTree_ = CreateWindowExW(
		WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT |
			TVS_SHOWSELALWAYS | TVS_CHECKBOXES | TVS_FULLROWSELECT | TVS_INFOTIP,
		0, 0, 0, 0, window_, reinterpret_cast<HMENU>( IDC_UPDATE_TREE), instance_, nullptr) ;
	scanButton_	   = CreateWindowExW( 0, WC_BUTTONW, loadString( IDS_SCAN_BUTTON).c_str(),
									 WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 0, 0, 0, 0,
									 window_, reinterpret_cast<HMENU>( IDC_SCAN), instance_, nullptr) ;
	installButton_ = CreateWindowExW( 0, WC_BUTTONW, loadString( IDS_INSTALL_BUTTON).c_str(),
									 WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, window_,
									 reinterpret_cast<HMENU>( IDC_INSTALL), instance_, nullptr) ;
	installTermsNote_ =
		CreateWindowExW( 0, WC_STATICW, L"", WS_CHILD | SS_LEFT, 0, 0, 0, 0, window_,
						reinterpret_cast<HMENU>( IDC_INSTALL_TERMS_NOTE), instance_, nullptr) ;
	installTermsButton_ = CreateWindowExW(
		0, WC_BUTTONW, loadString( IDS_INSTALL_TERMS_OPEN).c_str(), WS_CHILD | WS_TABSTOP, 0, 0, 0,
		0, window_, reinterpret_cast<HMENU>( IDC_INSTALL_TERMS), instance_, nullptr) ;
	selectAllButton_ =
		CreateWindowExW( 0, WC_BUTTONW, loadString( IDS_SELECT_ALL_RECOMMENDED).c_str(),
						WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, window_,
						reinterpret_cast<HMENU>( IDC_SELECT_ALL_RECOMMENDED), instance_, nullptr) ;
	clearSelectionButton_ = CreateWindowExW(
		0, WC_BUTTONW, loadString( IDS_CLEAR_SELECTION).c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP,
		0, 0, 0, 0, window_, reinterpret_cast<HMENU>( IDC_CLEAR_SELECTION), instance_, nullptr) ;
	providerSourcesButton_ = CreateWindowExW(
		0, WC_BUTTONW, loadString( IDS_PROVIDER_SOURCES).c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP,
		0, 0, 0, 0, window_, reinterpret_cast<HMENU>( IDC_PROVIDER_SOURCES), instance_, nullptr) ;
	recommendedOnlyCheckbox_ =
		CreateWindowExW( 0, WC_BUTTONW, loadString( IDS_RECOMMENDED_ONLY_FILTER).c_str(),
						WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 0, 0, 0, 0, window_,
						reinterpret_cast<HMENU>( IDC_RECOMMENDED_ONLY), instance_, nullptr) ;
	status_ = CreateWindowExW( 0, WC_STATICW, loadString( IDS_STATUS_IDLE).c_str(),
							  WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, 0, 0, 0, 0, window_,
							  reinterpret_cast<HMENU>( IDC_STATUS), instance_, nullptr) ;

	// 必須controlが一つでも作れなければ、不完全な操作画面でworkerを開始しない。
	if( treeHeader_ == nullptr || updateTree_ == nullptr || scanButton_ == nullptr ||
	   installButton_ == nullptr || selectAllButton_ == nullptr ||
	   clearSelectionButton_ == nullptr || providerSourcesButton_ == nullptr ||
	   recommendedOnlyCheckbox_ == nullptr || status_ == nullptr || installTermsNote_ == nullptr ||
	   installTermsButton_ == nullptr) {
		return false ;
	}

	// 標準fontを設定する、TreeTable以外のchild control handle群。
	const HWND controls[] = {
		scanButton_,	  installButton_,		 installTermsNote_,		 installTermsButton_,
		selectAllButton_, clearSelectionButton_, providerSourcesButton_, recommendedOnlyCheckbox_,
		status_} ;
	// Command領域はWindows標準UI fontを使用し、利用者のsystem設定を維持する。
	for( const HWND control : controls) {
		SendMessageW( control, WM_SETFONT, reinterpret_cast<WPARAM>( uiFont_), TRUE) ;
	}

	// 最下段の案内文だけを拡大し、buttonはWindows標準fontを維持する。
	static_cast<void>( updateMessageFont( GetDpiForWindow( window_))) ;

	// 標準checkboxの自動check、keyboard操作、およびaccessibilityを残して描画だけを置き換える。
	if( SetWindowSubclass( recommendedOnlyCheckbox_, recommendedFilterProc,
						 RECOMMENDED_FILTER_SUBCLASS_ID,
						 reinterpret_cast<DWORD_PTR>( this)) == FALSE) {
		return false ;
	}

	// 専用fontが作れない場合はOS所有の標準fontを使い、TreeTableを利用可能に保つ。
	if( !updateTreeFont( GetDpiForWindow( window_))) {
		// Font作成不能時もTreeTableを利用できるよう、OS所有の標準fontへ縮退する。
		SendMessageW( treeHeader_, WM_SETFONT, reinterpret_cast<WPARAM>( uiFont_), TRUE) ;
		SendMessageW( updateTree_, WM_SETFONT, reinterpret_cast<WPARAM>( uiFont_), TRUE) ;
	}

	TreeView_SetExtendedStyle( updateTree_, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER) ;
	static_cast<void>( SetWindowTheme( updateTree_, L"Explorer", nullptr)) ;
	// readonlyと通常の枠を見分けられない状態ではUIを公開しません。
	if( !initializeCheckboxImages()) {
		return false ;
	}

	// Icon resourceが取得できない環境でもscanとinstall機能は維持する。
	static_cast<void>( initializeDeviceClassImages()) ;
	// 必須の表示列を構成できない場合は、候補の意味が欠けたUIを公開しない。
	if( !initializeTreeColumns()) {
		return false ;
	}

#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
	// 内部画面試験で両fakeが未指定の場合に、既定Providerや実復旧APIを起動しない。
	if( !testProviderFactory_ || !testRestorePointFactory_) {
		return false ;
	}

	worker_ = std::make_unique<ProviderWorker>( window_, WORKER_NOTIFICATION_MESSAGE,
											   testProviderFactory_, testRestorePointFactory_) ;
#else
	worker_ = std::make_unique<ProviderWorker>( window_, WORKER_NOTIFICATION_MESSAGE) ;
#endif
	// 初回scanはregistryで既定有効とされたProviderを全て選択する。
	for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
		// registryの既定有効値だけを初期設定へ反映し、UI独自のProvider定義を作らない。
		if( descriptor.enabledByDefault) {
			enabledProviderIds_.push_back( descriptor.id) ;
		}
	}

	updateProviderSourcesCaption() ;
	layoutControls() ;
	updateCommandState() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::updateMessageFont( const UINT dpi) noexcept
{
	// DPIや対象controlが未確定なら、新しいfontを作成・適用しない。
	if( dpi == 0 || status_ == nullptr) {
		return false ;
	}

	NONCLIENTMETRICSW metrics{} ;	// 対象DPIにおけるWindows標準message font情報。
	metrics.cbSize = sizeof( metrics) ;
	LOGFONTW fontDescription{} ;	// CreateFontIndirectWへ渡す上下message font属性。
	// 対象DPIの標準message fontを取得できた場合に、その設定を基準へ使用する。
	if( SystemParametersInfoForDpi( SPI_GETNONCLIENTMETRICS, sizeof( metrics), &metrics, 0, dpi) !=
	   FALSE) {
		fontDescription = metrics.lfMessageFont ;
	}
	// 代替fontの情報も取得できない場合は、不明な設定でfontを置き換えない。
	else if( GetObjectW( uiFont_, sizeof( fontDescription), &fontDescription) == 0) {
		return false ;
	}

	// 負の高さはcharacter heightを示す。System設定が既に大きい場合は縮小しない。
	const int minimumHeight = -MulDiv( MESSAGE_FONT_POINT_SIZE, static_cast<int>( dpi), 72) ;
	// 文字の実高さが最低値を下回らないよう補正し、高DPIでもmessageの可読性を保つ。
	if( fontDescription.lfHeight >= 0 || fontDescription.lfHeight > minimumHeight) {
		fontDescription.lfHeight = minimumHeight ;
	}

	HFONT const newFont = CreateFontIndirectW( &fontDescription) ;	// 新しい所有font handle。
	// 新しいfontを作成できない場合は既存fontを保持する。
	if( newFont == nullptr) {
		return false ;
	}

	HFONT const previousFont = messageFont_ ;	// Controlから参照を外した後に解放する旧font。
	messageFont_			 = newFont ;
	SendMessageW( status_, WM_SETFONT, reinterpret_cast<WPARAM>( messageFont_), TRUE) ;
	InvalidateRect( status_, nullptr, TRUE) ;

	// controlへの付替えを終えた旧fontだけを解放する。
	if( previousFont != nullptr) {
		DeleteObject( previousFont) ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::updateTreeFont( const UINT dpi) noexcept
{
	// DPIまたは対象controlが未確定の間はfontを更新しない。
	if( dpi == 0 || treeHeader_ == nullptr || updateTree_ == nullptr) {
		return false ;
	}

	NONCLIENTMETRICSW metrics{} ;	// 対象DPIにおけるWindows標準message font情報。
	metrics.cbSize = sizeof( metrics) ;
	LOGFONTW fontDescription{} ;	// CreateFontIndirectWへ渡すTreeTable font属性。
	// 対象DPIの標準fontを取得できた場合はその設定を優先する。
	if( SystemParametersInfoForDpi( SPI_GETNONCLIENTMETRICS, sizeof( metrics), &metrics, 0, dpi) !=
	   FALSE) {
		fontDescription = metrics.lfMessageFont ;
	}
	// 標準設定も既存fontも取得できない場合は更新を中止する。
	else if( GetObjectW( uiFont_, sizeof( fontDescription), &fontDescription) == 0) {
		return false ;
	}

	// 負の高さはcharacter heightを示す。System設定が既に大きい場合は縮小しない。
	const int minimumHeight = -MulDiv( TREE_FONT_POINT_SIZE, static_cast<int>( dpi), 72) ;
	// 文字の高さが最低表示寸法を満たすよう補正する。
	if( fontDescription.lfHeight >= 0 || fontDescription.lfHeight > minimumHeight) {
		fontDescription.lfHeight = minimumHeight ;
	}

	HFONT const newFont = CreateFontIndirectW( &fontDescription) ;	// 新しい所有font handle。
	// 新しいfontを作成できない場合は既存の表示資源を維持する。
	if( newFont == nullptr) {
		return false ;
	}

	HFONT const previousFont = treeFont_ ;	// Controlから参照を外した後に解放する旧font。
	treeFont_				 = newFont ;
	SendMessageW( treeHeader_, WM_SETFONT, reinterpret_cast<WPARAM>( treeFont_), TRUE) ;
	SendMessageW( updateTree_, WM_SETFONT, reinterpret_cast<WPARAM>( treeFont_), TRUE) ;
	static_cast<void>(
		TreeView_SetItemHeight( updateTree_, scaleForDpi( TREE_ROW_LOGICAL_HEIGHT, dpi))) ;
	InvalidateRect( treeHeader_, nullptr, TRUE) ;
	InvalidateRect( updateTree_, nullptr, TRUE) ;

	// controlが新しいfontへ切り替わった後に旧fontを解放する。
	if( previousFont != nullptr) {
		DeleteObject( previousFont) ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::initializeDeviceClassImages() noexcept
{
	// Tree未作成時とimage list設定済み時は初期化を重ねない。
	if( updateTree_ == nullptr || deviceClassImages_.ImageList != nullptr) {
		return false ;
	}

	deviceClassImages_.cbSize = sizeof( deviceClassImages_) ;
	// 取得失敗時は未初期化状態へ戻し、不完全なimage listを使用しない。
	if( SetupDiGetClassImageList( &deviceClassImages_) == FALSE) {
		deviceClassImages_ = {} ;
		return false ;
	}

	// 未登録GUIDに対しSetupAPIが返すUnknown device setup class iconのindex。
	GUID const unknownClassGuid{} ;
	static_cast<void>( SetupDiGetClassImageIndex( &deviceClassImages_, &unknownClassGuid,
												&fallbackDeviceImageIndex_)) ;
	TreeView_SetImageList( updateTree_, deviceClassImages_.ImageList, TVSIL_NORMAL) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
int MainWindow::deviceClassImageIndex( const UpdateCandidate &candidate) noexcept
{
	// class情報またはimage listがない場合は既定のdevice画像を使う。
	if( deviceClassImages_.ImageList == nullptr || candidate.deviceClassGuid.empty()) {
		return fallbackDeviceImageIndex_ ;
	}

	GUID classGuid{} ;	// String GUIDから復元するWindows setup class GUID。
	// GUIDを解釈できない候補は既定画像で表示を継続する。
	if( FAILED( CLSIDFromString( candidate.deviceClassGuid.c_str(), &classGuid))) {
		return fallbackDeviceImageIndex_ ;
	}

	int imageIndex{} ;	// SetupAPI class image list内の解決済みindex。
	// class固有画像が見つからない場合は既定画像へ戻す。
	if( SetupDiGetClassImageIndex( &deviceClassImages_, &classGuid, &imageIndex) == FALSE) {
		return fallbackDeviceImageIndex_ ;
	}

	return imageIndex ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::deviceClassKey( const std::wstring_view value) const
{
	// GUID以外の名前や過大文字列をWindowsの名前解決へ渡さない。
	if( value.size() != 38U || value.front() != L'{' || value.back() != L'}') {
		return {} ;
	}

	const std::wstring		 terminated( value) ;	// Windows境界へ渡す終端付きの有限文字列。
	GUID					 guid{} ;				// 標準形式として解釈できた表示分類GUID。
	std::array<wchar_t, 39U> canonical{} ;			// Brace付き38文字と終端だけを保持する。
	// 不正GUIDをその他以外のgroup keyとして使用しない。
	if( FAILED( CLSIDFromString( terminated.c_str(), &guid)) ||
	   StringFromGUID2( guid, canonical.data(), static_cast<int>( canonical.size())) != 39) {
		return {} ;
	}

	return std::wstring( canonical.data(), 38U) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::deviceClassName( const std::wstring_view key) const
{
	// 不明分類はWindows照会をせず、呼出側のその他表示へ委譲する。
	if( key.empty()) {
		return {} ;
	}

	const std::wstring			  terminated( key) ;	// 呼出し中だけ有効な正規GUIDの終端文字列。
	GUID						  guid{} ;				// Local setup class情報だけを参照するGUID。
	std::array<wchar_t, LINE_LEN> description{} ;		// SetupAPIの分類説明上限に終端を含めたbuffer。
	DWORD						  required{} ;			// Windowsが返す終端込み文字数。
	// 説明取得失敗は表示上の分類不明とし、名前の推測や取得先追加を行わない。
	if( FAILED( CLSIDFromString( terminated.c_str(), &guid)) ||
	   SetupDiGetClassDescriptionW( &guid, description.data(),
								   static_cast<DWORD>( description.size()), &required) == FALSE ||
	   required <= 1U || required > description.size() || description[required - 1U] != L'\0') {
		return {} ;
	}

	return makeSingleLine( std::wstring( description.data(), required - 1U)) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::updateDeviceClassSummaries( const bool expired)
{
	const bool metadata = controller_.scanPurpose() == ScanPurpose::METADATA_ONLY ;	// 件数の用途。
	// 種類直下のdeviceだけを集計し、候補数をdevice数へ加算しない。
	for( auto category = TreeView_GetRoot( updateTree_); category != nullptr;
		category	  = TreeView_GetNextSibling( updateTree_, category)) {
		TVITEMW categoryItem{} ;	// 種類行と表示modelの対応。
		categoryItem.mask  = TVIF_PARAM ;
		categoryItem.hItem = category ;
		// 不正なparameterを配列indexとして使用しない。
		if( TreeView_GetItem( updateTree_, &categoryItem) == FALSE || categoryItem.lParam <= 0) {
			continue ;
		}

		const auto rowIndex = static_cast<std::size_t>( categoryItem.lParam - 1) ;	// 種類行の位置。
		// 種類行以外へ集計を上書きしない。
		if( rowIndex >= treeRows_.size() || treeRows_[rowIndex].kind != TreeRowKind::DEVICE_CLASS) {
			continue ;
		}

		std::size_t deviceCount{} ;			// 表示中のdevice数。
		std::size_t informationCount{} ;	// 条件を満たす候補があるdevice数。
		// 同名の別deviceを別々に数え、候補の有無は一device一件に畳み込む。
		for( auto device = TreeView_GetChild( updateTree_, category); device != nullptr;
			device		= TreeView_GetNextSibling( updateTree_, device)) {
			++deviceCount ;
			TVITEMW deviceItem{} ;	// Device行の非所有parameter。
			deviceItem.mask	 = TVIF_PARAM ;
			deviceItem.hItem = device ;
			// 未登録itemを候補として補完しない。
			if( TreeView_GetItem( updateTree_, &deviceItem) == FALSE) {
				continue ;
			}

			const auto *deviceRow = treeRowFromParameter( deviceItem.lParam) ;	// 同deviceの候補集合。
			// 分類や不正行をdeviceの候補集合として扱わない。
			if( deviceRow == nullptr || deviceRow->kind != TreeRowKind::DEVICE) {
				continue ;
			}

			bool found{} ;	// 同deviceを最大一件だけ加算する。
			// 全候補の意味を保持し、詳細で指定していない更新も件数へ含める。
			for( const auto index : deviceRow->candidateIndexes) {
				// 破損した表示indexから候補を参照しない。
				if( index >= candidates_.size()) {
					continue ;
				}

				const auto &candidate = candidates_[index] ;	// 元scanの候補属性。
				found				  = found ||
						(metadata ? !candidate.current && candidate.metadataDistribution.has_value()
								  : candidate.installable && !candidate.current &&
										candidate.action == DriverAction::UPDATE) ;
			}

			informationCount += found ? 1U : 0U ;
		}

		auto &row		= treeRows_[rowIndex] ;	// 同じ種類の表示値だけを更新する。
		row.primaryText = row.className +
						  formatResource( IDS_TREE_CLASS_DEVICE_COUNT, std::to_wstring( deviceCount)) ;
		row.status			   = expired ? loadString( IDS_TREE_CLASS_EXPIRED)
										 : formatResource( metadata ? IDS_TREE_CLASS_INFORMATION_COUNT
																   : IDS_TREE_CLASS_UPDATE_COUNT,
											  std::to_wstring( informationCount)) ;
		std::wstring text	   = row.primaryText ;	// 読み上げ用の同じ要約。
		categoryItem.mask	   = TVIF_TEXT | TVIF_STATE ;
		categoryItem.pszText   = text.data() ;
		categoryItem.stateMask = TVIS_STATEIMAGEMASK ;
		categoryItem.state	   = 0 ;
		TreeView_SetItem( updateTree_, &categoryItem) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::layoutControls() noexcept
{
	// 配置に必要な親windowと列headerが揃うまでlayoutを変更しない。
	if( window_ == nullptr || treeHeader_ == nullptr) {
		return ;
	}

	RECT client{} ;	// Client領域のphysical pixel矩形。
	GetClientRect( window_, &client) ;
	const UINT dpi					= GetDpiForWindow( window_) ;	// Layout計算へ使用する現在DPI。
	const int  margin				= scaleForDpi( 16, dpi) ;		// Client外周余白（physical pixel）。
	const int  gap					= scaleForDpi( 10, dpi) ;		// Control間隔（physical pixel）。
	const int  tableHeaderHeight	= scaleForDpi( 28, dpi) ;		// Table column header高さ。
	const int  buttonHeight			= scaleForDpi( 34, dpi) ;		// Command button共通高さ。
	const int  commandGap			= scaleForDpi( 8, dpi) ;		// Command control間隔。
	const int  scanWidth			= scaleForDpi( 130, dpi) ;		// Scan button幅。
	const int  installWidth			= scaleForDpi( 200, dpi) ;		// Install button幅。
	const int  selectAllWidth		= scaleForDpi( 110, dpi) ;		// 推奨更新一括選択button幅。
	const int  clearSelectionWidth	= scaleForDpi( 100, dpi) ;		// 全選択解除button幅。
	const int  providerSourcesWidth = scaleForDpi( 130, dpi) ;		// 取得元設定button幅。
	const int  filterWidth			= scaleForDpi( 150, dpi) ;		// 推奨更新filter checkbox幅。
	const int  statusHeight			= scaleForDpi( 28, dpi) ;		// 全幅status/progress帯高さ。
	const int  termsHeight = (GetWindowLongPtrW( installTermsNote_, GWL_STYLE) & WS_VISIBLE) != 0
								 ? scaleForDpi( 46, dpi)
								 : 0 ;									// 選択時だけの規約案内帯です。
	const int  termsWidth  = scaleForDpi( 136, dpi) ;					// 任意の全文閲覧button幅です。
	const int termsSpace = termsHeight == 0 ? 0 : termsHeight + gap ;	// 非表示時は空白を残しません。
	const int footerHeight =
		gap + termsSpace + buttonHeight + gap + statusHeight ;					// TreeTable下部領域高さ。
	const int clientWidth  = static_cast<int>( client.right - client.left) ;	// Client幅。
	const int clientHeight = static_cast<int>( client.bottom - client.top) ;	// Client高さ。
	const int contentWidth = std::max( 0, clientWidth - margin * 2) ;			// 左右余白を除く幅。

	const int tableTop = margin ;	// 一覧の列見出しを上端へ配置する。
	MoveWindow( treeHeader_, margin, tableTop, contentWidth, tableHeaderHeight, TRUE) ;
	const int treeTop = tableTop + tableHeaderHeight ;	// TreeView data領域上端のY座標。
	// Footerと下余白を除いたTreeView data領域高さ。
	const int treeHeight = std::max( 0, clientHeight - treeTop - footerHeight - margin) ;
	MoveWindow( updateTree_, margin, treeTop, contentWidth, treeHeight, TRUE) ;
	resizeTreeColumns( contentWidth) ;

	const int termsTop = treeTop + treeHeight + gap ;	// 案内を導入buttonの直前へ置きます。
	MoveWindow( installTermsNote_, margin, termsTop, std::max( 0, contentWidth - termsWidth - gap),
			   termsHeight, TRUE) ;
	MoveWindow( installTermsButton_, margin + std::max( 0, contentWidth - termsWidth), termsTop,
			   termsWidth, termsHeight == 0 ? 0 : buttonHeight, TRUE) ;
	const int buttonTop	  = termsTop + termsSpace ;	// Command button上端のY座標。
	int		  commandLeft = margin ;				// 次に配置するcommand controlの左端X座標。
	MoveWindow( scanButton_, commandLeft, buttonTop, scanWidth, buttonHeight, TRUE) ;
	commandLeft += scanWidth + commandGap ;
	MoveWindow( installButton_, commandLeft, buttonTop, installWidth, buttonHeight, TRUE) ;
	commandLeft += installWidth + commandGap ;
	MoveWindow( selectAllButton_, commandLeft, buttonTop, selectAllWidth, buttonHeight, TRUE) ;
	commandLeft += selectAllWidth + commandGap ;
	MoveWindow( clearSelectionButton_, commandLeft, buttonTop, clearSelectionWidth, buttonHeight,
			   TRUE) ;
	commandLeft += clearSelectionWidth + commandGap ;
	MoveWindow( providerSourcesButton_, commandLeft, buttonTop, providerSourcesWidth, buttonHeight,
			   TRUE) ;
	commandLeft += providerSourcesWidth + commandGap ;
	MoveWindow( recommendedOnlyCheckbox_, commandLeft, buttonTop, filterWidth, buttonHeight, TRUE) ;
	MoveWindow( status_, margin, buttonTop + buttonHeight + gap, contentWidth, statusHeight, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::initializeTreeColumns()
{
	// control未作成またはcolumn定義の件数不一致では初期化しない。
	if( treeHeader_ == nullptr || TREE_COLUMN_RESOURCE_IDS.size() != TREE_COLUMN_COUNT) {
		return false ;
	}

	// 定義順を表示順として、各column titleをHeader controlへ登録する。
	for( std::size_t index = 0; index < TREE_COLUMN_RESOURCE_IDS.size(); ++index) {
		std::wstring title = loadString( TREE_COLUMN_RESOURCE_IDS[index]) ;	// Header表示文字列。
		HDITEMW		 column{} ;												// Headerへ追加する一columnの初期属性。
		column.mask	   = HDI_TEXT | HDI_WIDTH | HDI_FORMAT ;
		column.pszText = title.data() ;
		column.cxy	   = 1 ;
		column.fmt	   = HDF_LEFT | HDF_STRING ;
		// columnを挿入できない場合はtable初期化を成功扱いにしない。
		if( Header_InsertItem( treeHeader_, static_cast<int>( index), &column) == -1) {
			return false ;
		}
	}

	updateTreeSortIndicator() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::resizeTreeColumns( const int tableWidth) noexcept
{
	// 表示幅やcolumn構成が未確定の間は幅の再計算を行わない。
	if( treeHeader_ == nullptr || tableWidth <= 0 ||
	   Header_GetItemCount( treeHeader_) != static_cast<int>( TREE_COLUMN_COUNT)) {
		return ;
	}

	std::array<int, TREE_COLUMN_COUNT> baseWidths{} ;	// Resize前のcolumn幅または初期比率。
	int baseTotal{} ;									// 比率計算へ使用するbaseWidths合計（physical pixel）。
	// 初回はlogical初期幅、二回目以降は利用者が調整した実column幅を比率として使用する。
	for( std::size_t index = 0; index < baseWidths.size(); ++index) {
		HDITEMW column{} ;	// Headerから現在幅を取得するcolumn属性。
		column.mask = HDI_WIDTH ;
		// 利用者が調整した現在の列幅を再配分の基準に使用できるかを示す。
		const bool hasCurrentWidth =
			Header_GetItem( treeHeader_, static_cast<int>( index), &column) != FALSE ;
		baseWidths[index] = treeTableWidth_ == 0 || !hasCurrentWidth
								? TREE_COLUMN_LOGICAL_WIDTHS[index]
								: column.cxy ;
		baseTotal += std::max( 1, baseWidths[index]) ;
	}

	const UINT dpi			= GetDpiForWindow( window_) ;	// 最小column幅のscaleに使用するDPI。
	const int  minimumWidth = scaleForDpi( 48, dpi) ;		// 利用者がdrag可能な最小column幅。
	int		   assignedWidth{} ;							// 既に左側columnへ割り当てた合計幅。
	// 最後のcolumnで丸め誤差を吸収し、HeaderとTreeViewの右端を一致させる。
	for( std::size_t index = 0; index < baseWidths.size(); ++index) {
		const int remainingColumns = static_cast<int>( baseWidths.size() - index) ;	// 残column数。
		const int availableWidth   = tableWidth - assignedWidth ;					// 残columnへ割当可能な幅。
		// 基準幅の比率で配分した幅。最後の列では残り幅を全て引き受ける。
		const int proportionalWidth =
			index + 1U == baseWidths.size()
				? availableWidth
				: MulDiv( tableWidth, std::max( 1, baseWidths[index]), baseTotal) ;
		const int reservedWidth = minimumWidth * std::max( 0, remainingColumns - 1) ;	// 後続分。
		// 後続列の最低幅を予約したうえで、この列へ割り当てるpixel数。
		const int columnWidth =
			std::max( minimumWidth, std::min( proportionalWidth, availableWidth - reservedWidth)) ;
		HDITEMW column{} ;	// Headerへ反映する現在columnの新しい幅。
		column.mask = HDI_WIDTH ;
		column.cxy	= columnWidth ;
		static_cast<void>( Header_SetItem( treeHeader_, static_cast<int>( index), &column)) ;
		assignedWidth += columnWidth ;
	}

	treeTableWidth_ = tableWidth ;
	InvalidateRect( updateTree_, nullptr, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::handleHeaderClick( const int columnIndex) noexcept
{
	// 定義外のcolumn通知を並べ替え条件へ取り込まない。
	if( columnIndex < 0 || static_cast<std::size_t>( columnIndex) >= TREE_COLUMN_COUNT) {
		return ;
	}

	const std::size_t selectedColumn =
		// 検証済みの0始まりcolumn index。
		static_cast<std::size_t>( columnIndex) ;
	// 同じcolumnの再選択では現在の並び順を反転する。
	if( sortActive_ && sortedColumn_ == selectedColumn) {
		sortAscending_ = !sortAscending_ ;
	} else {
		sortedColumn_  = selectedColumn ;
		sortAscending_ = true ;
		sortActive_	   = true ;
	}

	updateTreeSortIndicator() ;
	sortTreeItems() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::updateTreeSortIndicator() const noexcept
{
	// Header作成前はsort表示を更新しない。
	if( treeHeader_ == nullptr) {
		return ;
	}

	// 全columnの方向flagを読み戻し、選択columnだけへ新しいflagを設定する。
	for( std::size_t index = 0; index < TREE_COLUMN_COUNT; ++index) {
		HDITEMW column{} ;	// Headerから取得・更新するcolumn format。
		column.mask = HDI_FORMAT ;
		// 取得できないcolumnは飛ばし、取得済みの属性だけを更新する。
		if( Header_GetItem( treeHeader_, static_cast<int>( index), &column) == FALSE) {
			continue ;
		}

		column.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN) ;
		// 現在のsort対象columnにだけ方向矢印を付ける。
		if( sortActive_ && index == sortedColumn_) {
			column.fmt |= sortAscending_ ? HDF_SORTUP : HDF_SORTDOWN ;
		}

		static_cast<void>( Header_SetItem( treeHeader_, static_cast<int>( index), &column)) ;
	}

	InvalidateRect( treeHeader_, nullptr, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::sortTreeItems() noexcept
{
	// sort未指定または無効な表示先では候補の表示順を変更しない。
	if( !sortActive_ || updateTree_ == nullptr || sortedColumn_ >= TREE_COLUMN_COUNT) {
		return ;
	}

	const TreeSortContext context{.window	   = this,
								  .columnIndex = sortedColumn_,
								  .ascending   = sortAscending_} ;	// 同期sort呼出し中の条件。
	TVSORTCB			  sortParameters{} ;						// TreeViewのitem並べ替えparameter。
	sortParameters.lpfnCompare = compareTreeItems ;
	// Callback context pointerはTreeView_SortChildrenCBの同期呼出し中だけ有効である。
	sortParameters.lParam  = reinterpret_cast<LPARAM>( &context) ;
	sortParameters.hParent = TVI_ROOT ;
	static_cast<void>( TreeView_SortChildrenCB( updateTree_, &sortParameters, FALSE)) ;

	// 二階層だけを有限走査し、分類内のdeviceを別々に並べ替える。
	for( HTREEITEM category = TreeView_GetRoot( updateTree_); category != nullptr;
		category		   = TreeView_GetNextSibling( updateTree_, category)) {
		sortParameters.hParent = category ;
		static_cast<void>( TreeView_SortChildrenCB( updateTree_, &sortParameters, FALSE)) ;
	}

	InvalidateRect( updateTree_, nullptr, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::drawTreeRow( const NMTVCUSTOMDRAW &customDraw) const noexcept
{
	const TreeRow *const row =
		// 描画対象の検証済みrow。
		treeRowFromParameter( customDraw.nmcd.lItemlParam) ;
	// 描画対象の行とcontrolが揃わない通知は処理しない。
	if( row == nullptr || treeHeader_ == nullptr || updateTree_ == nullptr) {
		return ;
	}

	// 左からHeader columnと同じ順序で描画するrow value群。
	const std::array<std::wstring_view, TREE_COLUMN_COUNT> values{
		row->primaryText, row->currentVersion, row->candidateVersion} ;
	const bool selected = (customDraw.nmcd.uItemState & CDIS_SELECTED) != 0 ;	// 選択行判定。
	const bool focused	= GetFocus() == updateTree_ ;							// Highlight色を使うfocus状態。
	const bool enabled	= IsWindowEnabled( updateTree_) != FALSE ;				// 操作可能な描画状態。
	// 選択とfocusの有無に対応する、system palette内の背景色index。
	const int  backgroundColor =
		 selected && focused ? COLOR_HIGHLIGHT : (selected ? COLOR_BTNFACE : COLOR_WINDOW) ;
	// 選択・focus・有効状態に対応する、system palette内の文字色index。
	const int foregroundColor =
		selected && focused ? COLOR_HIGHLIGHTTEXT : (enabled ? COLOR_WINDOWTEXT : COLOR_GRAYTEXT) ;
	HBRUSH const backgroundBrush   = GetSysColorBrush( backgroundColor) ;	// Cell背景brush。
	HBRUSH const gridBrush		   = GetSysColorBrush( COLOR_3DFACE) ;		// Column境界とrow境界のbrush。
	const UINT	 dpi			   = GetDpiForWindow( window_) ;			// Cell余白計算用DPI。
	const int	 horizontalPadding = scaleForDpi( 6, dpi) ;					// Text左右余白（physical pixel）。
	// Tree glyph、checkbox、およびindent後の第一column text開始位置。
	RECT		 labelRectangle{} ;
	// NMCD::dwItemSpecはTreeViewがHTREEITEMを格納するWin32境界のpointer-sized fieldである。
	const bool	 hasLabelRectangle =
		TreeView_GetItemRect( updateTree_, reinterpret_cast<HTREEITEM>( customDraw.nmcd.dwItemSpec),
							 &labelRectangle, TRUE) != FALSE ;
	const int savedDeviceContext = SaveDC( customDraw.nmcd.hdc) ;	// 復元する描画context状態。
	// 描画状態を保存できない場合は呼出元のDCを変更しない。
	if( savedDeviceContext == 0) {
		return ;
	}

	SetBkMode( customDraw.nmcd.hdc, TRANSPARENT) ;
	SetTextColor( customDraw.nmcd.hdc, GetSysColor( foregroundColor)) ;
	// 標準描画と同じTreeTable fontをcustom columnにも選択する。
	SelectObject( customDraw.nmcd.hdc, treeFont_ != nullptr ? treeFont_ : uiFont_) ;

	// 標準TreeViewの階層glyphを残し、label以降をcolumnごとにclipして上書きする。
	for( std::size_t index = 0; index < values.size(); ++index) {
		RECT cell{} ;	// Headerから取得する現在columnのTreeView内矩形。
		// column矩形が取得できないcellの描画を省略する。
		if( Header_GetItemRect( treeHeader_, static_cast<int>( index), &cell) == FALSE) {
			continue ;
		}

		cell.top	= customDraw.nmcd.rc.top ;
		cell.bottom = customDraw.nmcd.rc.bottom ;
		// 先頭columnはTreeの階層記号と文字領域が重ならない位置から描く。
		if( index == 0) {
			cell.left = hasLabelRectangle ? labelRectangle.left : cell.left + horizontalPadding ;
		}

		// 幅が残らないcellには文字を描画しない。
		if( cell.left >= cell.right) {
			continue ;
		}

		FillRect( customDraw.nmcd.hdc, &cell, backgroundBrush) ;
		RECT textRectangle = cell ;	// 背景とgridを除いたtext clip領域。
		textRectangle.left += horizontalPadding ;
		textRectangle.right -= horizontalPadding ;
		// 左右の余白を除いた描画幅がある場合にだけ文字を描く。
		if( textRectangle.left < textRectangle.right) {
			DrawTextW( customDraw.nmcd.hdc, values[index].data(),
					  static_cast<int>( values[index].size()), &textRectangle,
					  DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX) ;
		}

		RECT verticalGrid{cell.right - 1, cell.top, cell.right, cell.bottom} ;	// Column右境界。
		FillRect( customDraw.nmcd.hdc, &verticalGrid, gridBrush) ;
	}

	RECT horizontalGrid{customDraw.nmcd.rc.left, customDraw.nmcd.rc.bottom - 1,
						customDraw.nmcd.rc.right, customDraw.nmcd.rc.bottom} ;	// Row下境界。
	FillRect( customDraw.nmcd.hdc, &horizontalGrid, gridBrush) ;
	RestoreDC( customDraw.nmcd.hdc, savedDeviceContext) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::updateCommandState() noexcept
{
	const ApplicationState state = controller_.state() ;	// Button判定に使用する現在state。
	// trueの場合は候補とcommandの変更を禁止する。
	const bool			   busy =
		state == ApplicationState::SCANNING || state == ApplicationState::CANCELLING_SCAN ||
		state == ApplicationState::CREATING_RESTORE_POINT ||
		state == ApplicationState::DOWNLOADING || state == ApplicationState::INSTALLING ||
		state == ApplicationState::PREPARING || state == ApplicationState::CANCELLING_PREPARATION ||
		state == ApplicationState::CANCELLING_METADATA_SEARCH ||
		state == ApplicationState::STOPPING ;
	const bool scanActive = controller_.scanPurpose() == ScanPurpose::STANDARD &&
							// 同じ検索の取消しを許す。
							state == ApplicationState::SCANNING ;
	const bool preparationActive = state == ApplicationState::PREPARING ;	// 同じ取得の取消しを許す。
	const bool cancelling		 = state == ApplicationState::CANCELLING_SCAN ||
							// 終端待ちは再操作を禁止する。
							state == ApplicationState::CANCELLING_PREPARATION ;
	wchar_t scanCaption[128]{} ;	// Resource取得中もnoexceptを維持する固定buffer。
	LoadStringW( instance_,
				cancelling						  ? IDS_SCAN_CANCEL_WAIT_BUTTON
				: scanActive || preparationActive ? IDS_SCAN_CANCEL_BUTTON
												  : IDS_SCAN_BUTTON,
				scanCaption, 128) ;
	SetWindowTextW( scanButton_, scanCaption) ;
	EnableWindow( scanButton_, !closeAfterScan_ && !closeAfterPreparation_ &&
								  !closeAfterMetadataSearch_ &&
								  (!busy || scanActive || preparationActive)) ;

	bool hasSelection			 = false ;	// trueの場合は表示中installable候補が一件以上選択済み。
	bool hasPersistedSelection	 = false ;	// trueの場合は保持中のinstallable選択が一件以上ある。
	bool hasRecommendedCandidate = false ;	// trueの場合は一括選択可能な推奨更新が一件以上ある。
	// 操作中やscan未確定時の候補をbutton有効化の根拠にしない。
	if( !busy && state == ApplicationState::SCAN_READY) {
		// 表示中checkと保持中selectionを分け、filterで非表示の候補をinstall対象にしない。
		for( std::size_t index = 0; index < candidates_.size(); ++index) {
			const UpdateCandidate &candidate = candidates_[index] ;	// Button判定対象candidate。
			// Candidate vectorと同じindexで保持している永続selection状態。
			const bool selected = index < candidateSelected_.size() && candidateSelected_[index] ;
			// install可能な保持中選択がある場合に選択解除操作を許可する。
			if( isSelectableCandidate( candidate) && selected) {
				hasPersistedSelection = true ;
				// 表示行にもcheckがある候補だけを現在のinstall対象として数える。
				if( index < candidateItems_.size() && candidateItems_[index] != nullptr &&
				   TreeView_GetCheckState( updateTree_, candidateItems_[index]) != FALSE) {
					hasSelection = true ;
				}
			}

			// install可能な推奨候補がある場合に一括選択操作を許可する。
			if( candidate.installable && candidate.recommended) {
				hasRecommendedCandidate = true ;
			}
		}
	}

	// 表示だけの残存checkも、通常の明示解除が許される状態で解除できます。
	if( state == ApplicationState::SCAN_READY &&
	   std::ranges::any_of( preparationDisplayBindings_,
						   []( const auto &binding) { return binding.checked ; })) {
		hasPersistedSelection = true ;
	}

	const bool termsPresented =
		// 案内失敗を同意不要へ読み替えません。
		updateInstallTermsPresentation() ;
	EnableWindow( installButton_, hasSelection && termsPresented ? TRUE : FALSE) ;
	EnableWindow( selectAllButton_, hasRecommendedCandidate ? TRUE : FALSE) ;
	EnableWindow( clearSelectionButton_, hasPersistedSelection ? TRUE : FALSE) ;
	EnableWindow( providerSourcesButton_, busy ? FALSE : TRUE) ;
	EnableWindow( updateTree_, busy ? FALSE : TRUE) ;
	EnableWindow( recommendedOnlyCheckbox_, state == ApplicationState::SCAN_READY ? TRUE : FALSE) ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
std::wstring MainWindow::formatHardwareRefreshSummary() const
{
	// 実行していないfixtureや旧scanへ完了事実を補いません。
	if( !hardwareRefresh_) {
		return {} ;
	}

	// 完了は同期再検出の成功だけを表し、導入成功を表しません。
	if( hardwareRefresh_->succeeded) {
		return loadString( IDS_HARDWARE_REFRESH_COMPLETED) ;
	}

	const auto	&result		= *hardwareRefresh_ ;	// 元の領域と値を別々に保持します。
	std::wstring diagnostic = result.domain == HardwareRefreshErrorDomain::CONFIGURATION_MANAGER
								  ? L"CONFIGRET "
							  : result.domain == HardwareRefreshErrorDomain::WINDOWS_ERROR
								  ? L"Win32 "
								  : L"HRESULT " ;	// 診断領域です。
	diagnostic += formatNativeError( result.error) ;
	// 主処理失敗と独立した復帰失敗を隠しません。
	if( result.restoreError != 0U) {
		diagnostic += L" / Win32 " + formatNativeError( result.restoreError) ;
	}

	return formatResource( IDS_HARDWARE_REFRESH_FAILED, diagnostic) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::isInitialPreparationReference( const UpdateCandidate &candidate) const noexcept
{
	// 取得targetは選択意図だけです。失効・既検査候補や別経路を初回確認へ変換しません。
	if( candidate.installable || candidate.action != DriverAction::NONE ||
	   !isSelectableCandidate( candidate)) {
		return false ;
	}

	const UpdateCandidate *observed{} ;	// 同deviceの一意な現在観測だけを借用します。
	// 表示名や版ではなく、元opaque identityで現在観測を照合します。
	for( const auto &current : candidates_) {
		// 他deviceと非現在行は初回の判断根拠にしません。
		if( !current.current || current.deviceIdentity != candidate.deviceIdentity) {
			continue ;
		}

		// 矛盾する複数現在行から都合のよいCode28だけを選びません。
		if( observed != nullptr) {
			return false ;
		}

		observed = &current ;
	}

	return observed && observed->deviceObservation &&
		   isDeviceObservationBound( *observed->deviceObservation, controller_.scanSessionId(),
									candidate.deviceIdentity) &&
		   observed->deviceObservation->driverPresence == DeviceDriverPresence::NOT_INSTALLED ;
}

/** @see src/app/main_window.h 宣言側の契約を正本とします。 */
bool MainWindow::visibleInRecommendedFilter( const UpdateCandidate &candidate) const noexcept
{
	// 取得前情報は根拠ある初回または新版確認へ限定し、検証済み導入候補とは分けます。
	if( !candidate.installable) {
		return isInitialPreparationReference( candidate) ||
			   (isSelectableCandidate( candidate) &&
				classifyPendingReferenceVersion( candidate, candidates_,
												controller_.scanSessionId()) ==
					PendingReferenceVersion::NEWER) ;
	}

	const bool indexedUpdate =
		candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
		candidate.discoveryBasis == CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
		!candidate.preparationTargetIdentity.empty() &&
		isCandidateDetailsValid( candidate,
								// 元検査済み候補の分類です。
								controller_.scanSessionId()) ;
	return !candidate.current &&
		   (candidate.action == DriverAction::INITIAL_INSTALL ||
			(candidate.action == DriverAction::UPDATE && (candidate.recommended || indexedUpdate))) ;
}

/** @see src/app/main_window.h 宣言側の契約を正本とします。 */
void MainWindow::updateScanSummaryStatus()
{
	// 情報検索0行を適用可能更新なしという通常検索の成功文言へ変換しない。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) {
		updateMetadataSearchStatus() ;
		return ;
	}

	// System変更対象として選択できる全候補件数。
	const std::size_t installableCount = static_cast<std::size_t>(
		std::count_if( candidates_.begin(), candidates_.end(),
					  []( const UpdateCandidate &candidate) { return candidate.installable ; })) ;
	const auto recommendedCount =
		std::count_if( candidates_.begin(), candidates_.end(), [this]( const auto &candidate) {
			return candidate.installable && visibleInRecommendedFilter( candidate) ;
		}) ;			   // 元の検査済み/Windows管理候補だけです。
	std::wstring text ;	// 導入可能数と未取得情報を混同しない終端案内です。
	// 推奨filter中は表示中の導入可能候補だけを数えます。
	if( showRecommendedOnly_) {
		text = formatResource( IDS_STATUS_RECOMMENDED_COUNT, std::to_wstring( recommendedCount)) ;
	}
	// 未検査を導入候補数へ含めず、未知の情報と候補不在を分けます。
	else if( installableCount == 0U) {
		text = controller_.preparationPlan() != nullptr
				   ? formatResource( IDS_STATUS_RECOMMENDED_COUNT, L"0")
				   : loadString( IDS_STATUS_NO_UPDATES) ;
	}
	// 部分失敗を通常完了の案内で隠しません。
	else if( scanOutcome_ == OutcomeCode::SUCCEEDED_WITH_ERRORS) {
		text = formatResource( IDS_STATUS_SCAN_WARNING, std::to_wstring( installableCount)) ;
	} else {
		text = formatResource( IDS_STATUS_SCAN_COUNT, std::to_wstring( installableCount)) ;
	}

	const auto initialReferences =
		std::count_if( candidates_.begin(), candidates_.end(), [this]( const auto &candidate) {
			return isInitialPreparationReference( candidate) ;
		}) ; // 未検査の初回確認数です。
	// 初回の通常入口を保持しつつ、未取得参照を検査済み候補へ水増ししません。
	if( initialReferences != 0) {
		text += L" " + formatResource( IDS_STATUS_INITIAL_PREPARATION_COUNT,
									  std::to_wstring( initialReferences)) ;
	}

	const auto updateReferences =
		std::count_if( candidates_.begin(), candidates_.end(), [this]( const auto &candidate) {
			return isSelectableCandidate( candidate) &&
				   classifyPendingReferenceVersion( candidate, candidates_,
												   controller_.scanSessionId()) ==
					   PendingReferenceVersion::NEWER ;
		}) ; // 元targetへ選択できる取得前の新版確認数です。
	// 取得前を導入候補へ数えず、0件文言だけで新しい確認入口を隠しません。
	if( updateReferences != 0) {
		const auto confirmation = formatResource( IDS_STATUS_UPDATE_CONFIRMATION_COUNT,
												 // 未検査を明示します。
												 std::to_wstring( updateReferences)) ;
		text = (showRecommendedOnly_ ? recommendedCount == 0 : installableCount == 0U) &&
					   initialReferences == 0
				   ? confirmation
				   : text + L" " + confirmation ;
	}

	// 未使用計画による取得準備能力を案内し、他候補の件数や表示filterへ従属させません。
	if( controller_.preparationPlan() != nullptr) {
		const auto guidance = loadString( IDS_STATUS_PREPARATION_REQUIRED) ;	// 既存の取得前案内です。
		text += L" " + guidance ;
	}

	const auto hardware = formatHardwareRefreshSummary() ;	// 瞬時の段階も終端後に確認できます。
	// Fixtureの未実行を完了として表示しません。
	if( !hardware.empty()) {
		text = hardware + L" " + text ;
	}

	DiagnosticRecord diagnostic ;	// 元表示predicateの結果だけを保存し、表示条件を変えません。
	diagnostic.event	 = DiagnosticEvent::CANDIDATE_DISPLAY ;
	diagnostic.operation = controller_.activeOperationId() ;
	diagnostic.status	 = static_cast<std::int32_t>( controller_.state()) ;
	const auto recommended =
		std::count_if( candidates_.begin(), candidates_.end(), [this]( const auto &candidate) {
			return visibleInRecommendedFilter( candidate) ;
		}) ; // 初回未検査参照を含む元filterの表示候補数です。
	const auto pending =
		std::count_if( candidates_.begin(), candidates_.end(), []( const auto &candidate) {
			return !candidate.current && !candidate.installable &&
				   !candidate.preparationTargetIdentity.empty() ;
		}) ; // targetを持つ取得前参照の件数です。
	const auto visibleDevices =
		std::count_if( treeRows_.begin(), treeRows_.end(), [this]( const auto &row) {
			return row.kind == TreeRowKind::DEVICE && row.deviceIndex < candidateItems_.size() &&
				   candidateItems_[row.deviceIndex] != nullptr ;
		}) ; // 実際に保持されたtree device行数です。
	const auto recommendedInstallable =
		std::count_if( candidates_.begin(), candidates_.end(), [this]( const auto &candidate) {
			return candidate.installable && visibleInRecommendedFilter( candidate) ;
		}) ; // Status文言が数える導入候補と未検査参照を区別します。
	diagnostic.add( DiagnosticField::TOTAL, candidates_.size())
		.add( DiagnosticField::INSTALLABLE, installableCount)
		.add( DiagnosticField::RECOMMENDED, static_cast<std::uint64_t>( recommended))
		.add( DiagnosticField::RECOMMENDED_INSTALLABLE,
			 static_cast<std::uint64_t>( recommendedInstallable))
		.add( DiagnosticField::INITIAL_REFERENCES, static_cast<std::uint64_t>( initialReferences))
		.add( DiagnosticField::NEWER_REFERENCES, static_cast<std::uint64_t>( updateReferences))
		.add( DiagnosticField::PENDING_REFERENCES, static_cast<std::uint64_t>( pending))
		.add( DiagnosticField::NON_INITIAL_REFERENCES,
			 static_cast<std::uint64_t>( pending >= initialReferences ? pending - initialReferences
																	 : 0))
		.add( DiagnosticField::RECOMMENDED_FILTER, showRecommendedOnly_)
		.add( DiagnosticField::VISIBLE_DEVICES, static_cast<std::uint64_t>( visibleDevices))
		.add( DiagnosticField::PLAN_PRESENT, controller_.preparationPlan() != nullptr)
		.add( DiagnosticField::TARGETS,
			 controller_.preparationPlan() ? controller_.preparationPlan()->targets.size() : 0U) ;
	recordLocalDiagnostic( diagnostic) ;

	const auto storage = diagnosticStorageText( instance_) ;	// 保存不能も検索結果と別に案内します。
	// 未開始の内部fixtureへ新しい表示を追加しません。
	if( !storage.empty()) {
		text += L" " + storage ;
	}

	setStatus( text, false) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::handleRecommendedFilterChange()
{
	// scan結果が確定しているときだけ表示filterを変更する。
	if( controller_.state() != ApplicationState::SCAN_READY) {
		return ;
	}

	// Checked時は元の検証済み候補と取得前の初回/新版確認だけへ表示を限定します。
	showRecommendedOnly_ = SendMessageW( recommendedOnlyCheckbox_, BM_GETCHECK, 0, 0) == BST_CHECKED ;
	populateCandidates( candidates_) ;
	updateScanSummaryStatus() ;
	updateCommandState() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::selectAllRecommendedUpdates()
{
	// scan結果が確定していない状態では一括選択しない。
	if( controller_.state() != ApplicationState::SCAN_READY) {
		return ;
	}

	initializeCandidateSelection() ;
	// 利用者の明示操作へ表示意図も同期し、旧checkを復活させません。
	for( auto &binding : preparationDisplayBindings_) {
		binding.checked = false ;
	}

	applyCandidateSelectionToTree() ;
	updateCommandState() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::clearCandidateSelection()
{
	// 操作中にinstall対象を変更しないよう選択解除を拒否する。
	if( controller_.state() != ApplicationState::SCAN_READY) {
		return ;
	}

	std::fill( candidateSelected_.begin(), candidateSelected_.end(), false) ;
	// 利用者の明示操作へ表示意図も同期し、旧checkを復活させません。
	for( auto &binding : preparationDisplayBindings_) {
		binding.checked = false ;
	}

	applyCandidateSelectionToTree() ;
	updateCommandState() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::showProviderSourcesMenu()
{
	// 専用結果に通常scan設定のcheckを重ねず、今回の条件と結果だけを表示する。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) {
		showMetadataSearchDetails() ;
		return ;
	}

	const std::span descriptors = builtInProviderDescriptors() ;	// Popupへ表示するregistry。
	// 起点controlまたはProvider定義がない場合はmenuを作成しない。
	if( providerSourcesButton_ == nullptr || descriptors.empty()) {
		return ;
	}

	HMENU const menu = CreatePopupMenu() ;	// 本関数がDestroyMenuで解放するpopup menu。
	// menu作成失敗時は無効なhandleで表示処理を続けない。
	if( menu == nullptr) {
		return ;
	}

	// 全ProviderをRegistry順にmenuへ追加し、今回の有効状態と前回scan結果を表示する。
	for( std::size_t index = 0; index < descriptors.size(); ++index) {
		const ProviderDescriptor &descriptor = descriptors[index] ;	// 現在追加する取得元定義。
		// このProviderが利用者の明示有効集合に含まれるかを示す。
		const bool	 enabled = std::find( enabledProviderIds_.begin(), enabledProviderIds_.end(),
										 descriptor.id) != enabledProviderIds_.end() ;
		std::wstring label	 = descriptor.displayName ;	// Provider名と前回状態を含むmenu text。
		// 同じstable IDのscan報告を探すiterator。Descriptor参照は同期探索中だけ借用する。
		const auto	 report = std::find_if( providerReports_.begin(), providerReports_.end(),
										   [&descriptor]( const ProviderScanReport &value) {
											   return value.descriptor.id == descriptor.id ;
										   }) ;
		// 前回のProvider結果がある場合にだけその状態をmenuへ追記する。
		if( report != providerReports_.end()) {
			label += L" — 前回: " + providerStateText( report->state) ;
			// 無効だったProviderには未実施の対象件数を実績として表示しない。
			if( report->state != ProviderScanState::DISABLED) {
				const std::wstring coverage =	// 対象、判定済み、表示候補の順に並べる件数。
					std::to_wstring( report->coverage.eligibleDeviceCount) + L" / " +
					std::to_wstring( report->coverage.assessedDeviceCount) + L" / " +
					std::to_wstring( report->candidateCount) ;
				label += L" (" + formatResource( IDS_PROVIDER_COVERAGE, coverage) + L")" ;
			}

			// 新計測があるProviderだけに確定度付きT／Q／R／A／Iを追記する。
			if( report->coverage.measurement.has_value()) {
				label +=
					L" — " +
					formatResource( IDS_MEASUREMENT_PROVIDER,
								   formatStageMeasurement( report->coverage.measurement->devices)) ;
			}
		}

		// Intel用ZIPの明示選択が保持されていることをmenuへ示す。
		if( descriptor.id == INTEL_WIRELESS_PACKAGE_PROVIDER_ID &&
		   !selectedIntelWirelessPackagePath_.empty()) {
			label += L" — " + loadString( IDS_INTEL_PACKAGE_SELECTED) ;
		}

		// Prolific用ZIPの明示選択が保持されていることをmenuへ示す。
		if( descriptor.id == PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID &&
		   !selectedProlificSerialPackagePath_.empty()) {
			label += L" — " + loadString( IDS_INTEL_PACKAGE_SELECTED) ;
		}

		// Silicon Labs用ZIPの明示選択が保持されていることをmenuへ示す。
		if( descriptor.id == SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID &&
		   !selectedSiliconLabsSerialPackagePath_.empty()) {
			label += L" — " + loadString( IDS_INTEL_PACKAGE_SELECTED) ;
		}

		// WCH serial用ZIPの明示選択が保持されていることをmenuへ示す。
		if( descriptor.id == WCH_SERIAL_PACKAGE_PROVIDER_ID &&
		   !selectedWchSerialPackagePath_.empty()) {
			label += L" — " + loadString( IDS_INTEL_PACKAGE_SELECTED) ;
		}

		// WCH multi-serial用ZIPの明示選択が保持されていることをmenuへ示す。
		if( descriptor.id == WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID &&
		   !selectedWchMultiSerialPackagePath_.empty()) {
			label += L" — " + loadString( IDS_INTEL_PACKAGE_SELECTED) ;
		}

		// 汎用署名INF用ZIPの明示選択が保持されていることをmenuへ示す。
		if( descriptor.id == GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID &&
		   !selectedGenericInfPackagePath_.empty()) {
			label += L" — " + loadString( IDS_INTEL_PACKAGE_SELECTED) ;
		}

		const UINT flags = MF_STRING | (enabled ? MF_CHECKED : MF_UNCHECKED) ;	// Check状態。
		static_cast<void>( AppendMenuW(
			menu, flags, PROVIDER_MENU_COMMAND_BASE + static_cast<UINT>( index), label.c_str())) ;
	}

	static_cast<void>( AppendMenuW( menu, MF_SEPARATOR, 0, nullptr)) ;
	const UINT coverageFlags =
		MF_STRING | (localCoverage_.empty() && controller_.scanMeasurement() == nullptr
						 ? MF_GRAYED
						 : MF_ENABLED) ;	// Dialog入口状態。
	static_cast<void>( AppendMenuW( menu, coverageFlags, LOCAL_COVERAGE_MENU_COMMAND,
								  loadString( IDS_LOCAL_COVERAGE_MENU).c_str())) ;
	appendIndexRefreshMenu( menu) ;

	RECT buttonBounds{} ;	// Screen座標のbutton矩形。
	// 表示位置を決定できない場合は作成済みmenuを解放して中止する。
	if( GetWindowRect( providerSourcesButton_, &buttonBounds) == FALSE) {
		DestroyMenu( menu) ;
		return ;
	}

	SetForegroundWindow( window_) ;
	const UINT command = TrackPopupMenu( menu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
										buttonBounds.left, buttonBounds.bottom, 0, window_,
										nullptr) ;	// 利用者が選択したProvider command。
	DestroyMenu( menu) ;
	// 到達件数の閲覧要求はProvider有効状態の切替として扱わない。
	if( command == LOCAL_COVERAGE_MENU_COMMAND) {
		showLocalCoverageDialog() ;
		return ;
	}

	// 通信結果の閲覧をProvider有効状態の切替へ変換しません。
	if( command == IDM_INDEX_REFRESH_DETAILS) {
		showIndexRefreshDetails() ;
		return ;
	}

	// 取消と範囲外commandをProvider選択へ変換しない。
	if( command < PROVIDER_MENU_COMMAND_BASE ||
	   command >= PROVIDER_MENU_COMMAND_BASE + descriptors.size()) {
		return ;
	}

	const std::size_t	index	   = command - PROVIDER_MENU_COMMAND_BASE ;	// 選択Provider index。
	const std::wstring &providerId = descriptors[index].id ;				// 切替対象stable ID。
	// 有効集合内の操作対象Providerの位置。末尾なら現在は無効である。
	const auto			enabled =
		std::find( enabledProviderIds_.begin(), enabledProviderIds_.end(), providerId) ;
	// 未有効のProviderは必要なfile選択を済ませてから有効にする。
	if( enabled == enabledProviderIds_.end()) {
		// 区分C Providerはfile選択を伴わない有効状態を作らない。
		if( providerId == INTEL_WIRELESS_PACKAGE_PROVIDER_ID &&
		   !selectUserPackage( IDS_INTEL_PACKAGE_SELECTION_NOTICE, IDS_INTEL_PACKAGE_DIALOG_TITLE,
							  IDS_INTEL_PACKAGE_FILTER_NAME, selectedIntelWirelessPackagePath_)) {
			return ;
		}

		// Prolific用ZIPの選択が完了しなければProviderを有効にしない。
		if( providerId == PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID &&
		   !selectUserPackage( IDS_PROLIFIC_PACKAGE_SELECTION_NOTICE,
							  IDS_PROLIFIC_PACKAGE_DIALOG_TITLE, IDS_PROLIFIC_PACKAGE_FILTER_NAME,
							  selectedProlificSerialPackagePath_)) {
			return ;
		}

		// Silicon Labs用ZIPの選択が完了しなければProviderを有効にしない。
		if( providerId == SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID &&
		   !selectUserPackage( IDS_SILABS_PACKAGE_SELECTION_NOTICE, IDS_SILABS_PACKAGE_DIALOG_TITLE,
							  IDS_SILABS_PACKAGE_FILTER_NAME,
							  selectedSiliconLabsSerialPackagePath_)) {
			return ;
		}

		// WCH serial用ZIPの選択が完了しなければProviderを有効にしない。
		if( providerId == WCH_SERIAL_PACKAGE_PROVIDER_ID &&
		   !selectUserPackage( IDS_WCH_PACKAGE_SELECTION_NOTICE, IDS_WCH_PACKAGE_DIALOG_TITLE,
							  IDS_WCH_PACKAGE_FILTER_NAME, selectedWchSerialPackagePath_)) {
			return ;
		}

		// WCH multi-serial用ZIPの選択が完了しなければProviderを有効にしない。
		if( providerId == WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID &&
		   !selectUserPackage( IDS_WCH_MULTI_PACKAGE_SELECTION_NOTICE,
							  IDS_WCH_MULTI_PACKAGE_DIALOG_TITLE, IDS_WCH_MULTI_PACKAGE_FILTER_NAME,
							  selectedWchMultiSerialPackagePath_)) {
			return ;
		}

		// 汎用署名INF用ZIPの選択が完了しなければProviderを有効にしない。
		if( providerId == GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID &&
		   !selectUserPackage( IDS_GENERIC_INF_SELECTION_NOTICE, IDS_GENERIC_INF_DIALOG_TITLE,
							  IDS_GENERIC_INF_FILTER_NAME, selectedGenericInfPackagePath_)) {
			return ;
		}

		enabledProviderIds_.push_back( providerId) ;
	} else {
		enabledProviderIds_.erase( enabled) ;
		// 選択元pathをscan session外へ不要に保持しない。
		if( providerId == INTEL_WIRELESS_PACKAGE_PROVIDER_ID) {
			selectedIntelWirelessPackagePath_.clear() ;
		}

		// Prolific Providerの無効化時に以前のZIP選択も破棄する。
		if( providerId == PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID) {
			selectedProlificSerialPackagePath_.clear() ;
		}

		// Silicon Labs Providerの無効化時に以前のZIP選択も破棄する。
		if( providerId == SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID) {
			selectedSiliconLabsSerialPackagePath_.clear() ;
		}

		// WCH serial Providerの無効化時に以前のZIP選択も破棄する。
		if( providerId == WCH_SERIAL_PACKAGE_PROVIDER_ID) {
			selectedWchSerialPackagePath_.clear() ;
		}

		// WCH multi-serial Providerの無効化時に以前のZIP選択も破棄する。
		if( providerId == WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID) {
			selectedWchMultiSerialPackagePath_.clear() ;
		}

		// 汎用署名INF Providerの無効化時に以前のZIP選択も破棄する。
		if( providerId == GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID) {
			selectedGenericInfPackagePath_.clear() ;
		}
	}

	updateProviderSourcesCaption() ;
	setStatus( loadString( IDS_PROVIDER_SETTING_CHANGED), false) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::selectUserPackage( const UINT noticeResourceId, const UINT titleResourceId,
								   const UINT filterResourceId, std::wstring &selectedPath)
{
	// 取得元に関する注意の確認を取り消した場合はfile選択へ進まない。
	if( MessageBoxW( window_, loadString( noticeResourceId).c_str(),
				   loadString( titleResourceId).c_str(), MB_OKCANCEL | MB_ICONINFORMATION) != IDOK) {
		return false ;
	}

	constexpr std::size_t MAXIMUM_PATH_CHARACTERS = 32768U ;	// 選択path buffer上限。
	constexpr wchar_t	  DEFAULT_EXTENSION[]	  = L"zip" ;	// 省略時に補う拡張子。
	// Dialogが選択pathを格納する、上限まで初期化済みの動的buffer。
	std::vector<wchar_t>  filePath( MAXIMUM_PATH_CHARACTERS, L'\0') ;
	const std::wstring	  dialogTitle = loadString( titleResourceId) ;	// Dialog title。
	std::wstring		  filter	  = loadString( filterResourceId) ;	// Filter表示名。
	filter.push_back( L'\0') ;
	filter += loadString( filterResourceId == IDS_GENERIC_INF_FILTER_NAME
							 ? IDS_GENERIC_INF_FILTER_PATTERN
							 : IDS_INTEL_PACKAGE_FILTER_PATTERN) ;
	filter.push_back( L'\0') ;
	filter.push_back( L'\0') ;

	OPENFILENAMEW dialog{} ;	// GetOpenFileNameWへ渡す一件選択条件。
	dialog.lStructSize	= sizeof( dialog) ;
	dialog.hwndOwner	= window_ ;
	dialog.lpstrFilter	= filter.c_str() ;
	dialog.nFilterIndex = 1U ;
	dialog.lpstrFile	= filePath.data() ;
	dialog.nMaxFile		= static_cast<DWORD>( filePath.size()) ;
	dialog.lpstrTitle	= dialogTitle.c_str() ;
	dialog.Flags		= OFN_DONTADDTORECENT | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR |
				   OFN_PATHMUSTEXIST ;
	dialog.lpstrDefExt = DEFAULT_EXTENSION ;
	// file選択が完了しなかった場合は取消とdialog障害を区別して終了する。
	if( GetOpenFileNameW( &dialog) == FALSE) {
		const DWORD dialogError = CommDlgExtendedError() ;	// 0は利用者取消、非0はdialog失敗。
		// 利用者による取消ではなくdialog障害の場合にだけ診断を表示する。
		if( dialogError != 0U) {
			const std::wstring message = formatResource( IDS_INTEL_PACKAGE_DIALOG_ERROR,
														// 失敗説明。
														std::to_wstring( dialogError)) ;
			MessageBoxW( window_, message.c_str(), loadString( IDS_ERROR_TITLE).c_str(),
						MB_OK | MB_ICONERROR) ;
		}

		return false ;
	}

	selectedPath.assign( filePath.data()) ;
	return !selectedPath.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatMeasurementCount( const CountMeasurement &measurement) const
{
	// 確定度ごとに値の有無を確認し、未計測を0として表示しない。
	switch( measurement.extent) {
		// 未計測には数値を付けず、0件の確定値と区別する。
		case MeasurementExtent::NOT_MEASURED:
			return loadString( IDS_MEASUREMENT_NOT_MEASURED) ;

		// 確定値は0を含めて数値だけを返す。
		case MeasurementExtent::EXACT:
			return measurement.value.has_value() ? std::to_wstring( measurement.value.value())
												 : loadString( IDS_MEASUREMENT_UNAVAILABLE) ;

		// 下限値は未確認範囲が残ることを文言で示す。
		case MeasurementExtent::LOWER_BOUND:
			return measurement.value.has_value()
					   ? formatResource( IDS_MEASUREMENT_LOWER_BOUND,
										std::to_wstring( measurement.value.value()))
					   : loadString( IDS_MEASUREMENT_UNAVAILABLE) ;

		// 取得不能と未知enumを成功または確定0へ変換しない。
		case MeasurementExtent::UNAVAILABLE:
			return loadString( IDS_MEASUREMENT_UNAVAILABLE) ;

		// 定義外の確定度も取得不能として表示し、値を推測しない。
		default:
			return loadString( IDS_MEASUREMENT_UNAVAILABLE) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatStageMeasurement( const StageDeviceCounts &measurement) const
{
	const std::wstring values =
		formatMeasurementCount( measurement.eligibleDeviceCount) + L" / " +
		formatMeasurementCount( measurement.queryCompletedDeviceCount) + L" / " +
		formatMeasurementCount( measurement.informationDeviceCount) + L" / " +
		formatMeasurementCount( measurement.applicableUpdateDeviceCount) + L" / " +
		// T／Q／R／A／I順。
		formatMeasurementCount( measurement.installReadyUpdateDeviceCount) ;
	return formatResource( IDS_MEASUREMENT_STAGES, values) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatMeasurementAcquisitions(
	const std::span<const MeasurementResource> resources) const
{
	std::uint64_t networkBodies{} ;		// 今回network本文を検証したresource数。
	std::uint64_t freshCaches{} ;		// 有効期間内cache本文を再検証したresource数。
	std::uint64_t revalidatedCaches{} ;	// 304でoriginを再検証したcache resource数。
	std::uint64_t unknown{} ;			// 取得経路未接続または定義外のresource数。
	// URLを表示せず、固定済み各resourceの実取得区分だけを数える。
	for( const MeasurementResource &resource : resources) {
		// 一resourceを実取得区分の一つだけへ分類する。
		switch( resource.acquisition) {
			// 今回取得したnetwork本文をcache利用と分けて数える。
			case MeasurementAcquisition::NETWORK_BODY:
				++networkBodies ;
				break ;

			// 有効期限内の検証済みcache利用を数える。
			case MeasurementAcquisition::FRESH_CACHE:
				++freshCaches ;
				break ;

			// 304で再検証したcache利用をfresh cacheと分けて数える。
			case MeasurementAcquisition::REVALIDATED_CACHE:
				++revalidatedCaches ;
				break ;

			// 未接続、複数resource用区分、非HTTP区分は不明として明示する。
			case MeasurementAcquisition::UNKNOWN:
				++unknown ;
				break ;

			// 一resourceに混在区分が来た場合も、取得元を推測せず不明へ数える。
			case MeasurementAcquisition::MIXED:
				++unknown ;
				break ;

			// 公式HTTP非該当のresourceはnetworkやcacheへ誤分類しない。
			case MeasurementAcquisition::NOT_APPLICABLE:
				++unknown ;
				break ;

			// 定義外の取得区分を既知経路へ補完しない。
			default:
				++unknown ;
				break ;
		}
	}

	const std::wstring values =
		std::to_wstring( networkBodies) + L" / " + std::to_wstring( freshCaches) + L" / " +
		// 固定表示順。
		std::to_wstring( revalidatedCaches) + L" / " + std::to_wstring( unknown) ;
	return formatResource( IDS_MEASUREMENT_ACQUISITIONS, values) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::showLocalCoverageDialog() const
{
	// 表示専用modeでは通常scanの失効履歴ではなく、専用の条件・全停止理由を表示する。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) {
		showMetadataSearchDetails() ;
		return ;
	}

	const ScanMeasurement *const snapshot =
		// Controllerがoperationへ照合したscan時点の計測。
		controller_.scanMeasurement() ;
	// 従来集計と新計測の両方がない場合だけ空dialogを表示しない。
	if( localCoverage_.empty() && snapshot == nullptr) {
		return ;
	}

	std::uint64_t deviceCount{} ;		// 全groupのpresent device合計。
	std::uint64_t intakeDeviceCount{} ;	// S63+調査対象groupのpresent device合計。
	std::uint64_t intakeGroupCount{} ;	// S63+調査対象のmanufacturer／class組合せ数。
	// Aggregateが検証したgroup件数を加算し、想定外overflow時は最大値で止める。
	for( const LocalCoverageEntry &entry : localCoverage_) {
		// device総数の加算が型の上限を超える場合は最大値に留める。
		if( entry.deviceCount > std::numeric_limits<std::uint64_t>::max() - deviceCount) {
			deviceCount = std::numeric_limits<std::uint64_t>::max() ;
		} else {
			deviceCount += entry.deviceCount ;
		}

		// 審査待ちまたは未識別でないgroupを受付待ち件数へ含めない。
		if( entry.reviewState != ManufacturerReviewState::PENDING_INTAKE &&
		   entry.reviewState != ManufacturerReviewState::UNIDENTIFIED) {
			continue ;
		}

		// 受付対象device数の加算が型の上限を超える場合は最大値に留める。
		if( entry.deviceCount > std::numeric_limits<std::uint64_t>::max() - intakeDeviceCount) {
			intakeDeviceCount = std::numeric_limits<std::uint64_t>::max() ;
		} else {
			intakeDeviceCount += entry.deviceCount ;
		}

		// 受付対象group数が最大値に達した後は加算して桁あふれさせない。
		if( intakeGroupCount != std::numeric_limits<std::uint64_t>::max()) {
			++intakeGroupCount ;
		}
	}

	std::vector<std::size_t> displayOrder( localCoverage_.size()) ;	// Dialog表示用group index。
	std::iota( displayOrder.begin(), displayOrder.end(), 0U) ;
	const auto reviewRank = []( const ManufacturerReviewState state) noexcept {
		// 審査待ちと未識別を先に確認できる表示順位へ変換する。
		switch( state) {
			// 審査受付待ちの maker を最初に表示する。
			case ManufacturerReviewState::PENDING_INTAKE:
				return 0U ;
			// 識別できない maker を審査待ちに続けて表示する。
			case ManufacturerReviewState::UNIDENTIFIED:
				return 1U ;
			// 審査済み maker は未解決の分類に続けて表示する。
			case ManufacturerReviewState::REVIEWED:
				return 2U ;
			// Platform 分類は maker 審査状態の後に表示する。
			case ManufacturerReviewState::PLATFORM:
				return 3U ;
		}

		return 0U ;
	} ; // S63+候補を先頭へ置く表示専用順位。
	// 未列挙状態、候補未到達、公式候補未到達、device数の順でintake候補を並べる。
	std::stable_sort(
		displayOrder.begin(), displayOrder.end(),
		[this, reviewRank]( const std::size_t leftIndex, const std::size_t rightIndex) {
			const LocalCoverageEntry &left			 = localCoverage_[leftIndex] ;		// 左比較対象。
			const LocalCoverageEntry &right			 = localCoverage_[rightIndex] ;		// 右比較対象。
			const unsigned int		  leftReviewRank = reviewRank( left.reviewState) ;	// 左審査順位。
			const unsigned int rightReviewRank = reviewRank( right.reviewState) ;		// 右審査順位。
			// 審査状態が異なるgroupは要確認の状態を優先して並べる。
			if( leftReviewRank != rightReviewRank) {
				return leftReviewRank < rightReviewRank ;
			}

			const bool leftUnreached  = left.candidateDeviceCount == 0 ;	// 左に候補到達なし。
			const bool rightUnreached = right.candidateDeviceCount == 0 ;	// 右に候補到達なし。
			// 同じ審査順位では候補に未到達のgroupを先に表示する。
			if( leftUnreached != rightUnreached) {
				return leftUnreached ;
			}

			const bool leftWithoutOfficial =
				// 左に公式候補到達なし。
				left.officialCandidateDeviceCount == 0 ;
			const bool rightWithoutOfficial =
				// 右に公式候補到達なし。
				right.officialCandidateDeviceCount == 0 ;
			// それまでの順位が同じ場合は公式候補のないgroupを先に表示する。
			if( leftWithoutOfficial != rightWithoutOfficial) {
				return leftWithoutOfficial ;
			}

			// 確認優先度が同じgroupはdevice件数の多い順に並べる。
			if( left.deviceCount != right.deviceCount) {
				return left.deviceCount > right.deviceCount ;
			}

			// 件数まで同じgroupはメーカー名順で安定した表示順を作る。
			if( left.manufacturer != right.manufacturer) {
				return left.manufacturer < right.manufacturer ;
			}

			return left.driverClass < right.driverClass ;
		}) ;

	const std::wstring unknown = loadString( IDS_VALUE_UNKNOWN) ;	// 欠損表示名の代替文字列。
	std::wstring	   details ;									// Provider・group別件数の展開表示。
	// 新計測が受理されている場合はProvider別のscope、段階、record、実取得区分を先に示す。
	if( snapshot != nullptr) {
		// Scan時registryの全reportを順に表示し、無効・未接続も0件と区別する。
		for( const ProviderScanReport &report : providerReports_) {
			// Top-levelと一括検証されたProvider計測だけを表示する。
			if( !report.coverage.measurement.has_value()) {
				continue ;
			}

			const ProviderMeasurement &providerMeasurement =
				// 現在表示するProviderの所有値。
				report.coverage.measurement.value() ;
			std::wstring scope ;	// 個別query証拠の範囲を色に依存せず示す文字列。
			// Providerが発行したscopeを対応する日本語resourceへ変換する。
			switch( providerMeasurement.scope) {
				// 未接続adapterは件数0ではなくscope未接続として表示する。
				case MeasurementScope::LEGACY_UNKNOWN:
					scope = loadString( IDS_MEASUREMENT_SCOPE_UNKNOWN) ;
					break ;

				// Device別queryの完了証拠をsystem queryと区別する。
				case MeasurementScope::DEVICE_QUERY:
					scope = loadString( IDS_MEASUREMENT_SCOPE_DEVICE) ;
					break ;

				// System全体queryは個別検索完了を配賦しない範囲として示す。
				case MeasurementScope::SYSTEM_QUERY:
					scope = loadString( IDS_MEASUREMENT_SCOPE_SYSTEM) ;
					break ;

				// 定義外値は未接続として安全側に表示する。
				default:
					scope = loadString( IDS_MEASUREMENT_SCOPE_UNKNOWN) ;
					break ;
			}

			const std::wstring recordCounts =
				formatMeasurementCount( providerMeasurement.unmatchedCandidateCount) + L" / " +
				formatMeasurementCount( providerMeasurement.informationRecordCount) + L" / " +
				formatMeasurementCount(
					providerMeasurement.unmatchedInformationRecordCount) ;	// 固定表示順の三件数。
			details += L"• " + makeSingleLine( report.descriptor.displayName) + L"\r\n  " +
					   formatResource( IDS_MEASUREMENT_SCOPE_OUTCOME,
									  scope + L" / " + std::wstring( outcomeName( report.outcome))) +
					   L"\r\n  " + formatStageMeasurement( providerMeasurement.devices) + L"\r\n  " +
					   formatResource( IDS_MEASUREMENT_RECORDS, recordCounts) + L"\r\n" ;
			// 公式HTTPの取得根拠があるProviderだけに実利用区分を追記する。
			if( !providerMeasurement.resources.empty()) {
				details +=
					L"  " + formatMeasurementAcquisitions( providerMeasurement.resources) + L"\r\n" ;
			}
		}

		// Provider内訳とmanufacturer／class内訳の境界を空行で区切る。
		if( !details.empty() && !localCoverage_.empty()) {
			details += L"\r\n" ;
		}
	}

	const std::size_t displayCount =
		// 実表示group数。
		std::min( displayOrder.size(), MAXIMUM_COVERAGE_DIALOG_ENTRIES) ;
	// 外部propertyを一行化・上限化し、取得元別件数を各group一行で表示する。
	for( std::size_t index = 0; index < displayCount; ++index) {
		const LocalCoverageEntry &entry =
			localCoverage_[displayOrder[index]] ;	// 現在表示するcoverage group。
		std::wstring manufacturer =
			// 製造元。
			makeSingleLine( entry.manufacturer.empty() ? unknown : entry.manufacturer) ;
		std::wstring driverClass =
			// Class名。
			makeSingleLine( entry.driverClass.empty() ? unknown : entry.driverClass) ;
		std::wstring reviewState ;	// Roadmap審査状態を色に依存せず示すlabel。
		// 審査状態ごとのresourceを選び、未識別と審査済みを区別する。
		switch( entry.reviewState) {
			// 審査済み maker の状態を対応 resource で表示する。
			case ManufacturerReviewState::REVIEWED:
				reviewState = loadString( IDS_COVERAGE_REVIEWED) ;
				break ;

			// Platform 分類を maker 審査済みと区別して表示する。
			case ManufacturerReviewState::PLATFORM:
				reviewState = loadString( IDS_COVERAGE_PLATFORM) ;
				break ;

			// 審査受付待ちを未対応の一般表示と区別する。
			case ManufacturerReviewState::PENDING_INTAKE:
				reviewState = loadString( IDS_COVERAGE_PENDING_INTAKE) ;
				break ;

			// Maker 未識別を対応済みと誤表示しない。
			case ManufacturerReviewState::UNIDENTIFIED:
				reviewState = loadString( IDS_COVERAGE_UNIDENTIFIED) ;
				break ;
		}

		// 長いメーカー表示名は上限で省略し、dialogの情報量を制限する。
		if( manufacturer.size() > MAXIMUM_COVERAGE_LABEL_CHARACTERS) {
			manufacturer.resize( MAXIMUM_COVERAGE_LABEL_CHARACTERS) ;
			manufacturer += L"…" ;
		}

		// 長いclass表示名は上限で省略し、dialogの情報量を制限する。
		if( driverClass.size() > MAXIMUM_COVERAGE_LABEL_CHARACTERS) {
			driverClass.resize( MAXIMUM_COVERAGE_LABEL_CHARACTERS) ;
			driverClass += L"…" ;
		}

		const std::wstring counts =	// Device、全候補、公式、利用者選択、WUA、localの順。
			std::to_wstring( entry.deviceCount) + L" / " +
			std::to_wstring( entry.candidateDeviceCount) + L" / " +
			std::to_wstring( entry.officialCandidateDeviceCount) + L" / " +
			std::to_wstring( entry.userSelectedCandidateDeviceCount) + L" / " +
			std::to_wstring( entry.managedCandidateDeviceCount) + L" / " +
			std::to_wstring( entry.localCandidateDeviceCount) + L" / 索引 " +
			std::to_wstring( entry.indexedCandidateDeviceCount) + L" / 索引参照 " +
			std::to_wstring( entry.indexedReferenceDeviceCount) ;
		details += L"• [" + reviewState + L"] " + manufacturer + L" / " + driverClass + L"\r\n  " +
				   formatResource( IDS_LOCAL_COVERAGE_COUNTS, counts) + L"\r\n" ;
		// Scan時点の同じgroupに新計測がある場合だけ段階別network到達を追記する。
		if( entry.measurement.has_value()) {
			details += L"  " +
					   formatResource( IDS_MEASUREMENT_GROUP,
									  formatStageMeasurement( entry.measurement->combined)) +
					   L"\r\n" ;
		}
	}

	// 表示上限で省いたgroup数を示し、一覧が全件と誤認されないようにする。
	if( displayOrder.size() > displayCount) {
		details += L"\r\n" + formatResource( IDS_LOCAL_COVERAGE_TRUNCATED,
											std::to_wstring( displayOrder.size() - displayCount)) ;
	}

	const std::wstring summaryCounts =	// Present device数とmanufacturer／class group数。
		std::to_wstring( deviceCount) + L" / " + std::to_wstring( localCoverage_.size()) ;
	const std::wstring intakeCounts =	// S63+対象device数とmanufacturer／class group数。
		std::to_wstring( intakeDeviceCount) + L" / " + std::to_wstring( intakeGroupCount) ;
	std::wstring measurementSummary ;	// Scan時点の全体計測と失効状態を示す本文。
	// Controllerが受理したsnapshotをversion、operation、sessionへ明示的に拘束して表示する。
	if( snapshot != nullptr) {
		const std::wstring snapshotIds = snapshot->context.applicationVersion + L" / " +
										 std::to_wstring( snapshot->context.operationId) + L" / " +
										 // 固定表示順のsnapshot識別値。
										 std::to_wstring( snapshot->context.scanSessionId) ;
		const std::wstring inventoryCounts =
			formatMeasurementCount( snapshot->inventory.enumeratedDeviceCount) + L" / " +
			formatMeasurementCount( snapshot->inventory.representedDeviceCount) + L" / " +
			// OS／D／差。
			formatMeasurementCount( snapshot->inventory.unrepresentedDeviceCount) ;
		measurementSummary = formatResource( IDS_MEASUREMENT_SNAPSHOT, snapshotIds) + L"\r\n" +
							 formatResource( IDS_MEASUREMENT_INVENTORY, inventoryCounts) + L"\r\n" +
							 formatResource( IDS_MEASUREMENT_NETWORK_COMBINED,
											formatStageMeasurement( snapshot->network.combined)) +
							 L"\r\n" +
							 formatResource( IDS_MEASUREMENT_NETWORK_MANAGED,
											formatStageMeasurement( snapshot->network.managed)) +
							 L"\r\n" +
							 formatResource( IDS_MEASUREMENT_NETWORK_OFFICIAL,
											formatStageMeasurement( snapshot->network.official)) +
							 L"\r\n\r\n" + loadString( IDS_MEASUREMENT_EXPLANATION) ;
		// Installまたは不正準備でsessionが失効した値を現在件数として再利用させない。
		if( controller_.scanSessionId() == 0U) {
			measurementSummary += L"\r\n" + loadString( IDS_MEASUREMENT_EXPIRED) ;
		}
	} else {
		measurementSummary = loadString( IDS_MEASUREMENT_NO_SNAPSHOT) ;
	}

	const std::wstring content =
		formatResource( IDS_LOCAL_COVERAGE_SUMMARY, summaryCounts) + L"\r\n" +
		formatResource( IDS_LOCAL_COVERAGE_INTAKE_SUMMARY, intakeCounts) + L"\r\n\r\n" +
		measurementSummary + L"\r\n\r\n" +
		// Dialog要約。
		(localCoverage_.empty() ? loadString( IDS_LOCAL_COVERAGE_EMPTY)
								: loadString( IDS_LOCAL_COVERAGE_EXPLANATION)) ;
	const std::wstring title = loadString( IDS_APP_TITLE) ;	// Task DialogのWindow title。
	const std::wstring instruction =
		// Task Dialogの主見出し。
		loadString( IDS_LOCAL_COVERAGE_TITLE) ;
	const std::wstring expandText =
		// 詳細展開buttonのcaption。
		loadString( IDS_LOCAL_COVERAGE_EXPAND) ;
	TASKDIALOGCONFIG dialog{} ;	// Common Controlsが本呼出し中だけ参照するdialog設定。
	dialog.cbSize				  = sizeof( dialog) ;
	dialog.hwndParent			  = window_ ;
	dialog.hInstance			  = instance_ ;
	dialog.dwFlags				  = TDF_SIZE_TO_CONTENT ;
	dialog.dwCommonButtons		  = TDCBF_OK_BUTTON ;
	dialog.pszWindowTitle		  = title.c_str() ;
	dialog.pszMainIcon			  = TD_INFORMATION_ICON ;
	dialog.pszMainInstruction	  = instruction.c_str() ;
	dialog.pszContent			  = content.c_str() ;
	dialog.pszExpandedInformation = details.c_str() ;
	dialog.pszExpandedControlText = expandText.c_str() ;
	int			  selectedButton{} ;	// Task Dialogが返すcommon button ID。
	const HRESULT taskDialogResult =
		// Dialog表示結果。
		TaskDialogIndirect( &dialog, &selectedButton, nullptr, nullptr) ;
	static_cast<void>( selectedButton) ;
	// TaskDialogを表示できない環境では同じ説明を標準message boxへ渡す。
	if( FAILED( taskDialogResult)) {
		const std::wstring fallback = content + L"\r\n\r\n" + details ;	// 互換fallback本文。
		MessageBoxW( window_, fallback.c_str(), instruction.c_str(), MB_OK | MB_ICONINFORMATION) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanOptions MainWindow::currentScanOptions() const
{
	ScanOptions options{.useDefaultProviders = false,
						.enabledProviderIds	 = enabledProviderIds_} ;	// 次回scan設定。
	const bool	intelProviderEnabled =									// Intel区分C Providerが次回scan対象ならtrue。
		std::find( enabledProviderIds_.begin(), enabledProviderIds_.end(),
				  INTEL_WIRELESS_PACKAGE_PROVIDER_ID) != enabledProviderIds_.end() ;
	// UI操作で成立させたProvider/fileの一対一関係だけをworkerへ渡す。
	if( intelProviderEnabled && !selectedIntelWirelessPackagePath_.empty()) {
		options.userSelectedFiles.push_back(
			{.providerId = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
			 .path		 = selectedIntelWirelessPackagePath_}) ;
	}

	const bool prolificProviderEnabled =	// Prolific区分C Providerが次回scan対象ならtrue。
		std::find( enabledProviderIds_.begin(), enabledProviderIds_.end(),
				  PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID) != enabledProviderIds_.end() ;
	// 有効かつZIP選択済みのProlific Providerにだけfile設定を渡す。
	if( prolificProviderEnabled && !selectedProlificSerialPackagePath_.empty()) {
		options.userSelectedFiles.push_back(
			{.providerId = std::wstring( PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID),
			 .path		 = selectedProlificSerialPackagePath_}) ;
	}

	const bool siliconLabsProviderEnabled =	// Silicon Labs区分Cが次回scan対象ならtrue。
		std::find( enabledProviderIds_.begin(), enabledProviderIds_.end(),
				  SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID) != enabledProviderIds_.end() ;
	// 有効かつZIP選択済みのSilicon Labs Providerにだけfile設定を渡す。
	if( siliconLabsProviderEnabled && !selectedSiliconLabsSerialPackagePath_.empty()) {
		options.userSelectedFiles.push_back(
			{.providerId = std::wstring( SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID),
			 .path		 = selectedSiliconLabsSerialPackagePath_}) ;
	}

	const bool wchProviderEnabled =	// WCH区分C Providerが次回scan対象ならtrue。
		std::find( enabledProviderIds_.begin(), enabledProviderIds_.end(),
				  WCH_SERIAL_PACKAGE_PROVIDER_ID) != enabledProviderIds_.end() ;
	// 有効かつZIP選択済みのWCH serial Providerにだけfile設定を渡す。
	if( wchProviderEnabled && !selectedWchSerialPackagePath_.empty()) {
		options.userSelectedFiles.push_back(
			{.providerId = std::wstring( WCH_SERIAL_PACKAGE_PROVIDER_ID),
			 .path		 = selectedWchSerialPackagePath_}) ;
	}

	const bool wchMultiProviderEnabled =	// WCH CH343SER Providerが次回scan対象ならtrue。
		std::find( enabledProviderIds_.begin(), enabledProviderIds_.end(),
				  WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID) != enabledProviderIds_.end() ;
	// 有効かつZIP選択済みのWCH multi-serial Providerにだけfile設定を渡す。
	if( wchMultiProviderEnabled && !selectedWchMultiSerialPackagePath_.empty()) {
		options.userSelectedFiles.push_back(
			{.providerId = std::wstring( WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID),
			 .path		 = selectedWchMultiSerialPackagePath_}) ;
	}

	const bool genericProviderEnabled =	// 汎用区分C Providerが次回scan対象ならtrue。
		std::find( enabledProviderIds_.begin(), enabledProviderIds_.end(),
				  GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID) != enabledProviderIds_.end() ;
	// 有効かつZIP選択済みの汎用署名INF Providerにだけfile設定を渡す。
	if( genericProviderEnabled && !selectedGenericInfPackagePath_.empty()) {
		options.userSelectedFiles.push_back(
			{.providerId = std::wstring( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
			 .path		 = selectedGenericInfPackagePath_}) ;
	}

	return options ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::updateProviderSourcesCaption() const
{
	// 取得元buttonの作成前には表示更新を行わない。
	if( providerSourcesButton_ == nullptr) {
		return ;
	}

	// 専用modeの結果閲覧buttonを通常scanの有効集合と誤表示しない。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) {
		SetWindowTextW( providerSourcesButton_, loadString( IDS_METADATA_RESULT_BUTTON).c_str()) ;
		return ;
	}

	// 有効数と登録総数を併記する、取得元ボタンの表示文字列。
	const std::wstring caption = loadString( IDS_PROVIDER_SOURCES) + L" (" +
								 std::to_wstring( enabledProviderIds_.size()) + L"/" +
								 std::to_wstring( builtInProviderDescriptors().size()) + L")" ;
	SetWindowTextW( providerSourcesButton_, caption.c_str()) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::providerStateText( const ProviderScanState state) const
{
	// 無効・対象外・候補なし・失敗を異なる表示文へ変換する。
	switch( state) {
		// 無効 Provider は未検索として表示する。
		case ProviderScanState::DISABLED:
			return loadString( IDS_PROVIDER_DISABLED) ;
		// 対象外は検索失敗や候補なしと区別して表示する。
		case ProviderScanState::NOT_APPLICABLE:
			return loadString( IDS_PROVIDER_NOT_APPLICABLE) ;
		// 候補なしを専用表示にし、最新版保証とは扱わない。
		case ProviderScanState::NO_CANDIDATES:
			return loadString( IDS_PROVIDER_NO_CANDIDATES) ;
		// 候補がある Provider を専用 resource で表示する。
		case ProviderScanState::CANDIDATES_AVAILABLE:
			return loadString( IDS_PROVIDER_CANDIDATES) ;
		// Metadata確定後のpayload未取得を候補なしと区別する。
		case ProviderScanState::PAYLOAD_NOT_APPROVED:
			return loadString( IDS_PROVIDER_PAYLOAD_NOT_APPROVED) ;
		// 制限または状態不明回線の未許可を検索失敗と区別する。
		case ProviderScanState::NETWORK_NOT_APPROVED:
			return loadString( IDS_PROVIDER_NETWORK_NOT_APPROVED) ;
		// 検索失敗を候補なしの表示に置き換えない。
		case ProviderScanState::FAILURE:
			return loadString( IDS_PROVIDER_FAILED) ;
		// Metadata 拒否を通信失敗と区別して表示する。
		case ProviderScanState::METADATA_REJECTED:
			return loadString( IDS_PROVIDER_METADATA_REJECTED) ;
		// 取得元の根拠拒否を専用状態として表示する。
		case ProviderScanState::SOURCE_REJECTED:
			return loadString( IDS_PROVIDER_SOURCE_REJECTED) ;
		// Payload の取得失敗を検索結果の空と区別する。
		case ProviderScanState::DOWNLOAD_FAILED:
			return loadString( IDS_PROVIDER_DOWNLOAD_FAILED) ;
		// 内容監査の拒否を取得成功とは別に表示する。
		case ProviderScanState::CONTENT_REJECTED:
			return loadString( IDS_PROVIDER_CONTENT_REJECTED) ;
	}

	return loadString( IDS_PROVIDER_FAILED) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::beginScan()
{
	ScanOptions options = currentScanOptions() ;	// 今回のProvider範囲と一scan承認snapshot。
	// 公式networkのない集合へ無関係な通信承認を発行せず、元registryの選択境界を維持します。
	const bool	officialNetworkSelected =
		std::ranges::any_of( builtInProviderDescriptors(), [&]( const auto &descriptor) {
			return isProviderEnabled( options, descriptor) &&
				   (descriptor.capabilities &
					capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0U ;
		}) ; // 索引・Storeのlocal結合と公式networkを区別します。
	// 検索操作は公式metadataの照会だけを許可し、payload取得とEULA同意を含めません。
	if( officialNetworkSelected) {
		OfficialDiscoveryScanApproval approval ;	// 固定予算・非従量回線の既存制限を維持します。
		approval.inspectionPermission	  = OfficialDiscoveryInspectionPermission::METADATA_ONLY ;
		options.officialDiscoveryApproval = approval ;
	}

	const BeginResult begin = controller_.beginScan() ;	// Scan開始の受付結果。
	// 状態機械が開始を拒否したscanをworkerへ送らない。
	if( !begin.accepted) {
		return ;
	}

	DiagnosticRecord diagnostic ;	// 開始受付の元状態と固定設定だけです。
	diagnostic.event	 = DiagnosticEvent::OPERATION_STARTED ;
	diagnostic.operation = begin.operationId ;
	diagnostic.status	 = static_cast<std::int32_t>( controller_.state()) ;
	recordLocalDiagnostic( diagnostic) ;
	// 同scanのcanonical Provider有効設定だけを記録します。
	for( const auto &descriptor : builtInProviderDescriptors()) {
		DiagnosticRecord provider ;	// 名称や探索条件本文を記録しません。
		provider.event	   = DiagnosticEvent::PROVIDER_CONFIGURATION ;
		provider.provider  = DiagnosticProvider::fromId( descriptor.id) ;
		provider.operation = begin.operationId ;
		provider.add( DiagnosticField::ENABLED, isProviderEnabled( options, descriptor)) ;
		recordLocalDiagnostic( provider) ;
	}

	// UI状態機械が発行した同じIDへ一scan承認を結合し、worker側で再照合する。
	if( options.officialDiscoveryApproval) {
		options.officialDiscoveryApproval->operationId = begin.operationId ;
	}

	hardwareRefresh_.reset() ;
	preparationApproval_	   = {} ;
	preparationDisplaySession_ = 0U ;
	preparationDisplayBindings_.clear() ;
	treeClassExpansion_.clear() ;
	preparationResultText_.clear() ;
	indexScanSummary_		 = {} ;
	indexPreparationSummary_ = {} ;
	providerReports_.clear() ;
	updateMetadataSearchColumns() ;
	updateProviderSourcesCaption() ;
	candidates_.clear() ;
	candidateSelected_.clear() ;
	localCoverage_.clear() ;
	scanOutcome_ = OutcomeCode::NOT_STARTED ;
	candidateItems_.clear() ;
	candidateRowIndexes_.clear() ;
	treeRows_.clear() ;
	candidateResultTexts_.clear() ;
	TreeView_DeleteAllItems( updateTree_) ;
	setStatus( loadString( IDS_STATUS_SCANNING), true) ;
	updateCommandState() ;

	// workerへscanを登録できない場合は開始済みUI状態を失敗完了へ戻す。
	if( worker_ == nullptr || !worker_->requestScan( begin.operationId, std::move( options))) {
		WorkerEvent failure ;	// Queue登録失敗を状態機械へ返すsynthetic完了event。
		failure.kind		= WorkerEventKind::SCAN_COMPLETED ;
		failure.operationId = begin.operationId ;
		failure.scanResult	= {.outcome = OutcomeCode::FAILURE,
							   .error	= static_cast<NativeError>( E_UNEXPECTED)} ;
		processScanCompleted( failure) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::handleScanCommand()
{
	// Modal確認、終了待ち、Window終了開始後の合成commandを新しい操作へ変換しない。
	if( closing_ || preparationReviewOpen_ || metadataReviewOpen_ || closeAfterScan_) {
		return ;
	}

	const ApplicationState state = controller_.state() ;	// 通常scanの開始または取消し判定状態。
	// 通常検索に続く取得も同じ主操作で協調取消しし、別の取得入口を要求しない。
	if( state == ApplicationState::PREPARING) {
		handlePreparationCommand() ;
		return ;
	}

	// 取得取消し完了まで別の検索を開始しない。
	if( state == ApplicationState::CANCELLING_PREPARATION) {
		return ;
	}

	// 同じ通常scan中の開始buttonは新操作ではなく協調取消しへ切り替える。
	if( controller_.scanPurpose() == ScanPurpose::STANDARD && state == ApplicationState::SCANNING) {
		cancelScan() ;
		return ;
	}

	// 取消し待ちを重ねず、その他の排他条件は状態機械の開始検証へ委ねる。
	if( state == ApplicationState::CANCELLING_SCAN) {
		return ;
	}

	beginScan() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::cancelScan()
{
	const OperationId operationId =
		// 同operationだけの取消し対象。
		controller_.activeOperationId() ;
	// 通常scanの実行中または既に取消し待ちの場合だけ表示と要求を更新する。
	if( controller_.scanPurpose() != ScanPurpose::STANDARD ||
	   (controller_.state() != ApplicationState::SCANNING &&
		controller_.state() != ApplicationState::CANCELLING_SCAN)) {
		return ;
	}

	continueInstallAfterPreparation_ = false ;

	// 完了eventがqueueにある場合も受信までWindowを維持し、取消し要求を同じIDへ限定する。
	if( worker_ != nullptr) {
		static_cast<void>( worker_->requestScanCancel( operationId)) ;
	}

	static_cast<void>( controller_.markScanCancelling( operationId)) ;
	SetWindowTextW( status_, loadString( IDS_SCAN_CANCELLING).c_str()) ;
	InvalidateRect( status_, nullptr, TRUE) ;
	updateCommandState() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::beginInstall()
{
	// 処理中・modal中・終了中に別のInstall意図を重ねません。
	if( closing_ || preparationReviewOpen_ || metadataReviewOpen_ ||
	   (controller_.state() != ApplicationState::SCAN_READY &&
		controller_.state() != ApplicationState::COMPLETED &&
		controller_.state() != ApplicationState::FAILURE &&
		controller_.state() != ApplicationState::IDLE)) {
		return ;
	}

	// 利用者が選択したcandidate index群。
	const std::vector<std::size_t> checkedIndexes = checkedCandidateIndexes() ;
	recordInstallSelectionDiagnostics( controller_.activeOperationId(), candidates_, checkedIndexes,
									  false) ;
	// 選択が空の場合は対象の明示選択を促し、install確認へ進まない。
	if( checkedIndexes.empty()) {
		MessageBoxW( window_, loadString( IDS_SELECTION_REQUIRED).c_str(),
					loadString( IDS_ERROR_TITLE).c_str(), MB_OK | MB_ICONINFORMATION) ;
		return ;
	}

	// 新たなInstall操作で以前の継続意図を再利用しません。
	continueInstallAfterPreparation_ = false ;

	// 未取得を含む選択は実導入APIへ直接渡さず、元targetの取得・検査へ進めます。
	if( std::ranges::any_of( checkedIndexes,
						   [&]( const auto index) { return !candidates_[index].installable ; })) {
		beginInstallPreparation( checkedIndexes) ;
		return ;
	}

	std::vector<std::wstring> identities ;	// Providerへ渡す選択済みopaque identity群。
	identities.reserve( checkedIndexes.size()) ;
	std::unordered_map<std::wstring, std::wstring> currentVersions ;	// Device別の現在版。

	// 現在使用中の行だけをdeviceへ対応付け、確認画面で推測せず版遷移を表示する。
	for( const UpdateCandidate &candidate : candidates_) {
		// opaque deviceと結び付いた現在行からだけ比較用の現在版を取得する。
		if( candidate.current && !candidate.deviceIdentity.empty()) {
			currentVersions.try_emplace( candidate.deviceIdentity, candidate.version) ;
		}
	}

	// 対象一覧と同意事項を含む最終確認文。
	std::wstring confirmation =
		formatResource( IDS_CONFIRM_PREFIX, std::to_wstring( checkedIndexes.size())) ;
	bool includesDowngrade{} ;					// trueの場合は旧版切替の追加警告を表示する。
	bool includesComponentGeneric{} ;			// trueの場合はOEM未検証候補の警告を表示する。
	bool includesRelaxedDiscovery{} ;			// trueの場合は探索区分B／Cの警告を表示する。
	bool includesAsixClientNotice{} ;			// ASIX候補選択時は通信断と復旧操作を確認する。
	bool includesIntelEthernetServerNotice{} ;	// trueの場合はServer NIC固有警告を表示する。
	bool includesOfficialInstaller{} ;			// driver導入完了とは異なる対話引継ぎの警告です。
	bool invalidConfirmation{} ;				// trueの場合はProviderまたは操作を安全に説明できない。

	bool includesUnacceptedEula{} ;		// 既存Providerの未受諾規約には明示判断を保持します。
	bool includesRequiredComponents{} ;	// 新しい必要構成の説明を一度だけ行います。

	// Index順に全選択を検証し、先頭上限件だけを確認dialogへ列挙する。
	for( std::size_t displayIndex = 0; displayIndex < checkedIndexes.size(); ++displayIndex) {
		// 現在確認文へ追加している選択候補。
		const UpdateCandidate &candidate = candidates_[checkedIndexes[displayIndex]] ;
		UINT actionResourceId{} ;	// 検証済みDriverActionに対応する表示resource ID。
		// 候補の操作種別を確認文へ変換し、未定義の操作は拒否対象にする。
		switch( candidate.action) {
			// 通常更新の確認には更新用の操作名称を使用する。
			case DriverAction::UPDATE:
				actionResourceId = IDS_ACTION_UPDATE ;
				break ;

			// 同版等の再導入は通常更新と別の名称で確認する。
			case DriverAction::REINSTALL:
				actionResourceId = IDS_ACTION_REINSTALL ;
				break ;

			// 旧版への切替には専用の警告名称を使用する。
			case DriverAction::DOWNGRADE:
				actionResourceId = IDS_ACTION_DOWNGRADE ;
				break ;

			// 同scan署名索引のREADY私有bindingに限って初回確認へ接続します。
			case DriverAction::INITIAL_INSTALL:
				// 未対応Providerの初回表示を実行許可へ読み替えません。
				if( candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
				   candidate.discoveryBasis ==
					   CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
				   candidate.assessment && isCandidateAssessmentReady( *candidate.assessment)) {
					actionResourceId = IDS_ACTION_INITIAL_INSTALL ;
				} else {
					invalidConfirmation = true ;
				}

				break ;

			// 操作なしの候補は導入確認の不正対象として共通拒否へ進む。
			case DriverAction::NONE:
			// 定義外の操作分類を導入確認へ受理しない。
			default:
				invalidConfirmation = true ;
				break ;
		}

		// Stable Provider IDだけから追加注意文を解決し、未知IDを警告なしで続行しない。
		const auto installNotice = providerInstallNotice( candidate.providerId) ;
		// Providerのinstall注意区分を解決できない候補は確認成立としない。
		if( !installNotice.has_value()) {
			invalidConfirmation = true ;
		} else {
			// 解決済み注意区分から必要なClient・Server専用警告を集約する。
			switch( *installNotice) {
				// 追加 notice がない候補では系列固有警告を追加しない。
				case InstallNoticeKind::NONE:
					break ;

				// ASIX client NIC の導入には専用注意事項を含める。
				case InstallNoticeKind::ASIX_CLIENT_NIC:
					includesAsixClientNotice = true ;
					break ;

				// Intel Server Ethernet の導入には専用注意事項を含める。
				case InstallNoticeKind::INTEL_ETHERNET_SERVER:
					includesIntelEthernetServerNotice = true ;
					break ;

				// 未知の notice を無警告へ読み替えず確認を拒否する。
				default:
					invalidConfirmation = true ;
					break ;
			}
		}

		// 不完全な説明で利用者へ同意を求めず、選択集合全体を拒否する。
		if( invalidConfirmation) {
			break ;
		}

		identities.push_back( candidate.identity) ;
		includesUnacceptedEula =
			includesUnacceptedEula ||
			(candidate.providerId == WINDOWS_UPDATE_PROVIDER_ID && !candidate.eulaAccepted) ;
		includesRequiredComponents = includesRequiredComponents ||
									 candidate.requiredExtensionCount != 0U ||
									 candidate.requiredDriverComponentCount != 0U ;
		// 明示必要構成を上限によるtitle省略とは独立に確認します。
		if( candidate.requiredExtensionCount || candidate.requiredDriverComponentCount) {
			confirmation += loadString( IDS_INDEX_REQUIRED_PLAN) + L"\r\n" +
							loadString( IDS_INDEX_ROLE_EXTENSION) + L": " +
							std::to_wstring( candidate.requiredExtensionCount) + L" | " +
							loadString( IDS_INDEX_ROLE_COMPONENT) + L": " +
							std::to_wstring( candidate.requiredDriverComponentCount) + L"\r\n" ;
		}

		includesOfficialInstaller =
			includesOfficialInstaller ||
			(candidate.assessment &&
			 candidate.assessment->installMethod == CandidateInstallMethod::OFFICIAL_INSTALLER) ;
		includesDowngrade = includesDowngrade || candidate.action == DriverAction::DOWNGRADE ;
		includesComponentGeneric =
			includesComponentGeneric ||
			candidate.defaultPreference == CandidateDefaultPreference::COMPONENT_GENERIC ;
		includesRelaxedDiscovery =
			includesRelaxedDiscovery ||
			candidate.discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ||
			candidate.discoveryBasis == CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ||
			candidate.discoveryBasis == CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
		// 確認対象の詳細表示を上限件数に制限し、過大なdialogを作らない。
		if( displayIndex < MAXIMUM_CONFIRMATION_TITLES) {
			const std::wstring unknown = loadString( IDS_VALUE_UNKNOWN) ;	// 欠損値の代替表示。
			// 同じopaque deviceに現在行がない場合は未照合と明示し、版を推測しない。
			const auto		   currentVersion = currentVersions.find( candidate.deviceIdentity) ;
			// 確認dialogへ表示する現在版。未照合と版数不明を区別した一行表現。
			const std::wstring currentVersionText =
				currentVersion == currentVersions.end()
					? loadString( IDS_CURRENT_VERSION_UNMATCHED)
					: makeSingleLine( currentVersion->second.empty() ? unknown
																	: currentVersion->second) ;
			// 確認対象の論理取得元名称。
			std::wstring source =
				makeSingleLine( candidate.sourceName.empty() ? unknown : candidate.sourceName) ;
			const std::wstring discovery =	// 公式候補の場合だけ表示する探索区分。
				formatCandidateDiscoveryBasis( candidate) ;
			// 補足の検出経路がある候補には取得元と併せて表示する。
			if( !discovery.empty()) {
				source += L" / " + discovery ;
			}

			confirmation +=
				L"• " + makeSingleLine( candidate.model.empty() ? unknown : candidate.model) +
				L" | " + loadString( IDS_CURRENT_VERSION_LABEL) + L": " + currentVersionText +
				L" → " + makeSingleLine( candidate.version.empty() ? unknown : candidate.version) +
				L" | " + loadString( IDS_CONFIRM_ACTION_LABEL) + L": " +
				loadString( actionResourceId) + L" | " + loadString( IDS_SOURCE_LABEL) + L": " +
				source + L"\r\n" ;
		}
	}

	const bool windowsServer = isWindowsServer() ;	// 最終確認と保護modeに使用する実OS判定。
	// 確認情報の不整合やClient・Server注意区分の不一致ではinstallを拒否する。
	if( invalidConfirmation || (includesIntelEthernetServerNotice && !windowsServer) ||
	   (includesAsixClientNotice && windowsServer)) {
		MessageBoxW( window_, loadString( IDS_INSTALL_CONFIGURATION_INVALID).c_str(),
					loadString( IDS_ERROR_TITLE).c_str(), MB_OK | MB_ICONERROR) ;
		// Intel Server候補をClient用復元ポイント経路へ渡さない。
		return ;
	}

	// 詳細表示を省いた対象があることを確認文の末尾へ示す。
	if( checkedIndexes.size() > MAXIMUM_CONFIRMATION_TITLES) {
		confirmation += L"…\r\n" ;
	}

	// 旧版への切替を含む選択ではdowngrade専用警告を追加する。
	if( includesDowngrade) {
		confirmation += loadString( IDS_DOWNGRADE_WARNING) ;
	}

	// 部品メーカー汎用候補を含む選択ではOEM固有版との差を警告する。
	if( includesComponentGeneric) {
		confirmation += loadString( IDS_COMPONENT_GENERIC_WARNING) ;
	}

	// 緩和された検出経路の候補を含む場合はその制約を追加表示する。
	if( includesRelaxedDiscovery) {
		confirmation += loadString( IDS_RELAXED_DISCOVERY_WARNING) ;
	}

	// ASIX Client NIC候補を含む選択には専用の導入注意を追加する。
	if( includesAsixClientNotice) {
		confirmation += loadString( IDS_ASIX_CLIENT_INSTALL_NOTICE) ;
	}

	// Intel Ethernet Server候補を含む選択には専用の導入注意を追加する。
	if( includesIntelEthernetServerNotice) {
		confirmation += loadString( IDS_INTEL_ETHERNET_SERVER_INSTALL_NOTICE) ;
	}

	// Clientの復元ポイント必須modeと、Server専用確認modeの選択結果。
	const InstallProtectionMode protectionMode =
		windowsServer ? InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT
					  : InstallProtectionMode::WINDOWS_RESTORE_POINT ;
	confirmation += loadString( windowsServer ? IDS_SERVER_CONFIRM_SUFFIX : IDS_CONFIRM_SUFFIX) ;
	// 取得同意とは別の最終操作確認で、公式installerの作用と結果境界を明示します。
	if( includesOfficialInstaller) {
		confirmation += L"\r\n" + loadString( IDS_INDEX_INSTALLER_WARNING) ;
	}

	// 通常Client標準INFはInstall clickを実行意思とし、同じ件数確認を重ねません。
	const bool requiresNewConsent = windowsServer || includesDowngrade ||
									includesOfficialInstaller || includesUnacceptedEula ||
									includesRequiredComponents ;	// 新たな条件だけを明示確認します。
	// Install clickと必要な新条件への明示判断だけを今回の実行意思へ結合します。
	const InstallConfirmation installConfirmation =
		!requiresNewConsent ||
				MessageBoxW( window_, confirmation.c_str(), loadString( IDS_CONFIRM_TITLE).c_str(),
							MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES
			? InstallConfirmation::CONFIRMED
			: InstallConfirmation::NOT_CONFIRMED ;

	const ScanSessionId scanSessionId = controller_.scanSessionId() ;	// 選択元session ID。
	// Install開始のidentityと状態検証結果。
	const BeginResult	begin =
		controller_.beginInstall( scanSessionId, identities, installConfirmation, protectionMode) ;
	// 状態機械が拒否したinstall要求をworkerへ送らない。
	if( !begin.accepted) {
		return ;
	}

	recordInstallSelectionDiagnostics( begin.operationId, candidates_, checkedIndexes, true) ;
	preparationApproval_ = {} ;
	setStatus( loadString( windowsServer ? IDS_STATUS_PREPARING_SERVER_INSTALL
									   : IDS_STATUS_CREATING_RESTORE_POINT),
			  true) ;
	updateCommandState() ;
	// worker登録に失敗した要求をUI上で処理中のまま残さない。
	if( worker_ == nullptr || !worker_->requestInstall( begin.operationId, scanSessionId, identities,
													  window_, protectionMode)) {
		InstallResult failure ;	// Queue登録失敗を表す既定失敗結果。
		failure.protectionMode = protectionMode ;
		static_cast<void>( controller_.completeInstall( begin.operationId, failure)) ;
		setStatus( loadString( IDS_STATUS_FAILED), false) ;
		updateCommandState() ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::processWorkerEvents()
{
	// worker未作成時は結果queueを参照しない。
	if( worker_ == nullptr) {
		return ;
	}

	std::vector<WorkerEvent> events = worker_->takeEvents() ;	// UIへownershipを移したevent群。
	// worker が発行した段階と完了を同じ operation 内の到着順で UI へ反映する。
	for( const WorkerEvent &event : events) {
		processWorkerEvent( event) ;
	}
}

//------------------------------------------------------------------------------
/** @see src/app/main_window.h 宣言側の契約を正本とします。 */
//------------------------------------------------------------------------------
void MainWindow::processWorkerEvent( const WorkerEvent &event)
{
	// 旧operation、停止中または破棄後の通知を現在のUI状態へ適用しません。
	if( closing_ || window_ == nullptr || IsWindow( window_) == FALSE ||
	   controller_.state() == ApplicationState::STOPPING ||
	   event.operationId != controller_.activeOperationId()) {
		return ;
	}

	// event種別ごとの受信処理へ送り、進捗と完了を混同しない。
	switch( event.kind) {
		// 通常 operation の進捗 event を状態機械へ反映する。
		case WorkerEventKind::PROGRESS:
			processOperationProgress( event) ;
			break ;

		// Scan 完了 event を候補一覧の受信処理へ渡す。
		case WorkerEventKind::SCAN_COMPLETED:
			processScanCompleted( event) ;
			break ;

		// 通常scan完了へ流さず、取消しや失敗の部分結果も専用契約で検証する。
		case WorkerEventKind::METADATA_SEARCH_COMPLETED:
			processMetadataSearchCompleted( event) ;
			break ;

		// Install 完了 event を個別結果の反映処理へ渡す。
		case WorkerEventKind::INSTALL_COMPLETED:
			processInstallCompleted( event) ;
			break ;

		// 公式取得準備の進捗を専用表示へ反映する。
		case WorkerEventKind::PREPARATION_PROGRESS:
			processPreparationProgress( event) ;
			break ;

		// 公式取得準備の完了を監査・候補公開結果の処理へ渡す。
		case WorkerEventKind::PREPARATION_COMPLETED:
			processPreparationCompleted( event.preparationResult, event.indexPreparation) ;
			break ;

		// 未知の worker event は UI 状態へ適用しない。
		default:
			break ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::processOperationProgress( const WorkerEvent &event)
{
	// 専用modeではWUA・復元・download・installの偽進捗を拒否する。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) {
		const auto state =
			// 同operationの実行／取消し待ちだけが進捗を受理する。
			controller_.state() ;
		// 専用modeで実際に行う段階だけを進捗へ反映する。
		if( (state == ApplicationState::SCANNING ||
			state == ApplicationState::CANCELLING_METADATA_SEARCH) &&
		   (event.progress.stage == ProviderStage::SCANNING_DEVICES ||
			event.progress.stage == ProviderStage::SEARCHING_OFFICIAL_CATALOGS ||
			event.progress.stage == ProviderStage::MERGING_CANDIDATES)) {
			setOperationProgress( event.progress) ;
		}

		return ;
	}

	bool accepted{} ;	// 現在stateへ進捗を適用できる場合はtrue。
	// 進捗段階と現在の状態機械が整合するeventだけを受理する。
	switch( event.progress.stage) {
		// Windows再検出は通常検索の開始段階だけで受理します。
		case ProviderStage::REFRESHING_HARDWARE:
		// Device 列挙の進捗は scan 中だけ受理する共通分岐へ進む。
		case ProviderStage::SCANNING_DEVICES:
		// WUA 検索の進捗は scan 中だけ受理する共通分岐へ進む。
		case ProviderStage::SEARCHING_WINDOWS_UPDATE:
		// 公式 catalog 検索の進捗は scan 中だけ受理する共通分岐へ進む。
		case ProviderStage::SEARCHING_OFFICIAL_CATALOGS:
		// 候補統合を含む scan 段階の進捗は scan 状態であることを要求する。
		case ProviderStage::MERGING_CANDIDATES:
			accepted = controller_.state() == ApplicationState::SCANNING ||
					   controller_.state() == ApplicationState::CANCELLING_SCAN ;
			break ;

		// 復元ポイント開始の進捗は同じ保護段階にある場合だけ受理する。
		case ProviderStage::CREATING_RESTORE_POINT:
			accepted = controller_.state() == ApplicationState::CREATING_RESTORE_POINT ;
			break ;

		// Download 進捗は対応する操作 ID の状態遷移を通して受理する。
		case ProviderStage::DOWNLOADING:
			accepted = controller_.markDownloading( event.operationId) ;
			break ;

		// Install 進捗は対応する操作 ID の状態遷移を通して受理する。
		case ProviderStage::INSTALLING:
			accepted = controller_.markInstalling( event.operationId) ;
			break ;

		// 復元ポイント終了は保護開始後の導入経路にある場合だけ受理する。
		case ProviderStage::FINALIZING_RESTORE_POINT:
			accepted = controller_.state() == ApplicationState::CREATING_RESTORE_POINT ||
					   controller_.state() == ApplicationState::DOWNLOADING ||
					   controller_.state() == ApplicationState::INSTALLING ;
			break ;

		// 未知の処理段階を進捗や状態遷移へ適用しない。
		default:
			break ;
	}

	// 状態検証を通過した進捗だけを表示帯へ反映する。
	if( accepted) {
		setOperationProgress( event.progress) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
/** @see main_window.h 宣言側の契約を正本とします。 */
std::wstring MainWindow::formatIndexRefreshSummary( const IndexScanSummary &summary) const
{
	// 純local fixtureや無効Providerを通信成功へ表示しません。
	if( !summary.refresh) {
		return {} ;
	}

	const auto &refresh = *summary.refresh ;	// 非機密な確定summaryだけです。
	const UINT	refreshText =
		 summary.status == IndexScanStatus::CANCELLED ||
				 refresh.status == IndexRefreshStatus::CANCELLED
			 ? IDS_INDEX_REFRESH_CANCELLED
		 : refresh.status == IndexRefreshStatus::REFRESHED			 ? IDS_INDEX_REFRESHED
		 : refresh.status == IndexRefreshStatus::UNCHANGED			 ? IDS_INDEX_REFRESH_UNCHANGED
		 : refresh.status == IndexRefreshStatus::AUTHENTICATED_CACHE ? IDS_INDEX_REFRESH_CACHED
		 : refresh.status == IndexRefreshStatus::CANCELLED
			 ? IDS_INDEX_REFRESH_CANCELLED
			 : IDS_INDEX_REFRESH_REJECTED ;	// 元区分です。
	const std::wstring timeReason =
		refresh.manifestStatus == SignedIndexManifestStatus::INVALID_TIME
			? loadString( IDS_INDEX_REFRESH_INVALID_TIME) + L"\r\n"
			: L"" ;	// 期限切れ以外も含む元の時刻拒否を、HTTP成功やerror0と区別します。
	return loadString( refreshText) + L"\r\n" + timeReason +
		   formatResource( IDS_INDEX_REFRESH_FACTS, std::to_wstring( refresh.httpStatus)) + L"\r\n" +
		   formatResource( IDS_INDEX_REFRESH_HTTP_ERROR, formatNativeError( refresh.httpError)) +
		   L"\r\n" + formatResource( IDS_INDEX_REFRESH_ERROR, formatNativeError( refresh.error)) +
		   L"\r\n" +
		   formatResource( IDS_INDEX_REFRESH_COMMIT,
						  std::to_wstring( static_cast<unsigned>( refresh.store.commit))) +
		   L"\r\n" +
		   formatResource(
			   IDS_INDEX_REFRESH_ATTEMPTED,
			   refresh.attemptedGeneration ? std::to_wstring( *refresh.attemptedGeneration) : L"—") +
		   L"\r\n" +
		   formatResource( IDS_INDEX_REFRESH_PERSISTED,
						  refresh.store.persistedGeneration
							  ? std::to_wstring( *refresh.store.persistedGeneration)
							  : L"—") ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
bool MainWindow::canShowIndexRefreshDetails() const noexcept
{
	const auto state = controller_.state() ;	// 新規処理中の前回結果を成功表示しない状態境界です。
	return controller_.scanPurpose() == ScanPurpose::STANDARD &&
		   indexScanSummary_.refresh.has_value() &&
		   (state == ApplicationState::SCAN_READY || state == ApplicationState::COMPLETED ||
			state == ApplicationState::FAILURE || state == ApplicationState::IDLE) ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
void MainWindow::appendIndexRefreshMenu( HMENU menu) const
{
	// 未実行やbusyの結果を成功への入口として有効にしません。
	const UINT flags = MF_STRING | (canShowIndexRefreshDetails() ? MF_ENABLED : MF_GRAYED) ;
	static_cast<void>( AppendMenuW( menu, flags, IDM_INDEX_REFRESH_DETAILS,
								  loadString( IDS_INDEX_REFRESH_DETAILS).c_str())) ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
void MainWindow::showIndexRefreshDetails() const
{
	// 未実行・無効・操作中の状態から成功dialogを作りません。
	if( !canShowIndexRefreshDetails()) {
		return ;
	}

	const auto body = formatIndexRefreshSummary( indexScanSummary_) ;	// 同scanの実保持summaryです。
	// 内部targetだけが実際に渡す本文を観測し、製品の表示や権限へは使用しません。
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
	testIndexRefreshDetailBody_ = body ;
#endif
	// LPARAMは同期dialogの終了まで生存する本文を指すWin32境界です。
	static_cast<void>( DialogBoxParamW( instance_, MAKEINTRESOURCEW( IDD_METADATA_DETAILS), window_,
									  indexRefreshDetailsProc, reinterpret_cast<LPARAM>( &body))) ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
void MainWindow::processScanCompleted( const WorkerEvent &event)
{
	const bool cancellationPending =
		// 完了適用前の利用者取消し状態。
		controller_.state() == ApplicationState::CANCELLING_SCAN ;
	// 状態機械が受理しないscan完了を表示へ反映しない。
	if( !controller_.completeScan( event.operationId, event.scanResult)) {
		return ;
	}

	hardwareRefresh_  = event.hardwareRefresh ;
	indexScanSummary_ = event.indexSummary ;
	recordScanDiagnostics( event, static_cast<std::int32_t>( controller_.state()),
						  controller_.scanMeasurement() != nullptr) ;
	preparationResultText_ =
		formatHardwareRefreshSummary() + L"\r\n" + formatIndexRefreshSummary( event.indexSummary) ;

	// 有効なABORTED終端では候補や導入権限を公開せず、失敗dialogとも区別する。
	if( cancellationPending && controller_.state() == ApplicationState::IDLE &&
	   !event.scanResult.succeeded && event.scanResult.outcome == OutcomeCode::ABORTED) {
		candidates_.clear() ;
		candidateSelected_.clear() ;
		providerReports_.clear() ;
		localCoverage_.clear() ;
		scanOutcome_ = OutcomeCode::ABORTED ;
		setStatus( loadString( IDS_SCAN_CANCELLED), false) ;
		updateCommandState() ;
		// Window終了要求はworker完了eventを受理した後にだけ再開する。
		if( closeAfterScan_) {
			closeAfterScan_ = false ;
			requestClose() ;
		}

		return ;
	}

	providerReports_			   = event.scanResult.providerReports ;
	const bool measurementAccepted = controller_.scanMeasurement() !=
									 nullptr ;	// Operationとsessionを再照合した計測だけを表示する。
	// Controllerが拒否したmeasurementはProvider別の一部だけも表示しない。
	if( !measurementAccepted) {
		// 全reportを従来coverage表示へ戻し、未検証値の部分表示を防ぐ。
		for( ProviderScanReport &report : providerReports_) {
			report.coverage.measurement.reset() ;
		}
	}

	// 成功flagと候補契約が矛盾したProvider result。
	const bool providerResultInvalid =
		event.scanResult.succeeded && controller_.state() == ApplicationState::FAILURE ;
	// scan失敗またはProvider結果不整合時は選択を破棄し、診断値を表示する。
	if( !event.scanResult.succeeded || providerResultInvalid) {
		candidates_.clear() ;
		candidateSelected_.clear() ;
		localCoverage_.clear() ;
		scanOutcome_ = OutcomeCode::NOT_STARTED ;
		setStatus( hardwareRefresh_ && !hardwareRefresh_->succeeded ? formatHardwareRefreshSummary()
																   : loadString( IDS_STATUS_FAILED),
				  false) ;
		updateCommandState() ;
		// 利用者へ提示する矛盾またはProvider error code。
		const NativeError errorCode =
			providerResultInvalid ? static_cast<NativeError>( E_UNEXPECTED) : event.scanResult.error ;
		// Error説明に使用する正規化済み結果分類。
		const OutcomeCode outcome =
			providerResultInvalid ? OutcomeCode::FAILURE : event.scanResult.outcome ;
		// Scan失敗理由とnative codeを含むdialog本文。
		const std::wstring error =
			loadString( IDS_SCAN_ERROR_PREFIX) + formatOperationError( errorCode, outcome) +
			(preparationResultText_.empty() ? L"" : L"\r\n" + preparationResultText_) ;
		MessageBoxW( window_, error.c_str(), loadString( IDS_ERROR_TITLE).c_str(),
					MB_OK | MB_ICONERROR) ;
		return ;
	}

	// 取得計画の拒否を、成功したdriver scanの失敗へ置き換えない。
	NativeError preparationError = event.preparationError ;	// 独立した取得計画の診断値。
	indexScanSummary_			 = event.indexSummary ;
	indexPreparationSummary_	 = event.indexPreparation ;
	const auto indexStatus =
		event.indexSummary.status == IndexScanStatus::TRUST_UNAVAILABLE
			? IDS_INDEX_TRUST_UNAVAILABLE
		: event.indexSummary.status == IndexScanStatus::COMPLETED ? IDS_INDEX_SCAN_COMPLETE
		: event.indexSummary.status == IndexScanStatus::PARTIAL ||
				event.indexSummary.status == IndexScanStatus::BUDGET_EXHAUSTED
			? IDS_INDEX_SCAN_PARTIAL
			: IDS_INDEX_SCAN_UNAVAILABLE ;	// 索引一致を適合・候補成功へ読み替えません。
	preparationResultText_ =
		loadString( indexStatus) + L"\r\n" +
		formatResource( IDS_INDEX_SCAN_COUNTS,
					   std::to_wstring( event.indexSummary.processedRecords) + L" / " +
						   std::to_wstring( event.indexSummary.totalRecords) + L" / " +
						   std::to_wstring( event.indexSummary.undeterminedRelations)) +
		L"\r\n" +
		formatResource( IDS_INDEX_PLAN_COUNTS,
					   std::to_wstring( event.indexPreparation.plannedTargets) + L" / " +
						   std::to_wstring( event.indexPreparation.unavailableRelations) + L" / " +
						   std::to_wstring( event.indexPreparation.capacityRejectedRelations)) +
		L"\r\n" + loadString( IDS_INDEX_ROUTING_PENDING) ;
	preparationResultText_ += L"\r\n" + formatIndexRefreshSummary( event.indexSummary) ;
	// 取得能力不足は数値診断を分けて表示し、元Provider候補を失敗へ変更しません。
	if( event.indexPreparation.authorityError != 0U) {
		preparationResultText_ +=
			L"\r\n" + formatNativeError( event.indexPreparation.authorityError) ;
	}

	// 準備計画を状態機械が拒否した場合は独立した計画エラーとして残す。
	if( event.preparationPlan &&
	   !controller_.setPreparationPlan( event.operationId, *event.preparationPlan)) {
		preparationError = static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 準備計画の失敗をscan候補の表示だけで隠さず警告する。
	if( preparationError != 0) {
		preparationResultText_ += L"\r\n" + formatResource( IDS_PREPARATION_PLAN_ERROR,
														   formatNativeError( preparationError)) ;
		MessageBoxW( window_, preparationResultText_.c_str(),
					loadString( IDS_PREPARATION_TITLE).c_str(), MB_OK | MB_ICONWARNING) ;
	}

	// 新scanへ旧device行の指定と個別実行結果を継承しない。
	preparationDisplaySession_ = 0U ;
	preparationDisplayBindings_.clear() ;
	treeClassExpansion_.clear() ;
	treeRows_.clear() ;
	candidateResultTexts_.clear() ;
	candidates_	   = event.scanResult.candidates ;
	localCoverage_ = event.scanResult.localCoverage ;
	// Top-level snapshotがない場合はgroup別の未検証measurementも表示しない。
	if( !measurementAccepted) {
		// 従来候補到達値は維持し、新しい段階別fieldだけを破棄する。
		for( LocalCoverageEntry &entry : localCoverage_) {
			entry.measurement.reset() ;
		}
	}

	scanOutcome_ = event.scanResult.outcome ;
	initializeCandidateSelection() ;
	populateCandidates( candidates_) ;
	updateScanSummaryStatus() ;

	updateCommandState() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::processInstallCompleted( const WorkerEvent &event)
{
	const auto scanSessionId =
		// 終端で失効する前の表示結合だけを保持します。
		controller_.scanSessionId() ;
	auto displayBindings = capturePreparationDisplayBindings() ;	// 失効前の元枠/意図です。
	// 状態機械が受理しないinstall完了を候補行へ反映しない。
	if( !controller_.completeInstall( event.operationId, event.installResult)) {
		return ;
	}

	preparationDisplaySession_	= scanSessionId ;
	preparationDisplayBindings_ = std::move( displayBindings) ;
	// 全体flagや現在版で完了を推測せず、一意な元個別結果だけを解除します。
	for( auto &binding : preparationDisplayBindings_) {
		const auto result =
			std::ranges::find( event.installResult.updates, binding.candidateIdentity,
							  &UpdateExecutionResult::identity) ;	// 同候補の元結果です。
		// 引継ぎ/失敗/未実行/部分成功では前回checkを保持します。
		if( binding.candidateIdentity.empty() || result == event.installResult.updates.end() ||
		   std::ranges::count( event.installResult.updates, binding.candidateIdentity,
							  &UpdateExecutionResult::identity) != 1 ||
		   result->installerHandoff || result->downloadOutcome != OutcomeCode::SUCCESS ||
		   result->downloadError != 0 || result->installOutcome != OutcomeCode::SUCCESS ||
		   result->installError != 0) {
			continue ;
		}

		const auto original =
			std::ranges::find( candidates_, binding.candidateIdentity,
							  &UpdateCandidate::identity) ;	// 元deviceへの一意結合です。
		// 欠測/別device/保護開始失敗から個別完了を作りません。
		if( original == candidates_.end() || original->deviceIdentity != binding.deviceIdentity ||
		   std::ranges::count( candidates_, binding.candidateIdentity, &UpdateCandidate::identity) !=
			   1 ||
		   event.installResult.restorePointCreation.outcome == OutcomeCode::FAILURE) {
			continue ;
		}

		const bool rolesComplete = std::ranges::all_of( result->requiredRoles, []( const auto &role) {
			return role.stageOutcome == OutcomeCode::SUCCESS && role.stageError == 0 &&
				   role.installOutcome == OutcomeCode::SUCCESS && role.installError == 0 &&
				   !role.installDiagnosticMissing &&
				   role.reflection == DriverPlanReflectionState::INSTALL_API_COMPLETED ;
		}) ; // 必要roleの未完了をbase成功から補いません。
		// 完了した元一候補だけを表示上解除します。
		if( rolesComplete) {
			binding.checked = false ;
		}
	}

	recordInstallDiagnostics( event, scanSessionId, candidates_,
							 static_cast<std::int32_t>( controller_.state())) ;

	// 元filterと行集合を保持したまま、同じ行へ結果と失効だけを反映します。
	displayInstallResult( event.installResult, scanSessionId) ;
	// trueの場合は全選択候補のinstallが成功した。
	const bool succeeded = controller_.state() == ApplicationState::COMPLETED ;
	const bool includesHandoff =
		std::ranges::any_of( event.installResult.updates, []( const auto &update) {
			return update.installerHandoff ;
		}) ; // 個別導入未確認を全体導入成功へ変換しません。
	setStatus( loadString( succeeded ? IDS_STATUS_COMPLETED : IDS_STATUS_FAILED), false) ;
	updateCommandState() ;

	// Success、再起動要求、failureに対応するmessage resource ID。
	const UINT messageId =
		succeeded
			? (event.installResult.rebootRequired ? IDS_RESULT_SUCCESS_REBOOT : IDS_RESULT_SUCCESS)
			: IDS_RESULT_FAILURE ;
	std::wstring message ;															// 復元ポイント診断またはinstall結果を示すdialog本文。
	UINT		 messageIcon = succeeded ? MB_ICONINFORMATION : MB_ICONWARNING ;	// Dialog icon種別。
	// 復元ポイント開始失敗を通常のinstall結果より優先して案内する。
	if( event.installResult.restorePointCreation.outcome == OutcomeCode::FAILURE) {
		message = loadString( IDS_RESTORE_POINT_ERROR_PREFIX) +
				  formatOperationError( event.installResult.restorePointCreation.error,
									   event.installResult.restorePointCreation.outcome) ;
		messageIcon = MB_ICONERROR ;
	}
	// 復元ポイントを開始した後の終了通知失敗を別の診断として示す。
	else if( event.installResult.restorePointCreation.outcome == OutcomeCode::SUCCESS &&
			event.installResult.restorePointCompletion.outcome != OutcomeCode::SUCCESS) {
		message = loadString( IDS_RESTORE_POINT_FINALIZE_ERROR_PREFIX) +
				  formatOperationError( event.installResult.restorePointCompletion.error,
									   event.installResult.restorePointCompletion.outcome) ;
	} else {
		message = loadString( includesHandoff ? (succeeded ? IDS_INDEX_INSTALLER_COMPLETED
														  : IDS_INDEX_INSTALLER_FAILED)
											 : messageId) ;
		// 復元ポイントが実際に開始された場合にだけその番号を表示する。
		if( event.installResult.restorePointCreation.outcome == OutcomeCode::SUCCESS) {
			message += L"\r\n\r\n" +
					   formatResource( IDS_RESTORE_POINT_CREATED,
									  std::to_wstring(
										  event.installResult.restorePointCreation.sequenceNumber)) ;
		}
		// Server保護modeでは復元ポイントを作成していない事実を明示する。
		else if( event.installResult.protectionMode ==
				InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) {
			message += L"\r\n\r\n" + loadString( IDS_SERVER_NO_RESTORE_POINT_RESULT) ;
		}
	}

	const auto storage = diagnosticStorageText( instance_) ;	// 元処理結果と保存状態を分けます。
	// 元成功文を改作せず、匿名診断の保存事実だけを付けます。
	if( !storage.empty()) {
		message += L"\r\n\r\n" + storage ;
	}

	MessageBoxW( window_, message.c_str(), loadString( IDS_APP_TITLE).c_str(), MB_OK | messageIcon) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::initializeCandidateSelection()
{
	const auto selection =	// Candidate別根拠を検証した一device一候補の初期状態。
		buildDefaultCandidateSelection( candidates_, builtInProviderDescriptors()) ;
	// 初期選択を検証できない場合は全候補を未選択にして誤導入を防ぐ。
	if( !selection.has_value()) {
		candidateSelected_.assign( candidates_.size(), false) ;
		return ;
	}

	candidateSelected_ = selection.value() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<MainWindow::PreparationDisplayBinding> MainWindow::capturePreparationDisplayBindings()
	const
{
	auto bindings =
		preparationDisplaySession_ == controller_.scanSessionId()
			? preparationDisplayBindings_
			: std::vector<PreparationDisplayBinding>{} ;	// 同scanの非表示行も保持します。
	// 実際に枠があった元deviceだけを退避し、現在観測へ枠を新設しません。
	for( const auto &row : treeRows_) {
		// 種類行/欠測/別deviceの位置を表示意図へ使いません。
		if( row.kind != TreeRowKind::DEVICE || row.deviceIndex >= candidates_.size() ||
		   row.deviceIndex >= candidateItems_.size() || !candidateItems_[row.deviceIndex]) {
			continue ;
		}

		const auto image = TreeView_GetItemState( updateTree_, candidateItems_[row.deviceIndex],
												 TVIS_STATEIMAGEMASK) >>
						   12U ;											// 元の枠とcheckです。
		const auto &device = candidates_[row.deviceIndex].deviceIdentity ;	// 表示名で結合しません。
		auto		prior  = std::ranges::find(
			bindings, device, &PreparationDisplayBinding::deviceIdentity) ;	// 同deviceだけです。
		// 既readonlyの元candidateは、再描画でchoiceを失っても保持します。
		if( row.readonlyCheckbox && prior != bindings.end()) {
			continue ;
		}

		// 枠の無い現在行から新しい表示checkを作りません。
		if( image == 0U) {
			continue ;
		}

		PreparationDisplayBinding binding ;	// 複数候補未指定ならcandidate IDは空のままです。
		binding.deviceIdentity = device ;
		binding.frame		   = true ;
		binding.checked		   = image == 2U || image == 4U ;
		binding.explicitChoice = row.explicitCandidateChoice ;
		// 元一候補が一意な同deviceの場合だけ版・取得元を保存します。
		if( row.hasCandidateChoice && row.candidateIndex < candidates_.size()) {
			const auto &candidate = candidates_[row.candidateIndex] ;	// 元の指定候補です。
			// 破損/現在行/重複候補を表示指定へ補完しません。
			if( !candidate.current && candidate.deviceIdentity == device &&
			   std::ranges::count( candidates_, candidate.identity, &UpdateCandidate::identity) ==
				   1) {
				binding.candidateIdentity = candidate.identity ;
				binding.version			  = candidate.version ;
				binding.sourceName		  = candidate.sourceName ;
				binding.reference =
					!candidate.installable && !candidate.preparationTargetIdentity.empty() ;
			}
		}

		// 同deviceのsnapshotだけを更新し、元の非表示行は保持します。
		if( prior == bindings.end()) {
			bindings.push_back( std::move( binding)) ;
		} else {
			*prior = std::move( binding) ;
		}
	}

	// filterで隠れた元checkも同じ選択vectorから表示だけへ退避します。
	for( std::size_t index{}; index < candidates_.size() && index < candidateSelected_.size();
		++index) {
		const auto &candidate = candidates_[index] ;	// 実行集合へ戻さない元候補です。
		// 現在行/未選択/重複/既退避deviceから別の表示意図を作りません。
		if( !candidateSelected_[index] || candidate.current || candidate.identity.empty() ||
		   std::ranges::count( candidates_, candidate.identity, &UpdateCandidate::identity) != 1 ||
		   std::ranges::any_of( bindings, [&]( const auto &binding) {
			   return binding.deviceIdentity == candidate.deviceIdentity ;
		   })) {
			continue ;
		}

		bindings.push_back(
			{.candidateIdentity = candidate.identity,
			 .deviceIdentity	= candidate.deviceIdentity,
			 .version			= candidate.version,
			 .sourceName		= candidate.sourceName,
			 .reference = !candidate.installable && !candidate.preparationTargetIdentity.empty(),
			 .frame		= true,
			 .checked	= true}) ;
	}

	return bindings ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
const MainWindow::PreparationDisplayBinding *MainWindow::retainedDisplayBinding(
	const TreeRow &row) const noexcept
{
	const auto session = controller_.scanSessionId() ;	// 新scanのclearだけで元表示を破棄します。
	// 元候補集合の失効後も同じ表示だけへ限定し、metadata modeへ持ち越しません。
	if( controller_.scanPurpose() != ScanPurpose::STANDARD || row.kind != TreeRowKind::DEVICE ||
	   row.deviceIndex >= candidates_.size() || preparationDisplaySession_ == 0U ||
	   (session != preparationDisplaySession_ &&
		!(session == 0U && (controller_.state() == ApplicationState::FAILURE ||
							controller_.state() == ApplicationState::COMPLETED)))) {
		return nullptr ;
	}

	const auto &device = candidates_[row.deviceIndex].deviceIdentity ;	// 同元deviceだけです。
	const auto	found =
		std::ranges::find( preparationDisplayBindings_, device,
						  &PreparationDisplayBinding::deviceIdentity) ;	// 表示名を使いません。
	return found != preparationDisplayBindings_.end() &&
				   std::ranges::count( preparationDisplayBindings_, device,
									  &PreparationDisplayBinding::deviceIdentity) == 1
			   ? &*found
			   : nullptr ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
bool MainWindow::initializeCheckboxImages()
{
	const UINT dpi	  = GetDpiForWindow( updateTree_) ;					// 元controlと同じ画像寸法です。
	const int  width  = GetSystemMetricsForDpi( SM_CXMENUCHECK, dpi) ;	// 標準checkbox幅です。
	const int  height = GetSystemMetricsForDpi( SM_CYMENUCHECK, dpi) ;	// 標準checkbox高さです。
	HIMAGELIST made =
		// 同Windowだけが所有します。
		ImageList_Create( width, height, ILC_COLOR32 | ILC_MASK, 5, 0) ;
	const HDC dc	  = GetDC( updateTree_) ;						// 作成中だけの借用DCです。
	const HDC memory  = dc ? CreateCompatibleDC( dc) : nullptr ;	// 一bitmap用です。
	bool	  success = made && memory ;							// 全五画像を作成した場合だけ接続します。
	// 0空/1通常枠/2通常check/3readonly枠/4readonlycheckを作ります。
	for( unsigned index{}; success && index < 5U; ++index) {
		const HBITMAP bitmap =
			// 追加後に解放する元bitmapです。
			CreateCompatibleBitmap( dc, width, height) ;
		const HGDIOBJ previous =
			bitmap ? SelectObject( memory, bitmap) : nullptr ;		// 借用選択を戻します。
		RECT		 rectangle{0, 0, width, height} ;				// 元画像内だけです。
		const HBRUSH mask = CreateSolidBrush( RGB( 255, 0, 255)) ;	// 透明mask色です。
		success			  = bitmap && previous && mask ;
		// 欠測したGDI objectへ描画しません。
		if( success) {
			FillRect( memory, &rectangle, mask) ;
			// 空画像以外だけをWindowsの標準checkboxで描画します。
			if( index != 0U) {
				DrawFrameControl( memory, &rectangle, DFC_BUTTON,
								 DFCS_BUTTONCHECK | (index >= 3U ? DFCS_INACTIVE : 0U) |
									 (index == 2U || index == 4U ? DFCS_CHECKED : 0U)) ;
			}

			SelectObject( memory, previous) ;
			success =
				ImageList_AddMasked( made, bitmap, RGB( 255, 0, 255)) == static_cast<int>( index) ;
		}

		// brush作成失敗でも元bitmapの選択を戻してから解放します。
		if( !success && previous) {
			SelectObject( memory, previous) ;
		}

		// 作成に成功したGDI objectだけを解放します。
		if( mask) {
			DeleteObject( mask) ;
		}

		// 画像listは追加済みbitmapを複製して所有します。
		if( bitmap) {
			DeleteObject( bitmap) ;
		}
	}

	// 失敗時もDCの借用を終了します。
	if( memory) {
		DeleteDC( memory) ;
	}

	// このWindowから借用したDCだけを返却します。
	if( dc) {
		ReleaseDC( updateTree_, dc) ;
	}

	// 不完全なreadonly表示を接続しません。
	if( !success) {
		// 作成済みlistだけを破棄し、所有memberへ渡しません。
		if( made) {
			ImageList_Destroy( made) ;
		}

		return false ;
	}

	const auto original = TreeView_SetImageList(
		updateTree_, made, TVSIL_STATE) ;	// 既定のこのcontrol専用state画像です。
	// 置換後に旧state画像の所有を終了します。
	if( original) {
		ImageList_Destroy( original) ;
	}

	checkboxImages_ = made ;
	return true ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
std::optional<std::size_t> MainWindow::preparationDisplayCandidate(
	const TreeRow &row) const noexcept
{
	const auto *binding = retainedDisplayBinding( row) ;	// 同じ798snapshotだけを使います。
	// 有効な新choiceを上書きせず、枠だけのsnapshotに候補IDを作りません。
	if( !binding || binding->candidateIdentity.empty() ||
	   (row.hasCandidateChoice && row.candidateIndex < candidates_.size() &&
		isSelectableCandidate( candidates_[row.candidateIndex]))) {
		return std::nullopt ;
	}

	const auto &device = candidates_[row.deviceIndex].deviceIdentity ;	// 元deviceだけです。

	const auto	candidate =
		std::ranges::find( candidates_, binding->candidateIdentity,
						  &UpdateCandidate::identity) ;	// 元候補そのものの位置です。
	// 別device・現在行・候補重複をreadonly表示へも補完しません。
	if( candidate == candidates_.end() || candidate->current ||
	   candidate->deviceIdentity != device ||
	   std::ranges::count( candidates_, binding->candidateIdentity, &UpdateCandidate::identity) !=
		   1) {
		return std::nullopt ;
	}

	const auto index =
		// 候補順は変えません。
		static_cast<std::size_t>( candidate - candidates_.begin()) ;
	return std::ranges::count( row.candidateIndexes, index) == 1 ? std::optional{index}
																: std::nullopt ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
void MainWindow::applyCandidateSelectionToTree()
{
	updatingTreeChecks_ = true ;
	const bool standard =
		// 専用modeは閲覧のみ。
		controller_.scanPurpose() == ScanPurpose::STANDARD ;
	const std::wstring unknown = loadString( IDS_VALUE_UNKNOWN) ;	// 欠損値の表示。
	// 一device一行だけを更新し、同じhandleへ複数候補のcheckを順次上書きしない。
	for( auto &row : treeRows_) {
		// 種類行や表示元を失った行を導入選択へ使用しない。
		if( row.kind != TreeRowKind::DEVICE || row.deviceIndex >= candidates_.size() ||
		   row.deviceIndex >= candidateItems_.size() ||
		   candidateItems_[row.deviceIndex] == nullptr) {
			continue ;
		}

		std::size_t installableCount{} ;	// 当該deviceの導入可能候補数。
		std::size_t soleIndex{} ;			// 唯一の候補の場合だけcheckboxへ結合する位置。
		bool		hasResult{} ;			// 個別結果を通常候補の説明で上書きしない。
		// 同deviceの候補だけから選択済み一候補、件数、個別結果を集める。
		for( const auto index : row.candidateIndexes) {
			// 表示集合と候補集合の不一致を暗黙の先頭採用へ補完しない。
			if( index >= candidates_.size()) {
				continue ;
			}

			const auto &candidate = candidates_[index] ;	// 同sessionの元候補。
			hasResult			  = hasResult || (index < candidateResultTexts_.size() &&
									  !candidateResultTexts_[index].empty()) ;
			// 閲覧専用・現在構成をcheckboxへ結合しない。
			if( standard && controller_.state() == ApplicationState::SCAN_READY &&
			   controller_.scanSessionId() != 0U && isSelectableCandidate( candidate) &&
			   (visibleInRecommendedFilter( candidate) ||
				(row.explicitCandidateChoice && row.candidateIndex == index &&
				 !showRecommendedOnly_))) {
				++installableCount ;
				soleIndex = index ;
				// 推奨全選択または詳細の明示操作で選んだ一候補を表示する。
				if( index < candidateSelected_.size() && candidateSelected_[index]) {
					row.candidateIndex	   = index ;
					row.hasCandidateChoice = true ;
				}
			}
		}

		// 新scanで対応を失った指定や、導入できなくなった指定を再利用しない。
		if( row.hasCandidateChoice &&
		   (row.candidateIndex >= candidates_.size() ||
			!isSelectableCandidate( candidates_[row.candidateIndex]) ||
			(showRecommendedOnly_ &&
			 !visibleInRecommendedFilter( candidates_[row.candidateIndex])) ||
			candidates_[row.candidateIndex].deviceIdentity !=
				candidates_[row.deviceIndex].deviceIdentity)) {
			row.hasCandidateChoice		= false ;
			row.explicitCandidateChoice = false ;
		}

		// 一候補しかないdeviceは、checkboxからその候補だけを選べる。
		if( !row.hasCandidateChoice && installableCount == 1U) {
			row.candidateIndex	   = soleIndex ;
			row.hasCandidateChoice = true ;
		}

		// 結果確定後は候補版と結果要約を履歴として保持し、再選択させない。
		if( !hasResult) {
			const auto &device = candidates_[row.deviceIndex] ;	// 現在観測を優先する表示元。
			row.status		   = loadString( IDS_DEVICE_PRESENCE_UNKNOWN) ;
			// 一覧は存在と問題コードだけを要約し、属性ごとの元診断は詳細へ残す。
			if( device.current && device.deviceObservation && isCandidateDetailsValid( device)) {
				const auto &observed = *device.deviceObservation ;	// 同deviceの元観測。
				row.status =
					loadString( observed.driverPresence == DeviceDriverPresence::NOT_INSTALLED
								   ? IDS_DEVICE_PRESENCE_NOT_INSTALLED
							   : observed.driverPresence == DeviceDriverPresence::REGISTERED
								   ? IDS_DEVICE_PRESENCE_REGISTERED
								   : IDS_DEVICE_PRESENCE_UNKNOWN) ;
				// Windowsが実際に返した問題コードだけを付記する。
				if( observed.node.problemCode) {
					row.status +=
						L" / " + formatResource( IDS_DEVICE_PROBLEM,
												std::to_wstring( *observed.node.problemCode)) ;
				}
			}

			row.candidateVersion = unknown ;
			// 失効した全候補へ再検索を案内し、旧候補を新しい導入許可へ見せない。
			if( standard && controller_.scanSessionId() == 0U) {
				row.status += L" / " + loadString( IDS_TREE_CLASS_EXPIRED) ;
			}
			// 選択した候補の版だけを明示し、複数版を先頭候補から推測しない。
			else if( row.hasCandidateChoice) {
				const auto &candidate = candidates_[row.candidateIndex] ;	// Checkboxと同じ一候補。
				row.candidateVersion =
					makeSingleLine( candidate.version.empty() ? unknown : candidate.version) ;
				// 参照の申告版を実取得後のdriver版と混同させません。
				if( !candidate.installable && !candidate.preparationTargetIdentity.empty() &&
				   !candidate.version.empty()) {
					row.candidateVersion =
						formatResource( IDS_REFERENCE_VERSION_FORMAT, row.candidateVersion) ;
				}

				row.status +=
					L" / " +
					loadString( candidate.action == DriverAction::INITIAL_INSTALL
								   ? IDS_ACTION_INITIAL_INSTALL
							   : candidate.action == DriverAction::DOWNGRADE ? IDS_ACTION_DOWNGRADE
							   : candidate.action == DriverAction::REINSTALL ? IDS_ACTION_REINSTALL
							   : candidate.action == DriverAction::UPDATE
								   ? IDS_ACTION_UPDATE
								   : IDS_DEVICE_CANDIDATE_READY) ;
			}
			// 複数候補の閲覧・指定を詳細へ集約する。
			else if( installableCount > 1U) {
				row.candidateVersion = formatResource( IDS_DEVICE_MULTIPLE_CANDIDATES,
													  std::to_wstring( installableCount)) ;
				row.status += L" / " + loadString( IDS_DEVICE_CHOOSE_DETAILS) ;
			} else {
				// 未取得情報や検証拒否はdriverなしへ補完せず、詳細へ残す。
				for( const auto index : row.candidateIndexes) {
					// 現在構成を取得前配布情報へ読み替えない。
					if( index >= candidates_.size() || candidates_[index].current) {
						continue ;
					}

					const auto &candidate = candidates_[index] ;	// 閲覧専用の元情報。
					row.status += L" / " + (!standard ? loadString( IDS_METADATA_ROW)
											: candidate.audit.inspectionDownload ==
													CandidateAuditGateState::PENDING
												? loadString( IDS_DEVICE_ACQUIRE_VERIFY)
												: formatCandidateAssessment( candidate)) ;
					// 配布情報専用modeでは版を配布版という列見出しの下だけへ示す。
					if( !standard && candidate.metadataDistribution &&
					   !candidate.metadataDistribution->version.empty()) {
						row.candidateVersion =
							makeSingleLine( candidate.metadataDistribution->version) ;
					}

					break ;
				}
			}
		}

		// 元参照の版と取得元は表示だけへ戻し、実行choice/checkを作りません。
		if( !hasResult) {
			const auto display = preparationDisplayCandidate( row) ;	// 同scanの一意な元選択だけです。
			// 実行可能な新choiceが無い場合だけreadonlyの元版を表示します。
			if( display) {
				const auto binding =
					std::ranges::find( preparationDisplayBindings_, candidates_[*display].identity,
									  &PreparationDisplayBinding::
										  candidateIdentity) ;	// helperが元結合を確認済みです。
				// 退避した元申告版を表示用の一行へ変換します。
				const auto version =
					makeSingleLine( binding->version.empty() ? unknown : binding->version) ;
				row.candidateVersion = binding->reference
										   ? formatResource( IDS_REFERENCE_VERSION_FORMAT, version)
										   : version ;
				row.status += L" / " + loadString( IDS_PREPARATION_DISPLAY_READONLY) ;
				// 元取得元の表示名だけを端末内に保持します。
				if( !binding->sourceName.empty()) {
					row.status += L" / " + makeSingleLine( binding->sourceName) ;
				}
			}
		}

		const auto *retained = retainedDisplayBinding( row) ;	// 元枠とcheckだけです。
		const bool	historicalChecked =
			retained && retained->frame && retained->checked ;	// 実行selectionへ合流しません。
		const bool checked = row.hasCandidateChoice &&
							 row.candidateIndex < candidateSelected_.size() &&
							 candidateSelected_[row.candidateIndex] ;	// 指定一候補だけの保持check。
		// 元checked意図だけの行は有効choiceが残っていても実行checkと区別します。
		row.readonlyCheckbox = retained && retained->frame &&
							   (installableCount == 0U || (historicalChecked && !checked)) ;
		std::wstring text = row.primaryText + L" | " + loadString( IDS_COLUMN_CURRENT_VERSION) +
							L": " + row.currentVersion + L" | " +
							loadString( IDS_COLUMN_CANDIDATE_VERSION) + L": " +
							row.candidateVersion ;	// 表示する三列を読み上げる要約。
		TVITEMW item{} ;							// 一device一itemへの更新。
		item.mask	   = TVIF_STATE | TVIF_TEXT ;
		item.hItem	   = candidateItems_[row.deviceIndex] ;
		item.stateMask = TVIS_STATEIMAGEMASK ;
		item.state	   = row.readonlyCheckbox	 ? INDEXTOSTATEIMAGEMASK( historicalChecked ? 4 : 3)
						 : installableCount > 0U ? INDEXTOSTATEIMAGEMASK( checked ? 2 : 1)
												 : 0 ;
		item.pszText   = text.data() ;
		TreeView_SetItem( updateTree_, &item) ;
	}

	updatingTreeChecks_ = false ;
	InvalidateRect( updateTree_, nullptr, TRUE) ;
}

/** @see src/app/main_window.h */
bool MainWindow::selectDeviceCandidate( const std::size_t candidateIndex,
									   const bool		 preserveDisplayIntent)
{
	// 終端済み・専用mode・失効・非導入候補から新しい導入選択を作らない。
	if( controller_.state() != ApplicationState::SCAN_READY ||
	   controller_.scanPurpose() != ScanPurpose::STANDARD || controller_.scanSessionId() == 0U ||
	   candidateIndex >= candidates_.size() || candidateIndex >= candidateSelected_.size() ||
	   candidateIndex >= candidateItems_.size() || candidateIndex >= candidateRowIndexes_.size() ||
	   candidateItems_[candidateIndex] == nullptr ||
	   candidateRowIndexes_[candidateIndex] >= treeRows_.size() ||
	   !isSelectableCandidate( candidates_[candidateIndex]) ||
	   (showRecommendedOnly_ && !visibleInRecommendedFilter( candidates_[candidateIndex]))) {
		return false ;
	}

	auto &row = treeRows_[candidateRowIndexes_[candidateIndex]] ;	// 同deviceの表示行。
	// 任意の候補indexを別device行のcheckboxへ結合しない。
	if( row.kind != TreeRowKind::DEVICE || row.deviceIndex >= candidates_.size() ||
	   candidates_[row.deviceIndex].deviceIdentity != candidates_[candidateIndex].deviceIdentity ||
	   std::find( row.candidateIndexes.begin(), row.candidateIndexes.end(), candidateIndex) ==
		   row.candidateIndexes.end()) {
		return false ;
	}

	// 非表示も含む同deviceの選択を一件にし、同名の別deviceは変更しない。
	for( std::size_t index{}; index < candidates_.size(); ++index) {
		// 名前やversionでなく元opaque identityで排他範囲を決める。
		if( candidates_[index].deviceIdentity == candidates_[candidateIndex].deviceIdentity &&
		   index < candidateSelected_.size()) {
			candidateSelected_[index] = index == candidateIndex ;
		}
	}

	row.candidateIndex			= candidateIndex ;
	row.hasCandidateChoice		= true ;
	row.explicitCandidateChoice = !preserveDisplayIntent ;
	// 新しい明示選択だけが元表示を消費し、内部READY途中では保持します。
	if( !preserveDisplayIntent) {
		std::erase_if( preparationDisplayBindings_, [&]( const auto &binding) {
			return binding.deviceIdentity == candidates_[candidateIndex].deviceIdentity ;
		}) ;
	}

	applyCandidateSelectionToTree() ;
	updateCommandState() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::populateCandidates( const std::span<const UpdateCandidate> candidates)
{
	// 最初の監査report再描画も含め、全再構築の直前に閉状態まで保存します。
	for( HTREEITEM item = TreeView_GetRoot( updateTree_); item != nullptr;
		item		   = TreeView_GetNextSibling( updateTree_, item)) {
		TVITEMW native{} ;	// この同期取得だけの元itemです。
		native.mask	 = TVIF_PARAM ;
		native.hItem = item ;
		// 新scanで破棄したrowや取得不能なitemを再利用しません。
		if( TreeView_GetItem( updateTree_, &native) != FALSE) {
			const auto *row = treeRowFromParameter( native.lParam) ;	// 正当な分類だけです。
			// 通常deviceのidentityを分類keyへ代用しません。
			if( row && row->kind == TreeRowKind::DEVICE_CLASS) {
				treeClassExpansion_.insert_or_assign(
					row->classKey, (TreeView_GetItemState( updateTree_, item, TVIS_EXPANDED) &
									TVIS_EXPANDED) != 0U) ;
			}
		}
	}

	std::unordered_map<std::wstring, std::wstring>
		choices ;	// 同sessionの明示指定をfilter切替で保持する。
	// 古いrowのindexをそのまま新しいdeviceへ持ち越さず、opaque候補IDも照合する。
	for( const auto &row : treeRows_) {
		// 有効な指定一候補だけを次の同device行へ移す。
		if( row.kind == TreeRowKind::DEVICE && row.hasCandidateChoice &&
		   row.explicitCandidateChoice && row.candidateIndex < candidates.size() &&
		   row.deviceIndex < candidates.size() &&
		   candidates[row.candidateIndex].deviceIdentity ==
			   candidates[row.deviceIndex].deviceIdentity) {
			choices.emplace( candidates[row.deviceIndex].deviceIdentity,
							candidates[row.candidateIndex].identity) ;
		}
	}

	updatingTreeChecks_ = true ;
	TreeView_DeleteAllItems( updateTree_) ;
	candidateItems_.assign( candidates.size(), nullptr) ;
	candidateRowIndexes_.assign( candidates.size(), candidates.size() * 2U) ;
	candidateResultTexts_.resize( candidates.size()) ;
	treeRows_.clear() ;
	treeRows_.reserve( candidates.size() * 2U) ;
	std::unordered_map<std::wstring, std::size_t> deviceGroups ;	// Opaque device別の有限group位置。
	std::vector<std::vector<std::size_t>>		  groups ;			// 現在観測と全候補を同じgroupへ保持する。
	std::vector<std::size_t> displayIndexes ;						// 各groupで現在属性を優先する表示元。
	// 候補vectorの順序を変えず、同deviceだけを一つの表示groupへまとめる。
	for( std::size_t index{}; index < candidates.size(); ++index) {
		const auto &candidate = candidates[index] ;	// 同scanの元候補。
		const auto [iterator, inserted] =
			// 同deviceのgroup。
			deviceGroups.try_emplace( candidate.deviceIdentity, groups.size()) ;
		// 新しいdeviceの初回だけ表示元と候補集合を追加する。
		if( inserted) {
			groups.emplace_back() ;
			displayIndexes.push_back( index) ;
		}

		groups[iterator->second].push_back( index) ;
		// Provider候補より後に来る場合も現在OS属性を優先する。
		if( candidate.current) {
			displayIndexes[iterator->second] = index ;
		}
	}

	std::unordered_map<std::wstring, HTREEITEM>	   classItems ;	// 種類GUID別のroot。
	std::unordered_map<std::wstring, std::wstring> classNames ;	// 種類説明の一回だけの照会。
	const auto unknown = loadString( IDS_VALUE_UNKNOWN) ;		// 欠損versionの表示。
	// 各deviceに一行だけ作り、現在・metadata・候補のchildを作らない。
	for( std::size_t groupIndex{}; groupIndex < groups.size(); ++groupIndex) {
		const auto &indexes		 = groups[groupIndex] ;			// 同deviceの全候補index。
		const auto	displayIndex = displayIndexes[groupIndex] ;	// 現在属性優先の表示元。
		const auto &device		 = candidates[displayIndex] ;	// 同じopaque deviceの元観測。
		const bool	recommended =
			std::any_of( indexes.begin(), indexes.end(), [this, &candidates]( const auto index) {
				return visibleInRecommendedFilter( candidates[index]) ;
			}) ; // Spanは同期構築中だけ借用し、filterはdevice単位で適用する。
		const bool hasExecutionResult =
			std::any_of( indexes.begin(), indexes.end(), [this]( const auto index) {
				return index < candidateResultTexts_.size() &&
					   !candidateResultTexts_[index].empty() ;
			}) ; // 失効後も明示対象の結果行をfilterで消しません。
		// Filterで除くdeviceの候補selectionは保持し、別deviceへ移さない。
		if( controller_.scanPurpose() == ScanPurpose::STANDARD && showRecommendedOnly_ &&
		   !recommended && !hasExecutionResult) {
			continue ;
		}

		std::wstring classKey		 = deviceClassKey( device.deviceClassGuid) ;	// 表示専用の種類。
		auto [nameIterator, newName] = classNames.try_emplace( classKey) ;			// 同じ種類の説明cache。
		// Windowsの種類説明は各種類につき一回だけ照会する。
		if( newName) {
			nameIterator->second = deviceClassName( classKey) ;
		}

		const auto className = nameIterator->second ;	// Map再配置から独立した説明。
		// 取得できない分類は一つのその他分類へ保持する。
		if( className.empty()) {
			classKey.clear() ;
		}

		const int imageIndex = deviceClassImageIndex( device) ;	// 標準の分類icon。
		auto [classIterator, newClass] =
			// 所属する分類root。
			classItems.try_emplace( classKey, nullptr) ;
		// 表示deviceがある種類だけを新規作成する。
		if( newClass) {
			TreeRow classRow{} ;	// Checkboxを持たない種類行。
			classRow.kind		  = TreeRowKind::DEVICE_CLASS ;
			classRow.classKey	  = classKey ;
			classRow.unknownClass = classKey.empty() ;
			classRow.className =
				classRow.unknownClass ? loadString( IDS_TREE_CLASS_UNKNOWN) : className ;
			classRow.primaryText = classRow.className ;
			treeRows_.push_back( std::move( classRow)) ;
			TVINSERTSTRUCTW insert{} ;	// 種類行と表示modelの対応。
			insert.hParent		= TVI_ROOT ;
			insert.hInsertAfter = TVI_LAST ;
			insert.item.mask =
				TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_STATE ;
			insert.item.pszText		   = treeRows_.back().primaryText.data() ;
			insert.item.lParam		   = static_cast<LPARAM>( treeRows_.size()) ;
			insert.item.iImage		   = classKey.empty() ? fallbackDeviceImageIndex_ : imageIndex ;
			insert.item.iSelectedImage = insert.item.iImage ;
			insert.item.stateMask	   = TVIS_STATEIMAGEMASK ;
			classIterator->second	   = TreeView_InsertItem( updateTree_, &insert) ;
		}

		// 分類挿入失敗時にdeviceをrootへ誤配置しない。
		if( classIterator->second == nullptr) {
			continue ;
		}

		TreeRow row{} ;	// 全候補を詳細へ保持する一device行。
		row.kind			 = TreeRowKind::DEVICE ;
		row.deviceIndex		 = displayIndex ;
		row.candidateIndexes = indexes ;
		row.primaryText		 = makeSingleLine( device.model.empty() ? device.title : device.model) ;
		// 名前欠損を記号だけの行や生IDで補わない。
		if( row.primaryText.empty() || row.primaryText == L"-" || row.primaryText == unknown) {
			row.primaryText = loadString( IDS_DEVICE_NAME_UNKNOWN) ;
		}

		row.currentVersion = device.current
								 ? makeSingleLine( device.version.empty() ? unknown : device.version)
								 : loadString( IDS_CURRENT_VERSION_UNMATCHED) ;
		const auto choice  = choices.find( device.deviceIdentity) ;	// Filter前の明示指定。
		// 同sessionの元candidate identityが存在する場合だけ指定を戻す。
		if( choice != choices.end()) {
			// 同deviceの候補だけを探し、名前・版の一致をidentityの代用にしない。
			for( const auto index : indexes) {
				// 実際のopaque candidate identityが一致した場合だけ採用する。
				if( candidates[index].identity == choice->second) {
					row.candidateIndex			= index ;
					row.hasCandidateChoice		= true ;
					row.explicitCandidateChoice = true ;
					break ;
				}
			}
		}

		treeRows_.push_back( std::move( row)) ;
		const auto		rowIndex = treeRows_.size() - 1U ;	// 同deviceの全候補が参照する行。
		TVINSERTSTRUCTW insert{} ;							// 分類直下の唯一のdevice item。
		insert.hParent		= classIterator->second ;
		insert.hInsertAfter = TVI_LAST ;
		insert.item.mask	= TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_STATE ;
		insert.item.pszText = treeRows_.back().primaryText.data() ;
		insert.item.lParam	= static_cast<LPARAM>( rowIndex + 1U) ;
		insert.item.iImage	= imageIndex ;
		insert.item.iSelectedImage = imageIndex ;
		insert.item.stateMask	   = TVIS_STATEIMAGEMASK ;
		const auto item = TreeView_InsertItem( updateTree_, &insert) ;	// 標準control所有のhandle。
		// 挿入失敗したdeviceへ候補選択を結合しない。
		if( item == nullptr) {
			continue ;
		}

		// 全候補は同じdevice行へ対応し、checkbox自体の解決は指定一候補だけに限定する。
		for( const auto index : indexes) {
			candidateItems_[index]		= item ;
			candidateRowIndexes_[index] = rowIndex ;
		}
	}

	applyCandidateSelectionToTree() ;
	updateDeviceClassSummaries() ;
	sortTreeItems() ;
	// 同じ正規分類だけへ元の開閉を戻し、新分類を自動展開しません。
	for( HTREEITEM item = TreeView_GetRoot( updateTree_); item != nullptr;
		item		   = TreeView_GetNextSibling( updateTree_, item)) {
		TVITEMW native{} ;	// 新規itemの同window内対応です。
		native.mask	 = TVIF_PARAM ;
		native.hItem = item ;
		// 挿入後に対応を解決できなかったitemは変更しません。
		if( TreeView_GetItem( updateTree_, &native) != FALSE) {
			const auto *row = treeRowFromParameter( native.lParam) ;	// 新候補集合の分類です。
			// 失われた分類から別分類へ開閉を移しません。
			if( row && row->kind == TreeRowKind::DEVICE_CLASS) {
				const auto prior =
					// 新分類には保存値がありません。
					treeClassExpansion_.find( row->classKey) ;
				TreeView_Expand( updateTree_, item,
								prior != treeClassExpansion_.end() && prior->second ? TVE_EXPAND
																					: TVE_COLLAPSE) ;
			}
		}
	}

	updatingTreeChecks_ = false ;
	InvalidateRect( updateTree_, nullptr, TRUE) ;
}

/** @see main_window.h 宣言側の契約を正本とします。 */
void MainWindow::refreshCandidateRows()
{
	std::unordered_map<std::wstring_view, std::vector<std::size_t>>
		groups ;	// 同期更新中だけ借用する元deviceです。
	// 追加候補を含む同deviceの全indexを集め、表示名や版で結合しません。
	for( std::size_t index{}; index < candidates_.size(); ++index) {
		groups[candidates_[index].deviceIdentity].push_back( index) ;
	}

	candidateItems_.resize( candidates_.size(), nullptr) ;
	candidateRowIndexes_.resize( candidates_.size(), treeRows_.size()) ;
	candidateResultTexts_.resize( candidates_.size()) ;
	const auto unknown = loadString( IDS_VALUE_UNKNOWN) ;	// 欠測を候補版で補いません。
	// 既存行だけを更新し、新しいdevice/classの挿入・削除・sortを行いません。
	for( std::size_t rowIndex{}; rowIndex < treeRows_.size(); ++rowIndex) {
		auto &row = treeRows_[rowIndex] ;	// 同itemの表示modelです。
		// 分類や元itemを失った行から新しい結合を作りません。
		if( row.kind != TreeRowKind::DEVICE || row.deviceIndex >= candidates_.size() ||
		   row.deviceIndex >= candidateItems_.size() || !candidateItems_[row.deviceIndex]) {
			continue ;
		}

		const auto item = candidateItems_[row.deviceIndex] ;	// 削除しない元native itemです。
		const auto found =
			// 元opaque deviceです。
			groups.find( candidates_[row.deviceIndex].deviceIdentity) ;
		// Append契約に反した欠測を別deviceの先頭へ補完しません。
		if( found == groups.end()) {
			continue ;
		}

		row.candidateIndexes = found->second ;
		// 元deviceの現在代表を優先し、追加された唯一候補も同じitemへ結合します。
		for( const auto index : row.candidateIndexes) {
			candidateItems_[index]		= item ;
			candidateRowIndexes_[index] = rowIndex ;
			// 読取専用の事後観測が追加された場合も、同じ行の現在列だけへ反映します。
			if( candidates_[index].current) {
				row.deviceIndex = index ;
			}
		}

		const auto &device = candidates_[row.deviceIndex] ;	// 分類と表示名は元行のままです。
		row.currentVersion = device.current
								 ? makeSingleLine( device.version.empty() ? unknown : device.version)
								 : loadString( IDS_CURRENT_VERSION_UNMATCHED) ;
	}
}

/** @see main_window.h 宣言側の契約を正本とします。 */
void MainWindow::applyPostInstallObservations( const InstallResult &result,
											  const ScanSessionId  scanSessionId)
{
	std::unordered_set<std::wstring> devices ;	// 今回の実行結果へ一意に結合した対象です。
	// 未選択/未知の観測DTOから任意の一覧行を更新しません。
	for( const auto &update : result.updates) {
		const auto found =
			std::find_if( candidates_.begin(), candidates_.end(), [&update]( const auto &candidate) {
				return candidate.identity == update.identity ;
			}) ; // 元candidate identityだけを解決します。
		// 元候補が保持されている場合だけ同deviceを対象へ加えます。
		if( found != candidates_.end()) {
			devices.insert( found->deviceIdentity) ;
		}
	}

	// 対象deviceごとに一つの事後観測だけを受理します。
	for( const auto &device : devices) {
		const PostInstallDeviceObservation *observed{} ;	// 同deviceの元DTOです。借用だけです。
		std::size_t							count{} ;		// 重複した観測は全て拒否します。
		// 選択に結合しない他deviceのDTOは適用しません。
		for( const auto &value : result.currentDevices) {
			// 同deviceの正確な個数を数え、一部だけ採用しません。
			if( value.observation.deviceIdentity == device) {
				observed = &value ;
				++count ;
			}
		}

		const bool valid = count == 1U && observed && observed->error == 0U &&
						   scanSessionId != 0U &&
						   isDeviceObservationBound( observed->observation, scanSessionId,
													device) ;	// 元scanの読取専用結合です。
		bool represented{} ;									// 現在行を更新できた場合trueです。
		// 同deviceの現在代表だけを変更し、候補の版/署名/導入計画を現在値へ書き換えません。
		for( auto &candidate : candidates_) {
			// 他deviceと候補metadataを更新対象にしません。
			if( candidate.deviceIdentity != device || !candidate.current) {
				continue ;
			}

			represented = true ;
			candidate.version.clear() ;
			candidate.provider.clear() ;
			candidate.driverDate.clear() ;
			candidate.deviceObservation.reset() ;
			// 確認不能は旧Code28/旧版を現在観測として残さず、名前/classは識別用の前回値を保持します。
			if( !valid) {
				continue ;
			}

			candidate.deviceObservation = observed->observation ;
			candidate.version			= observed->version ;
			candidate.provider			= observed->provider ;
			candidate.driverDate		= observed->driverDate ;
			candidate.manufacturer		= observed->manufacturer ;
			candidate.driverClass		= observed->driverClass ;
			candidate.deviceClassGuid	= observed->deviceClassGuid ;
			// 実際に読めた名前だけを反映し、候補titleから製品名を補完しません。
			if( !observed->name.empty()) {
				candidate.model = observed->name ;
				candidate.title = observed->name ;
			}
		}

		// 元一覧に現在行がないProvider候補も、実観測がある場合だけ表示専用代表を追加します。
		if( valid && !represented) {
			UpdateCandidate current ;	// 新しい導入能力を持たない現在観測です。
			current.identity = L"post-current:" + std::to_wstring( scanSessionId) + L":" + device ;
			current.deviceIdentity	  = device ;
			current.current			  = true ;
			current.providerId		  = DRIVER_STORE_PROVIDER_ID ;
			current.discoveryBasis	  = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
			current.audit			  = makeWindowsManagedCandidateAudit( true) ;
			current.model			  = observed->name ;
			current.title			  = observed->name ;
			current.manufacturer	  = observed->manufacturer ;
			current.driverClass		  = observed->driverClass ;
			current.deviceClassGuid	  = observed->deviceClassGuid ;
			current.provider		  = observed->provider ;
			current.version			  = observed->version ;
			current.driverDate		  = observed->driverDate ;
			current.deviceObservation = observed->observation ;
			candidates_.push_back( std::move( current)) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::displayInstallResult( const InstallResult &result,
									  const ScanSessionId  scanSessionId)
{
	updatingTreeChecks_ = true ;
	candidateResultTexts_.resize( candidates_.size()) ;
	// Scan session失効後は全候補を表示専用にし、明示的な再検索まで再選択させない。
	for( std::size_t index = 0; index < candidates_.size(); ++index) {
		UpdateCandidate &candidate = candidates_[index] ;	// Session失効を反映する表示候補。
		candidate.installable	   = false ;
		candidate.preparationTargetIdentity.clear() ;
		// install後に失効した候補の保持中選択を解除する。
		if( index < candidateSelected_.size()) {
			candidateSelected_[index] = false ;
		}

		// Candidate identityと一致する個別実行結果。
		const auto updateResult =
			std::find_if( result.updates.begin(), result.updates.end(),
						 [&candidate]( const UpdateExecutionResult &itemResult) {
							 return itemResult.identity == candidate.identity ;
						 }) ;
		// 個別結果のない候補に他候補の導入結果を流用しない。
		if( updateResult == result.updates.end()) {
			continue ;
		}

		std::wstring statusText ;	// Download/install結果を示す候補別status。
		// 復元ポイント未作成による中止を候補ごとの結果にも示す。
		if( result.restorePointCreation.outcome == OutcomeCode::FAILURE) {
			statusText = loadString( IDS_RESTORE_POINT_NOT_CREATED) ;
		}
		// download未成功をinstall失敗やinstall成功と区別して表示する。
		else if( updateResult->downloadOutcome != OutcomeCode::SUCCESS &&
				updateResult->downloadOutcome != OutcomeCode::SUCCEEDED_WITH_ERRORS) {
			statusText =
				loadString( IDS_DOWNLOAD_FAILED) +
				formatOperationError( updateResult->downloadError, updateResult->downloadOutcome) ;
		}
		// installが成功または警告付き成功となった候補に導入済み結果を示す。
		else if( updateResult->installerHandoff) {
			statusText = loadString( updateResult->handoffOutcome == OutcomeCode::SUCCESS
										? IDS_INDEX_INSTALLER_COMPLETED
										: IDS_INDEX_INSTALLER_FAILED) ;
			// 起動失敗と原exit codeを個別結果として保持し、driver導入済みにしません。
			if( updateResult->installerExitCode) {
				statusText += L" (exit " + std::to_wstring( *updateResult->installerExitCode) + L")" ;
			}

			// 引継ぎの原診断を導入結果と別に表示します。
			if( updateResult->handoffError != 0) {
				statusText +=
					formatOperationError( updateResult->handoffError, updateResult->handoffOutcome) ;
			}
		}
		// 役割別事実を保持し、base成功やstageから全構成完了を推測しません。
		else if( !updateResult->requiredRoles.empty()) {
			statusText = loadString( IDS_INDEX_PLAN_RESULTS) ;
			// 各未実行/変更済み/未確認結果を同一候補に保持します。
			for( const auto &role : updateResult->requiredRoles) {
				const auto roleName =
					loadString( role.role == DriverPlanRole::BASE_DRIVER ? IDS_INDEX_ROLE_BASE
							   : role.role == DriverPlanRole::EXTENSION
								   ? IDS_INDEX_ROLE_EXTENSION
								   : IDS_INDEX_ROLE_COMPONENT) ;	// 非秘密roleです。
				std::wstring fact ;									// 推測しない実処理段階です。
				// 失敗とpendingを成功から分離します。
				switch( role.reflection) {
					// stage済みでも適用未確認を成功へ補完しません。
					case DriverPlanReflectionState::WINDOWS_PENDING:
						fact = loadString( IDS_INDEX_ROLE_PENDING) ;
						break ;

					// 指定APIの完了だけを表示し実状態の完了を推測しません。
					case DriverPlanReflectionState::INSTALL_API_COMPLETED:
						fact = loadString( IDS_INDEX_ROLE_API_COMPLETED) ;
						break ;

					// package登録と指定導入を区別します。
					case DriverPlanReflectionState::STAGED:
						fact = loadString( IDS_INDEX_ROLE_STAGED) ;
						break ;

					// 役割の元stage/install診断を個別に保持します。
					case DriverPlanReflectionState::FAILED:
						fact = loadString( IDS_INSTALL_FAILED) +
							   formatOperationError( role.installError ? role.installError
																	  : role.stageError,
													OutcomeCode::FAILURE) ;
						break ;

					// 実行していない役割を導入済みへ換算しません。
					default:
						fact = loadString( IDS_NOT_INSTALLED) ;
						break ;
				}

				// 内部補完HRESULTをWindowsが実際に返した診断として表示しません。
				if( role.installDiagnosticMissing) {
					fact += loadString( IDS_INDEX_ROLE_DIAGNOSTIC_MISSING) ;
				}

				statusText += L" | " + roleName + L": " + fact ;
			}
		}
		// 実指定導入の成功だけを導入済みと表示します。
		else if( updateResult->installOutcome == OutcomeCode::SUCCESS ||
				updateResult->installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) {
			statusText = loadString( IDS_INSTALL_SUCCEEDED) ;
		}
		// installが開始されていない候補を導入失敗と混同しない。
		else if( updateResult->installOutcome == OutcomeCode::NOT_STARTED) {
			statusText = loadString( IDS_NOT_INSTALLED) ;
		} else {
			statusText =
				loadString( IDS_INSTALL_FAILED) +
				formatOperationError( updateResult->installError, updateResult->installOutcome) ;
		}

		candidateResultTexts_[index] = statusText ;
		// 候補と表示行の対応範囲を確認してから、診断や必要構成を詳細へ分離した要約を表示する。
		if( index < candidateRowIndexes_.size() && candidateRowIndexes_[index] < treeRows_.size()) {
			auto &row = treeRows_[candidateRowIndexes_[index]] ;	// 実行対象deviceの唯一の表示行。
			const UINT summary =
				result.restorePointCreation.outcome == OutcomeCode::FAILURE
					? IDS_RESTORE_POINT_NOT_CREATED
				: updateResult->downloadOutcome != OutcomeCode::SUCCESS &&
						updateResult->downloadOutcome != OutcomeCode::SUCCEEDED_WITH_ERRORS
					? IDS_DOWNLOAD_FAILED
				: updateResult->installerHandoff
					? (updateResult->handoffOutcome == OutcomeCode::SUCCESS
						   ? IDS_INDEX_INSTALLER_COMPLETED
						   : IDS_INDEX_INSTALLER_FAILED)
				: !updateResult->requiredRoles.empty() ? IDS_DEVICE_RESULT_ROLES
				: updateResult->installOutcome == OutcomeCode::SUCCESS ||
						updateResult->installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS
					? IDS_INSTALL_SUCCEEDED
				: updateResult->installOutcome == OutcomeCode::NOT_STARTED
					? IDS_NOT_INSTALLED
					: IDS_INSTALL_FAILED ;	// 実状態は個別結果と事後観測のまま保持する。
			row.status = loadString( summary) + L" / " + loadString( IDS_DEVICE_RESULT_DETAILS) ;
			row.candidateVersion = makeSingleLine(
				candidate.version.empty() ? loadString( IDS_VALUE_UNKNOWN) : candidate.version) ;
		}
	}

	applyPostInstallObservations( result, scanSessionId) ;
	refreshCandidateRows() ;
	// 元行の分類・表示名・個別結果を保持し、実際に読めた同deviceの現在状態だけを付記します。
	for( auto &row : treeRows_) {
		// 種類行と無関係deviceを導入成功へ変えません。
		if( row.kind != TreeRowKind::DEVICE || row.deviceIndex >= candidates_.size()) {
			continue ;
		}

		const auto &device = candidates_[row.deviceIndex] ;	// 事後観測を優先した現在代表です。
		// 結果を持たない行へ別deviceの短文を流用しません。
		if( !std::ranges::any_of( row.candidateIndexes, [this]( const auto index) {
			   return index < candidateResultTexts_.size() && !candidateResultTexts_[index].empty() ;
		   })) {
			continue ;
		}

		// Nodeを実際に読めた場合だけ現在の登録/問題状態を表示します。
		if( device.deviceObservation &&
		   device.deviceObservation->node.read.state == DevicePropertyReadState::VALUE) {
			const auto &observation = *device.deviceObservation ;	// 元問題Codeと登録根拠です。
			row.status +=
				L" / " +
				loadString( observation.driverPresence == DeviceDriverPresence::NOT_INSTALLED
							   ? IDS_DEVICE_PRESENCE_NOT_INSTALLED
						   : observation.driverPresence == DeviceDriverPresence::REGISTERED
							   ? IDS_DEVICE_PRESENCE_REGISTERED
							   : IDS_DEVICE_PRESENCE_UNKNOWN) ;
			// 古いCodeを新しい観測へ引き継ぎません。
			if( observation.node.problemCode) {
				row.status +=
					L" / " + formatResource( IDS_DEVICE_PROBLEM,
											std::to_wstring( *observation.node.problemCode)) ;
			}
		} else {
			row.status += L" / " + loadString( IDS_DEVICE_POST_INSTALL_UNKNOWN) ;
		}

		// 個別対象の再起動待ちをAPI成功や現在観測で消しません。
		if( std::any_of(
			   result.updates.begin(), result.updates.end(), [this, &device]( const auto &update) {
				   return update.rebootRequired &&
						  std::any_of( candidates_.begin(), candidates_.end(),
									  [&update, &device]( const auto &candidate) {
										  return candidate.identity == update.identity &&
												 candidate.deviceIdentity == device.deviceIdentity ;
									  }) ;
			   })) {
			row.status += L" / " + loadString( IDS_DEVICE_POST_INSTALL_REBOOT) ;
		}
	}

	applyCandidateSelectionToTree() ;
	updateDeviceClassSummaries( true) ;
	updatingTreeChecks_ = false ;
	// 更新した版や結果で並べ替えず、元itemの選択行と表示位置を維持します。
	InvalidateRect( updateTree_, nullptr, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<std::size_t> MainWindow::checkedCandidateIndexes() const
{
	std::vector<std::size_t> indexes ;	// 同deviceの指定一候補だけを返す。
	// 候補ごとの保持selectionと、device行に明示結合した候補の両方を確認する。
	for( std::size_t index{}; index < candidates_.size(); ++index) {
		// 一つのchecked deviceから同deviceの全候補を要求へ入れない。
		if( !isSelectableCandidate( candidates_[index]) || index >= candidateSelected_.size() ||
		   !candidateSelected_[index] || index >= candidateItems_.size() ||
		   candidateItems_[index] == nullptr || index >= candidateRowIndexes_.size() ||
		   candidateRowIndexes_[index] >= treeRows_.size()) {
			continue ;
		}

		const auto &row = treeRows_[candidateRowIndexes_[index]] ;	// 当該deviceの唯一の表示行。
		// Checkboxが結合する元一候補だけを採用し、表示名から対象を推測しない。
		if( row.kind == TreeRowKind::DEVICE && row.hasCandidateChoice &&
		   row.candidateIndex == index &&
		   TreeView_GetCheckState( updateTree_, candidateItems_[index]) != FALSE) {
			indexes.push_back( index) ;
		}
	}

	return indexes ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::handleTreeCheckChange( const HTREEITEM item, const bool checked)
{
	TVITEMW nativeItem{} ;	// 通知されたitemだけのrow parameter。
	nativeItem.mask	 = TVIF_PARAM ;
	nativeItem.hItem = item ;
	// 解決できないitemを元候補の選択へ変換しない。
	if( TreeView_GetItem( updateTree_, &nativeItem) == FALSE) {
		return ;
	}

	const auto *row = treeRowFromParameter( nativeItem.lParam) ;	// Modalを開く前だけ借用する行。
	// readonlyの元枠を実行selectionへ変換せず、元画像だけを復元します。
	if( row && row->readonlyCheckbox) {
		applyCandidateSelectionToTree() ;
		return ;
	}

	// 種類や失効・閲覧専用の行へ強制付与されたcheckを直ちに除く。
	if( row == nullptr || row->kind != TreeRowKind::DEVICE ||
	   controller_.state() != ApplicationState::SCAN_READY ||
	   controller_.scanPurpose() != ScanPurpose::STANDARD ||
	   std::none_of(
		   row->candidateIndexes.begin(), row->candidateIndexes.end(), [this]( const auto index) {
			   return index < candidates_.size() && isSelectableCandidate( candidates_[index]) ;
		   })) {
		updatingTreeChecks_ = true ;
		TreeView_SetItemState( updateTree_, item, 0, TVIS_STATEIMAGEMASK) ;
		updatingTreeChecks_ = false ;
		return ;
	}

	// 有効な通常枠への明示操作だけで、そのdeviceの古い表示意図を置き換えます。
	std::erase_if( preparationDisplayBindings_, [&]( const auto &binding) {
		return binding.deviceIdentity == candidates_[row->deviceIndex].deviceIdentity ;
	}) ;
	// 解除では候補identityを選び直さず、当該deviceの保持selectionだけを除く。
	if( !checked) {
		// 非表示も含む当該deviceの全候補を解除する。
		for( const auto index : row->candidateIndexes) {
			// 選択状態との範囲不一致を参照しない。
			if( index < candidateSelected_.size()) {
				candidateSelected_[index] = false ;
			}
		}

		applyCandidateSelectionToTree() ;
		return ;
	}

	// 唯一または詳細で指定済みの一候補だけをdevice checkboxへ結合する。
	if( row->hasCandidateChoice) {
		static_cast<void>( selectDeviceCandidate( row->candidateIndex)) ;
		return ;
	}

	// 複数候補が未指定ならcheckを戻し、利用者が詳細で一件を指定するまで未選択に保つ。
	applyCandidateSelectionToTree() ;
	TreeView_SelectItem( updateTree_, item) ;
	static_cast<void>( showSelectedCandidateDetails()) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
const MainWindow::TreeRow *MainWindow::treeRowFromParameter( const LPARAM parameter) const noexcept
{
	// 未設定や負のitem parameterを行indexとして参照しない。
	if( parameter <= 0) {
		return nullptr ;
	}

	const std::size_t rowIndex = static_cast<std::size_t>( parameter - 1) ;	// 0始まりrow index。
	return rowIndex < treeRows_.size() ? &treeRows_[rowIndex] : nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatCandidateDiscoveryBasis( const UpdateCandidate &candidate) const
{
	// 検出経路を公式catalog・Web・手動取込の区分へ変換する。
	switch( candidate.discoveryBasis) {
		// 構造化公式 catalog 由来を level A として表示する。
		case CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG:
			return loadString( IDS_DISCOVERY_LEVEL_A) ;
		// 公式 Web page 由来を level B として表示する。
		case CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE:
			return loadString( IDS_DISCOVERY_LEVEL_B) ;
		// 利用者が指定した package を level C として表示する。
		case CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE:
			return loadString( IDS_DISCOVERY_LEVEL_C) ;
		// 収集者確認を公式live探索levelへ偽装しません。
		case CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION:
			return loadString( IDS_DISCOVERY_INDEX) ;
		// Windows 管理取得元は公式 Web 探索 level の対象外として共通分岐へ進む。
		case CandidateDiscoveryBasis::MANAGED_SERVICE:
		// Local inventory には公式 Web 探索 level を付与しない。
		case CandidateDiscoveryBasis::LOCAL_INVENTORY:
			return {} ;
		// 未指定の探索根拠は不明表示の共通分岐へ進む。
		case CandidateDiscoveryBasis::UNSPECIFIED:
		// 未知の探索根拠へ確認済み level を付けない。
		default:
			return loadString( IDS_VALUE_UNKNOWN) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatCandidateAuditGate( const CandidateAuditGateState state,
												  const UINT					passedResourceId,
												  const UINT pendingResourceId) const
{
	// 未監査・合格・Windows委譲を区別し、監査gateの状態を表示する。
	switch( state) {
		// 対象外の監査 gate は合否と区別して表示する。
		case CandidateAuditGateState::NOT_APPLICABLE:
			return loadString( IDS_AUDIT_NOT_APPLICABLE) ;
		// 未完了 gate は監査種類に応じた保留表示を使用する。
		case CandidateAuditGateState::PENDING:
			return loadString( pendingResourceId) ;
		// 合格 gate は監査種類に応じた完了表示を使用する。
		case CandidateAuditGateState::PASSED:
			return loadString( passedResourceId) ;
		// Windows に委譲する判定を独自監査の合格と区別する。
		case CandidateAuditGateState::MANAGED_BY_WINDOWS:
			return loadString( IDS_AUDIT_WINDOWS_MANAGED) ;
		// Provider による検証を Windows 管理の判定と区別する。
		case CandidateAuditGateState::PROVIDER_VALIDATED:
			return loadString( IDS_AUDIT_PROVIDER_VALIDATED) ;
		// 利用者提供の未検証情報を合格として表示しない。
		case CandidateAuditGateState::USER_PROVIDED_UNVERIFIED:
			return loadString( IDS_AUDIT_USER_UNVERIFIED) ;
		// 監査拒否を専用の gate 表示にする。
		case CandidateAuditGateState::REJECTED:
			return loadString( IDS_AUDIT_REJECTED) ;
		// 監査実行の失敗を不適合の拒否と区別する。
		case CandidateAuditGateState::FAILURE:
			return loadString( IDS_AUDIT_FAILED) ;
	}

	return loadString( IDS_AUDIT_FAILED) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatCandidateAudit( const UpdateCandidate &candidate) const
{
	// 現在属性だけの列挙をcompatible listや導入準備の監査合格とは表示しない。
	if( candidate.current) {
		return loadString( IDS_METADATA_CURRENT_ROW) ;
	}

	// 情報検索の許諾状態を取得済み・監査済みの判定へ転用しない。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY && !candidate.current) {
		const auto license =
			candidate.metadataDistribution
				? candidate.metadataDistribution->license
				: MetadataLicenseStatus::UNRESOLVED ;	// 欠損した許諾条件も未確定として表示する。
		return loadString( IDS_METADATA_ROW) + L" / " +
			   loadString( license == MetadataLicenseStatus::ACCEPTANCE_BEFORE_DOWNLOAD
							  ? IDS_METADATA_TERMS_REQUIRED
						  : license == MetadataLicenseStatus::CONFIRMED_NO_CONSENT
							  ? IDS_METADATA_TERMS_NOT_REQUIRED
							  : IDS_METADATA_TERMS_UNKNOWN) +
			   L" / " + formatCandidateAssessment( candidate) ;
	}

	const CandidateAuditStatus &audit = candidate.audit ;	// 表示対象の監査状態。
	const std::wstring			origin =
		formatCandidateAuditGate( audit.sourceOrigin, IDS_AUDIT_ORIGIN_PASSED,
								 IDS_AUDIT_ORIGIN_PENDING) ;	// 取得元確認の表示値。
	const std::wstring download =
		formatCandidateAuditGate( audit.inspectionDownload, IDS_AUDIT_DOWNLOAD_PASSED,
								 IDS_AUDIT_DOWNLOAD_PENDING) ;	// 検査用downloadの表示値。
	const std::wstring content =
		formatCandidateAuditGate( audit.contentIntegrity, IDS_AUDIT_CONTENT_PASSED,
								 IDS_AUDIT_CONTENT_PENDING) ;	// Package内容監査の表示値。
	const std::wstring system =
		formatCandidateAuditGate( audit.systemApplicability, IDS_AUDIT_SYSTEM_PASSED,
								 IDS_AUDIT_SYSTEM_PENDING) ;	// 現在system適用性の表示値。

	std::wstring readiness ;	// Install workflow準備状態の表示値。
	// 閲覧専用・監査待ち・準備完了・拒否を導入準備状態として区別する。
	switch( audit.installReadiness) {
		// 表示専用候補は導入可能と誤表示しない。
		case CandidateInstallReadiness::DISPLAY_ONLY:
			readiness = loadString( IDS_INSTALL_READINESS_DISPLAY_ONLY) ;
			break ;

		// 監査待ち候補は導入準備の未完了を示す。
		case CandidateInstallReadiness::AUDIT_PENDING:
			readiness = loadString( IDS_INSTALL_READINESS_AUDIT_PENDING) ;
			break ;

		// 導入準備が成立した候補には準備完了を表示する。
		case CandidateInstallReadiness::READY:
			readiness = loadString( IDS_INSTALL_READINESS_READY) ;
			break ;

		// 導入を許可できない候補は blocked 状態として表示する。
		case CandidateInstallReadiness::BLOCKED:
			readiness = loadString( IDS_INSTALL_READINESS_BLOCKED) ;
			break ;

		// 未知の準備状態も導入不可の表示にする。
		default:
			readiness = loadString( IDS_INSTALL_READINESS_BLOCKED) ;
			break ;
	}

	return loadString( IDS_AUDIT_ORIGIN_LABEL) + origin + L" / " +
		   loadString( IDS_AUDIT_DOWNLOAD_LABEL) + download + L" / " +
		   loadString( IDS_AUDIT_CONTENT_LABEL) + content + L" / " +
		   loadString( IDS_AUDIT_SYSTEM_LABEL) + system + L" / " +
		   loadString( IDS_AUDIT_INSTALL_LABEL) + readiness + L" / " +
		   formatCandidateAssessment( candidate) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatCandidateText( const UpdateCandidate &candidate) const
{
	const std::wstring unknown = loadString( IDS_VALUE_UNKNOWN) ;	// 欠損metadataの代替表示。
	// 表示用driver version。
	const auto		  &displayVersion =
		   candidate.metadataDistribution
				   ? candidate.metadataDistribution->version
				   : candidate.version ;	// 読み上げでも現在INF版と明示配布版を区別する。
	const std::wstring version =
		// 欠損を未知として補完した版。
		displayVersion.empty() ? unknown : displayVersion ;
	// 表示用driver provider名。
	const std::wstring provider = candidate.provider.empty() ? unknown : candidate.provider ;
	// 表示用driver日付。
	const std::wstring date = candidate.driverDate.empty() ? unknown : candidate.driverDate ;
	// 表示用取得元名称。
	std::wstring	   source	 = candidate.sourceName.empty() ? unknown : candidate.sourceName ;
	const std::wstring discovery =	// 公式候補の場合だけ表示する探索区分。
		formatCandidateDiscoveryBasis( candidate) ;
	// 検出経路の補足を読み上げ用の取得元文字列にも含める。
	if( !discovery.empty()) {
		source = L"[" + discovery + L"] " + source ;
	}

	// 表示用取得場所またはtrust boundary。
	const std::wstring location =
		candidate.sourceLocation.empty() ? unknown : candidate.sourceLocation ;
	const std::wstring state = formatCandidateState( candidate) ;	// Candidate操作分類。
	const std::wstring audit = formatCandidateAudit( candidate) ;	// Candidate監査到達状態。
	const std::wstring size =
		// Download sizeまたはlocal状態。
		formatCandidateSize( candidate, unknown) ;

	// Providerが提示した候補名または欠損時の代替表示。
	const std::wstring title = candidate.title.empty() ? unknown : candidate.title ;
	// TreeView childへ設定するmetadataと取得元の連結文字列。
	std::wstring	   text =
		L"[" + state + L"] " + title + L" | " +
		loadString( candidate.metadataDistribution ? IDS_METADATA_DISTRIBUTION_VERSION
				   : !candidate.installable && !candidate.preparationTargetIdentity.empty()
					   ? IDS_REFERENCE_VERSION
					   : IDS_VERSION_LABEL) +
		L": " + version + L" | " + provider + L" | " + date + L" | " +
		loadString( IDS_SOURCE_LABEL) + L": " + source + L" — " + location + L" | " + size + L" | " +
		audit + L" | " + loadString( IDS_ASSESSMENT_HINT) ;
	// 標準TreeViewの完全item textへ、視覚列だけでは省略される製品属性と現在版を残す。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) {
		const auto current =
			std::find_if( candidates_.begin(), candidates_.end(), [&candidate]( const auto &entry) {
				return entry.current && entry.deviceIdentity == candidate.deviceIdentity ;
			}) ; // 同じsnapshot内で対応した現在INF版だけを参照する。
		text +=
			L" | " + loadString( IDS_COLUMN_MANUFACTURER) + L": " +
			(candidate.manufacturer.empty() ? unknown : candidate.manufacturer) + L" | " +
			loadString( IDS_COLUMN_MODEL) + L": " +
			(candidate.model.empty() ? unknown : candidate.model) + L" | " +
			loadString( IDS_COLUMN_CLASS) + L": " +
			(candidate.driverClass.empty() ? unknown : candidate.driverClass) + L" | " +
			loadString( IDS_CURRENT_VERSION_LABEL) + L": " +
			(current == candidates_.end() || current->version.empty() ? unknown : current->version) ;
	}

	// 任意候補であることを読み上げ用の説明にも含める。
	if( candidate.browseOnly) {
		text += L" | " + loadString( IDS_VALUE_OPTIONAL) ;
	}

	return makeSingleLine( text) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatCandidateState( const UpdateCandidate &candidate) const
{
	// 現在構成flagをdriver存在の保証にせず、metadata-onlyでも観測を優先する。
	if( candidate.current) {
		return formatDeviceObservation( candidate) ;
	}

	// 初回導入を更新・再導入へ分類せず、方式の可否は候補監査で別表示します。
	if( candidate.action == DriverAction::INITIAL_INSTALL) {
		return loadString( IDS_ACTION_INITIAL_INSTALL) ;
	}

	// 全metadata行は現在属性または配布情報であり、更新／旧版／推奨へ分類しない。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) {
		return loadString( IDS_METADATA_ROW) ;
	}

	// 取得前の比較分類は実導入actionへ変換せず、未検査として表示します。
	if( !candidate.installable && !candidate.preparationTargetIdentity.empty() &&
	   candidate.providerId == SIGNED_INDEX_PROVIDER_ID) {
		const auto relation = classifyPendingReferenceVersion(
			candidate, candidates_, controller_.scanSessionId()) ;	// 同現在観測との比較だけです。
		return loadString( relation == PendingReferenceVersion::NEWER   ? IDS_REFERENCE_NEWER
						  : relation == PendingReferenceVersion::SAME  ? IDS_REFERENCE_SAME
						  : relation == PendingReferenceVersion::OLDER ? IDS_REFERENCE_OLDER
																	   : IDS_REFERENCE_UNKNOWN) ;
	}

	std::wstring state ;	// 操作分類、観測差分、同一版取得元情報を連結する表示値。
	// Web配布情報の行は現在使用中driverと区別して監査状況を示す。
	if( candidate.discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE &&
	   !candidate.installable && !candidate.current && candidate.action == DriverAction::NONE) {
		// 配布情報と導入可否を区別し、取得後に「未監査」と固定表示しない。
		state = loadString( candidate.audit.inspectionDownload == CandidateAuditGateState::PASSED
							   ? IDS_PREPARATION_AUDITED_ROW
							   : IDS_OFFICIAL_RELEASE_DISCOVERY_STATE) ;
	}
	// 推奨候補には通常の操作種別に代えて推奨更新の状態を示す。
	else if( candidate.recommended) {
		state = loadString( IDS_RECOMMENDED_UPDATE) ;
	} else {
		// 現在・推奨以外の候補は更新・同版・旧版の操作を区別して表示する。
		switch( candidate.action) {
			// 更新候補には通常更新の操作名称を付ける。
			case DriverAction::UPDATE:
				state = loadString( IDS_ACTION_UPDATE) ;
				break ;

			// 再導入候補を通常更新と別の名称で表示する。
			case DriverAction::REINSTALL:
				state = loadString( IDS_ACTION_REINSTALL) ;
				break ;

			// 旧版候補には downgrade の操作名称を付ける。
			case DriverAction::DOWNGRADE:
				state = loadString( IDS_ACTION_DOWNGRADE) ;
				break ;

			// 操作のない非代表行を現在使用中と推測せず、表示専用とする。
			case DriverAction::NONE:
			// 未知の操作も実行状態を推測しない。
			default:
				state = loadString( IDS_METADATA_ROW) ;
				break ;
		}
	}

	// 保存された公式release観測差分がある場合にだけ比較情報を付記する。
	if( candidate.releaseObservationDifference.has_value()) {
		UINT observationResourceId{} ;	// 過大評価しない観測差分のresource ID。
		// 初回観測・metadata一致・hash一致を異なる強さの情報として表示する。
		switch( *candidate.releaseObservationDifference) {
			// 初めて確認した配布情報には初回観測の名称を付ける。
			case ReleaseObservationDifference::FIRST_OBSERVATION:
				observationResourceId = IDS_RELEASE_OBSERVATION_FIRST ;
				break ;

			// 公開 metadata が変わらない観測には同一情報の名称を付ける。
			case ReleaseObservationDifference::METADATA_UNCHANGED:
				observationResourceId = IDS_RELEASE_OBSERVATION_METADATA_SAME ;
				break ;

			// 強い内容識別値が変わらない観測には hash 同一の表示を使用する。
			case ReleaseObservationDifference::STRONG_IDENTITY_UNCHANGED:
				observationResourceId = IDS_RELEASE_OBSERVATION_HASH_SAME ;
				break ;

			// 取得元 binding の変更は変更ありの共通表示へ進む。
			case ReleaseObservationDifference::SOURCE_BINDING_CHANGED:
			// Device binding の変更は変更ありの共通表示へ進む。
			case ReleaseObservationDifference::DEVICE_BINDING_CHANGED:
			// OS の変更は変更ありの共通表示へ進む。
			case ReleaseObservationDifference::OPERATING_SYSTEM_CHANGED:
			// Device 構成の変更は変更ありの共通表示へ進む。
			case ReleaseObservationDifference::DEVICE_CONFIGURATION_CHANGED:
			// Policy の変更は変更ありの共通表示へ進む。
			case ReleaseObservationDifference::POLICY_CHANGED:
			// Parser の変更は変更ありの共通表示へ進む。
			case ReleaseObservationDifference::PARSER_CHANGED:
			// 配布情報の変更は変更ありの共通表示へ進む。
			case ReleaseObservationDifference::RELEASE_CHANGED:
			// 内容識別値の変更は変更ありの共通表示へ進む。
			case ReleaseObservationDifference::CONTENT_IDENTITY_CHANGED:
			// 保留理由を含む差分は変更ありとして表示する。
			case ReleaseObservationDifference::PENDING_REASON_CHANGED:
				observationResourceId = IDS_RELEASE_OBSERVATION_CHANGED ;
				break ;

			// 無効な比較は同一情報と表示せず再評価の共通表示へ進む。
			case ReleaseObservationDifference::INVALID:
			// 未知の差分分類も再評価として表示する。
			default:
				observationResourceId = IDS_RELEASE_OBSERVATION_REEVALUATED ;
				break ;
		}

		state += L" / " + loadString( observationResourceId) ;
	}

	// 同一版を扱う取得元が複数ある場合にだけgroup件数を示す。
	if( candidate.equivalentSourceCount > 1) {
		state += L" / " + formatResource( IDS_EQUIVALENT_SOURCES,
										 std::to_wstring( candidate.equivalentSourceCount)) ;
		// 同一版groupの初期選択取得元にだけ既定取得元の注記を付ける。
		if( candidate.preferredSource) {
			state += L" / " + loadString( IDS_PREFERRED_SOURCE) ;
		}
	}

	return state ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatCandidateSize( const UpdateCandidate	&candidate,
											 const std::wstring_view unknown) const
{
	// 情報検索では正確な公表値と概算を区別し、現在属性だけでpayload保持を推測しない。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY) {
		// 公表された正確なbyte数だけを非概算の値として表示する。
		if( !candidate.current && candidate.maximumDownloadBytes > 0U) {
			return formatResource( IDS_METADATA_EXACT_BYTES,
								  std::to_wstring( candidate.maximumDownloadBytes)) ;
		}

		// 公表概算はdownload上限や実測値へ読み替えない。
		if( !candidate.current && !candidate.displayDownloadSize.empty()) {
			return formatResource( IDS_METADATA_APPROXIMATE_SIZE,
								  makeSingleLine( candidate.displayDownloadSize)) ;
		}

		return std::wstring( unknown) ;
	}

	// 数値のdownload上限が判明している候補では容量表記を優先する。
	if( candidate.maximumDownloadBytes > 0) {
		return formatByteSize( candidate.maximumDownloadBytes, unknown) ;
	}

	// 数値容量がない場合はProviderの表示用容量を一行へ整えて使用する。
	if( !candidate.displayDownloadSize.empty()) {
		return makeSingleLine( candidate.displayDownloadSize) ;
	}

	// Driver Store候補はnetwork容量ではなくlocal取得済み状態を表示する。
	if( candidate.sourceName == L"Windows Driver Store") {
		return loadString( IDS_LOCAL_CACHED) ;
	}

	return std::wstring( unknown) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::loadString( const UINT resourceId) const
{
	constexpr int MAXIMUM_RESOURCE_CHARACTERS = 2048 ;										// UI文字列の最大UTF-16文字数。
	std::wstring  value( static_cast<std::size_t>( MAXIMUM_RESOURCE_CHARACTERS), L'\0') ;	// 受信領域。
	// 終端nullを除いてLoadStringWが格納したUTF-16文字数。
	const int	  length =
		LoadStringW( instance_, resourceId, value.data(), MAXIMUM_RESOURCE_CHARACTERS) ;
	// resourceを読み出せなかった場合は無効な文字列領域を参照しない。
	if( length <= 0) {
		return {} ;
	}

	value.resize( static_cast<std::size_t>( length)) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatResource( const UINT resourceId, const std::wstring_view value) const
{
	std::wstring	  format	  = loadString( resourceId) ;	// `%1`を一つ含むresource文字列。
	const std::size_t placeholder = format.find( L"%1") ;		// 置換対象placeholderの開始位置。
	// 定義されたplaceholderがある場合にだけ置換を行う。
	if( placeholder != std::wstring::npos) {
		format.replace( placeholder, 2, value) ;
	}

	return format ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::setStatus( const std::wstring_view text, const bool busy)
{
	// status control作成前は表示更新を行わない。
	if( status_ == nullptr) {
		return ;
	}

	statusBusy_		  = busy ;
	statusPercentage_ = 0 ;
	SetWindowTextW( status_, std::wstring( text).c_str()) ;
	InvalidateRect( status_, nullptr, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::setOperationProgress( const ProviderProgress &progress)
{
	// 進捗表示先が存在しない間はcontrolを操作しない。
	if( status_ == nullptr) {
		return ;
	}

	UINT resourceId{} ;	// 現在段階を示すstatus文字列resource ID。
	// 実際のProvider段階に対応する進捗説明をresourceから選ぶ。
	switch( progress.stage) {
		// 通常検索の先行Windows再検出を独立した段階で表示します。
		case ProviderStage::REFRESHING_HARDWARE:
			resourceId = IDS_STATUS_REFRESHING_HARDWARE ;
			break ;

		// 現在 device を列挙する段階の名称を表示する。
		case ProviderStage::SCANNING_DEVICES:
			resourceId = IDS_STATUS_SCANNING_DEVICES ;
			break ;

		// WUA を検索する段階の名称を表示する。
		case ProviderStage::SEARCHING_WINDOWS_UPDATE:
			resourceId = IDS_STATUS_SEARCHING_WINDOWS_UPDATE ;
			break ;

		// 公式 catalog を検索する段階の名称を表示する。
		case ProviderStage::SEARCHING_OFFICIAL_CATALOGS:
			resourceId = IDS_STATUS_SEARCHING_OFFICIAL_CATALOGS ;
			break ;

		// Provider 候補を統合する段階の名称を表示する。
		case ProviderStage::MERGING_CANDIDATES:
			resourceId = IDS_STATUS_MERGING_CANDIDATES ;
			break ;

		// 復元ポイントを開始する保護段階の名称を表示する。
		case ProviderStage::CREATING_RESTORE_POINT:
			resourceId = IDS_STATUS_CREATING_RESTORE_POINT ;
			break ;

		// Payload の取得段階を導入と区別して表示する。
		case ProviderStage::DOWNLOADING:
			resourceId = IDS_STATUS_DOWNLOADING ;
			break ;

		// 選択 driver の導入段階を表示する。
		case ProviderStage::INSTALLING:
			resourceId = IDS_STATUS_INSTALLING ;
			break ;

		// 復元ポイント終了通知の段階を表示する。
		case ProviderStage::FINALIZING_RESTORE_POINT:
			resourceId = IDS_STATUS_FINALIZING_RESTORE_POINT ;
			break ;

		// 未知の段階では status 帯を推測更新しない。
		default:
			return ;
	}

	const std::uint32_t percentage =	// 下部status帯へ描画する検証済み全体完了率。
		std::min<std::uint32_t>( progress.percentComplete, 100) ;
	std::wstring text = loadString( resourceId) ;	// 段階と進捗を結合するstatus文字列。
	// 総数が確定している進捗にだけ処理済み件数と総数を表示する。
	if( progress.totalItems != 0) {
		const std::uint64_t completed =	// 総数を超えない表示用完了件数。
			std::min( progress.completedItems, progress.totalItems) ;
		text += L" " + std::to_wstring( completed) + L" / " + std::to_wstring( progress.totalItems) +
				L" 件" ;
	}

	text += L"（全体 " + std::to_wstring( percentage) + L"%）" ;
	// 取消し待ちを後着の確定進捗で隠さず、率は実測値のまま保持する。
	if( controller_.state() == ApplicationState::CANCELLING_METADATA_SEARCH) {
		text = loadString( IDS_METADATA_CANCEL_WAIT_BUTTON) + L" — " + text ;
	}
	// 通常scanの取消し待ちも後着進捗で通常処理中の表示へ戻さない。
	else if( controller_.state() == ApplicationState::CANCELLING_SCAN) {
		text = loadString( IDS_SCAN_CANCEL_WAIT_BUTTON) + L" — " + text ;
	}

	statusBusy_		  = true ;
	statusPercentage_ = percentage ;
	SetWindowTextW( status_, text.c_str()) ;
	InvalidateRect( status_, nullptr, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::requestClose()
{
	// 終了処理の重複と準備確認dialog中のwindow破棄を防ぐ。
	if( closing_ || preparationReviewOpen_ || metadataReviewOpen_) {
		return ;
	}

	const ApplicationState state = controller_.state() ;	// 終了可否を判断する現在state。
	// 通常scanはworker完了eventまでmessage pumpを維持して協調取消しする。
	if( controller_.scanPurpose() == ScanPurpose::STANDARD &&
	   (state == ApplicationState::SCANNING || state == ApplicationState::CANCELLING_SCAN)) {
		// 終了待ちを重ねず、確認拒否では検索とWindowを維持する。
		if( closeAfterScan_ || MessageBoxW( window_, loadString( IDS_SCAN_CLOSE).c_str(),
										  loadString( IDS_CLOSE_TITLE).c_str(),
										  MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
			return ;
		}

		closeAfterScan_ = true ;
		cancelScan() ;
		return ;
	}

	// 情報検索は取消し後の完了eventまでmessage pumpを維持し、ここではjoinしない。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY &&
	   (state == ApplicationState::SCANNING ||
		state == ApplicationState::CANCELLING_METADATA_SEARCH)) {
		// 重複要求または確認取消しで進行中Windowを破棄しない。
		if( closeAfterMetadataSearch_ ||
		   MessageBoxW( window_, loadString( IDS_METADATA_CLOSE).c_str(),
					   loadString( IDS_CLOSE_TITLE).c_str(),
					   MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
			return ;
		}

		closeAfterMetadataSearch_ = true ;
		cancelMetadataSearch() ;
		return ;
	}

	// 準備取得中は即時破棄せず、協調取消と完了待ちへ切り替える。
	if( state == ApplicationState::PREPARING || state == ApplicationState::CANCELLING_PREPARATION) {
		// 終了待ちを重ねず、利用者が取消を承認しなかった場合は処理を継続する。
		if( closeAfterPreparation_ ||
		   MessageBoxW( window_, loadString( IDS_PREPARATION_CLOSE).c_str(),
					   loadString( IDS_CLOSE_TITLE).c_str(),
					   MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
			return ;
		}

		closeAfterPreparation_			 = true ;
		continueInstallAfterPreparation_ = false ;
		// workerが存在する場合にだけ準備処理の協調取消を要求する。
		if( worker_ != nullptr) {
			static_cast<void>( worker_->requestPreparationCancel( controller_.activeOperationId())) ;
		}

		static_cast<void>( controller_.markPreparationCancelling( controller_.activeOperationId())) ;
		SetWindowTextW( status_, loadString( IDS_PREPARATION_CANCELLING).c_str()) ;
		updateCommandState() ;
		// 完了eventまでUIを動かし、ここでworkerのblocking joinを行わない。
		return ;
	}

	// trueの場合はProvider operationの安全な完了を待つ必要がある。
	const bool busy =
		state == ApplicationState::SCANNING || state == ApplicationState::CANCELLING_SCAN ||
		state == ApplicationState::CREATING_RESTORE_POINT ||
		state == ApplicationState::DOWNLOADING || state == ApplicationState::INSTALLING ;
	// 実行中operationの終了待ちに同意がなければwindowを閉じない。
	if( busy &&
	   MessageBoxW( window_, loadString( IDS_CLOSE_BUSY).c_str(), loadString( IDS_CLOSE_TITLE).c_str(),
				   MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
		return ;
	}

	closing_						 = true ;
	continueInstallAfterPreparation_ = false ;
	controller_.stop() ;
	setStatus( loadString( IDS_STATUS_STOPPING), busy) ;
	updateCommandState() ;
	UpdateWindow( window_) ;

	// window破棄前にworkerを安全に停止し、遅延通知元の所有権を解放する。
	if( worker_ != nullptr) {
		worker_->stop() ;
		worker_.reset() ;
	}

	DestroyWindow( window_) ;
}

} // namespace drivercrate
