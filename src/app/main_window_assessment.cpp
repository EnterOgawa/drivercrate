//------------------------------------------------------------------------------
/**
 * @file main_window_assessment.cpp
 * @brief Device観測と全候補の詳細表示・一候補の明示選択。
 * @version 01.11.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  登録状態・検証理由・方式の詳細表示を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  構成役割とpackage内検査範囲を表示。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/27  同deviceの候補比較と明示的な一件選択を詳細へ集約。
 * Ver.01.04.01 Shunji Ogawa  2026/10/27  検証拒否と所有する失効候補の実行履歴表示を分離。
 * Ver.01.05.00 Shunji Ogawa  2026/10/28  一覧の状態と全体取得検査結果をデバイス詳細へ保持。
 * Ver.01.06.00 Shunji Ogawa  2026/10/28  元選択に結合した取得・検査と導入の二段階操作へ接続。
 * Ver.01.07.00 Shunji Ogawa  2026/11/07  詳細を単一選択tableへ変更し推奨filterと可否を整合。
 * Ver.01.08.00 Shunji Ogawa  2026/11/08  詳細を表とbuttonへ簡素化し実セル文字の状態tooltipを追加。
 * Ver.01.09.00 Shunji Ogawa  2026/11/08  同内容候補の表示集約と元一件選択を保持。
 * Ver.01.10.00 Shunji Ogawa  2026/11/08  明示指定を保持して比較可能な最新候補を初期表示。
 * Ver.01.11.00 Shunji Ogawa  2026/11/08  準備不成立後の元表示保持と段階別匿名診断を追加。
 * Ver.01.11.01 Shunji Ogawa  2026/11/09  所有型と初期値を保って詳細dialog四memberを個別に文書化。
 * Ver.01.11.02 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note UI thread限定。固定理由と診断だけを表示し、取得・導入・同意を実行しない。
 * @see docs/adr/0150-device-observation-and-candidate-assessment-contract.md
 */
//------------------------------------------------------------------------------

#include "app/main_window.h"
#include "app/resource.h"
#include "core/candidate_audit.h"
#include "core/device_observation.h"
#include "core/pending_reference_version.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <commctrl.h>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include <windowsx.h>

namespace drivercrate {
namespace {

// 読取り状態とresourceの有限対応。Enum順はここだけで対応させる。
constexpr std::array<UINT, 7> READ_RESOURCES{IDS_DEVICE_READ_NOT_READ, IDS_DEVICE_READ_VALUE,
											 IDS_DEVICE_READ_EMPTY,	   IDS_DEVICE_READ_MISSING,
											 IDS_DEVICE_READ_FAILED,   IDS_DEVICE_READ_INVALID,
											 IDS_DEVICE_READ_LIMIT} ;
// 詳細の成否を過大評価しない固定表示。
constexpr std::array<UINT, 7> STATE_RESOURCES{
	IDS_ASSESSMENT_STATE_NOT_CHECKED, IDS_ASSESSMENT_STATE_PASSED,
	IDS_ASSESSMENT_STATE_REJECTED,	  IDS_ASSESSMENT_STATE_FAILED,
	IDS_ASSESSMENT_STATE_UNSUPPORTED, IDS_ASSESSMENT_STATE_NOT_APPLICABLE,
	IDS_ASSESSMENT_STATE_WINDOWS} ;
// 未実装を含む方式名。名称だけではexecutorを許可しない。
constexpr std::array<UINT, 5> METHOD_RESOURCES{
	IDS_ASSESSMENT_METHOD_UNKNOWN, IDS_ASSESSMENT_METHOD_WINDOWS, IDS_ASSESSMENT_METHOD_INF,
	IDS_ASSESSMENT_METHOD_INSTALLER, IDS_ASSESSMENT_METHOD_MANUAL} ;
// Enumの各主理由に対する固定文。Page本文・URLを合成しない。
constexpr std::array<UINT, 30> REASON_RESOURCES{IDS_ASSESSMENT_REASON_NOT_EXAMINED,
												IDS_ASSESSMENT_REASON_VALIDATED,
												IDS_ASSESSMENT_REASON_WINDOWS,
												IDS_ASSESSMENT_REASON_API_FAILURE,
												IDS_ASSESSMENT_REASON_FORMAT,
												IDS_ASSESSMENT_REASON_ORIGIN_UNKNOWN,
												IDS_ASSESSMENT_REASON_USER,
												IDS_ASSESSMENT_REASON_ORIGIN_REJECTED,
												IDS_ASSESSMENT_REASON_DELEGATION,
												IDS_ASSESSMENT_REASON_NOT_ACQUIRED,
												IDS_ASSESSMENT_REASON_MISSING_FILE,
												IDS_ASSESSMENT_REASON_HASH,
												IDS_ASSESSMENT_REASON_SIGNATURE,
												IDS_ASSESSMENT_REASON_PUBLISHER,
												IDS_ASSESSMENT_REASON_PNP,
												IDS_ASSESSMENT_REASON_OS,
												IDS_ASSESSMENT_REASON_ARCH,
												IDS_ASSESSMENT_REASON_RANK,
												IDS_ASSESSMENT_REASON_LEGACY,
												IDS_ASSESSMENT_REASON_SAME,
												IDS_ASSESSMENT_REASON_NOT_RECOMMENDED,
												IDS_ASSESSMENT_REASON_FIRMWARE,
												IDS_ASSESSMENT_REASON_MIXED,
												IDS_ASSESSMENT_REASON_NO_REQUIREMENT,
												IDS_ASSESSMENT_REASON_REQUIREMENT_MISSING,
												IDS_ASSESSMENT_REASON_REQUIREMENT_UNKNOWN,
												IDS_ASSESSMENT_REASON_EXECUTOR,
												IDS_ASSESSMENT_REASON_SCOPE,
												IDS_INDEX_INSTALLER_SELECTION,
												IDS_INDEX_INSTALLER_SCOPE} ;
// 必須性と独立した役割の名称。
constexpr std::array<UINT, 5>  ROLE_RESOURCES{
	 IDS_ASSESSMENT_ROLE_BASE, IDS_ASSESSMENT_ROLE_EXTENSION, IDS_ASSESSMENT_ROLE_COMPONENT,
	 IDS_ASSESSMENT_ROLE_UTILITY, IDS_ASSESSMENT_ROLE_FIRMWARE} ;
static_assert( REASON_RESOURCES.size() ==
			  static_cast<std::size_t>( CandidateAssessmentReason::INSTALLER_SCOPE_ATTESTED) + 1U) ;

//------------------------------------------------------------------------------
/**
 * @brief 不正enumでも範囲外参照せず固定resourceへ変換する。
 * @tparam Enum 表示対象の有限enum。
 * @tparam Size 固定対応表の要素数。
 * @param[in] value 表示対象。
 * @param[in] resources 対応表。
 * @return 定義済みresource、または矛盾説明のresource。
 */
//------------------------------------------------------------------------------
template <typename Enum, std::size_t Size>
UINT resourceFor( const Enum value, const std::array<UINT, Size> &resources) noexcept
{
	const auto index = static_cast<std::size_t>( value) ;	// 未知値は上限で拒否する。
	return index < resources.size() ? resources[index] : IDS_ASSESSMENT_INCONSISTENT ;
}

/** @brief 同deviceの一候補または現在構成を所有する詳細entry。 */
struct DeviceDetailEntry {
	/// 候補・版・日付・取得元・区分の表示値。文字列をidentityに使用しない。
	std::array<std::wstring, 5> columns ;
	/// 表示済みの値と状態だけから作った短いセル説明。
	std::array<std::wstring, 5> tips ;
	/// 次の明示button操作が選ぶ元scan候補のindex。
	std::size_t					candidateIndex{} ;
	/// 現在scanでinstall可能な候補だけに明示選択buttonを許す。
	bool						selectable{} ;
} ;

/** @brief 同期dialogだけが借用する所有値と明示選択の結果。 */
struct DeviceDetailDialog {
	/// Device名を含む同期dialogの見出し。
	std::wstring				   title ;
	/// 同deviceの現在観測と全候補。Modal中に元vectorを参照し続けない。
	std::vector<DeviceDetailEntry> entries ;
	/// 五列の有限resource見出し。同期dialogが表示文字列をcopyする。
	std::array<std::wstring, 5>	   columnLabels ;
	/// 初期表示するentryの0始まりindex。最大値は初期highlightなしです。
	std::size_t					   initialEntry{std::numeric_limits<std::size_t>::max()} ;
	/// 明示buttonで指定した元候補index。choiceRequestedがfalseなら使用しない。
	std::size_t					   chosenCandidateIndex{} ;
	/// 閲覧や閉じるだけではfalseを維持する。
	bool						   choiceRequested{} ;
	/// 同期dialogが所有し、閉じる前に破棄する標準tooltip。
	HWND						   tooltip{} ;
	/// 同一threadの借用table。所有snapshotより長生きしません。
	HWND						   table{} ;
	/// 同一threadの借用dialog。所有snapshotより長生きしません。
	HWND						   dialog{} ;
	/// Tooltipが借用中は再割当しない短い表示文字列。
	std::wstring				   activeTip ;
	/// Hover対象の元順ordinal。選択中の行とは独立します。
	int							   hoverRow{-1} ;
	/// Hover対象の列。選択中の行とは独立します。
	int							   hoverColumn{-1} ;
	/// 現在の可視文字runだけのtable client座標。
	RECT						   hoverText{} ;
} ;

// 候補IDとは独立した、dialog内のtooltip/subclass/timer識別子。
constexpr UINT_PTR		 DETAIL_TIP_ID = 0x7790U ;

//------------------------------------------------------------------------------
/**
 * @brief 元順の実row/paramを照合し、所有snapshotだけを返す。
 * @param[in] table 当該dialogの実table。
 * @param[in] state 同期dialogの所有値。
 * @param[in] row 実controlから得た0始まり行。
 * @return 元順ordinalも一致したentry、またはnullptr。
 */
//------------------------------------------------------------------------------
const DeviceDetailEntry *deviceDetailEntryAtRow( const HWND table, const DeviceDetailDialog &state,
												const int row) noexcept
{
	LVITEMW item{} ;	// 生pointerを保存しない実ordinalです。
	item.mask  = LVIF_PARAM ;
	item.iItem = row ;
	// 項目追加、負値、別行のordinalを採用しません。
	if( table == nullptr || row < 0 || static_cast<std::size_t>( row) >= state.entries.size() ||
	   ListView_GetItemCount( table) != static_cast<int>( state.entries.size()) ||
	   !ListView_GetItem( table, &item) || item.lParam != static_cast<LPARAM>( row) + 1) {
		return nullptr ;
	}

	return &state.entries[static_cast<std::size_t>( row)] ;
}

//------------------------------------------------------------------------------
/**
 * @brief 古いpopupとhover期限だけを解除し、選択は変更しない。
 * @param[in,out] state 同期dialogの所有値。
 */
//------------------------------------------------------------------------------
void hideDeviceDetailTip( DeviceDetailDialog &state) noexcept
{
	// 借用文字列はcontrolの破棄/更新まで保持します。
	if( state.tooltip != nullptr) {
		TTTOOLINFOW tool{sizeof( tool)} ;	// 同dialogの唯一toolです。
		tool.hwnd = state.dialog ;
		tool.uId  = DETAIL_TIP_ID ;
		SendMessageW( state.tooltip, TTM_TRACKACTIVATE, FALSE, reinterpret_cast<LPARAM>( &tool)) ;
	}

	KillTimer( state.dialog, DETAIL_TIP_ID) ;
	TRACKMOUSEEVENT tracking{sizeof( tracking), TME_CANCEL | TME_HOVER | TME_LEAVE, state.table,
							 0} ;	// 局所hoverだけです。
	TrackMouseEvent( &tracking) ;
	state.hoverRow = state.hoverColumn = -1 ;
	state.hoverText					   = {} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Hover先の実cellと可視文字runを測り、余白/header/破損を拒否する。
 * @param[in] state 同期dialogの所有値。
 * @param[in] point Table client座標。
 * @param[out] row 照合済みの実row。
 * @param[out] column 照合済みの実column。
 * @param[out] textRect 可視文字runの矩形。
 * @return 文字上で短い説明を持つ場合true。
 */
//------------------------------------------------------------------------------
bool hitDeviceDetailText( const DeviceDetailDialog &state, const POINT point, int &row, int &column,
						 RECT &textRect)
{
	LVHITTESTINFO hit{} ;	// 通知や現在選択から行を推測しません。
	hit.pt			  = point ;
	row				  = ListView_SubItemHitTest( state.table, &hit) ;
	column			  = hit.iSubItem ;
	const auto *entry = deviceDetailEntryAtRow( state.table, state, row) ;	// 元ordinalを再読します。
	// 未知列や説明を持たない空欄を対象にしません。
	if( entry == nullptr || column < 0 || column >= 5 ||
	   entry->columns[static_cast<std::size_t>( column)].empty() ||
	   entry->tips[static_cast<std::size_t>( column)].empty()) {
		return false ;
	}

	const auto &value =
		entry->columns[static_cast<std::size_t>( column)] ;	// 表に表示した値だけです。
	// 異常なUI文字列の測定を有限にし、内容/identity gateは変更しません。
	if( value.size() > 16384U) {
		return false ;
	}

	std::wstring actual( value.size() + 1U, L'\0') ;	// 実cell copy用の終端込み容量です。
	LVITEMW		 cellText{} ;							// SDK macroの一時scopeへ依存しない同期copyです。
	cellText.iSubItem	= column ;
	cellText.pszText	= actual.data() ;
	cellText.cchTextMax = static_cast<int>( actual.size()) ;
	const int copied =
		static_cast<int>( SendMessageW( state.table, LVM_GETITEMTEXTW, static_cast<WPARAM>( row),
									  reinterpret_cast<LPARAM>( &cellText))) ;	// 実表示値です。
	actual.resize( static_cast<std::size_t>( std::max( 0, copied))) ;
	RECT	   cell{}, header{}, client{} ;					// Column/row/clientの可視交差です。
	const HWND heading = ListView_GetHeader( state.table) ;	// 標準headerの実column位置です。
	// LVIR_LABELもsubitem全体なので、別途実fontで文字幅を測定します。
	if( actual != value || !ListView_GetSubItemRect( state.table, row, column, LVIR_BOUNDS, &cell) ||
	   !Header_GetItemRect( heading, column, &header) || !GetClientRect( state.table, &client)) {
		return false ;
	}

	MapWindowPoints( heading, state.table, reinterpret_cast<POINT *>( &header), 2U) ;
	cell.left	 = header.left ;
	cell.right	 = header.right ;
	cell.top	 = std::max( cell.top, header.bottom) ;
	const HDC dc = GetDC( state.table) ;	// このcontrolだけの一時測定DCです。
	// 測定不能ならcell全体のhoverへ拡大しません。
	if( dc == nullptr) {
		return false ;
	}

	const auto font =
		reinterpret_cast<HFONT>( SendMessageW( state.table, WM_GETFONT, 0, 0)) ;	// 実fontです。
	const auto previous = SelectObject( dc, font) ;									// 測定後に必ず戻します。
	SIZE	   extent{} ;															// 終端を含まない実文字runの寸法です。
	const bool measured = GetTextExtentPoint32W( dc, value.data(), static_cast<int>( value.size()),
												&extent) != FALSE ;	// Clip前です。
	SelectObject( dc, previous) ;
	ReleaseDC( state.table, dc) ;
	const int inset =
		// 標準reportの文字余白です。
		MulDiv( 6, static_cast<int>( GetDpiForWindow( state.table)), 96) ;
	const LONG top =
		cell.top + std::max( 0L, (cell.bottom - cell.top - extent.cy) / 2L) ;	// 垂直余白を除きます。
	RECT run{cell.left + inset, top, cell.left + inset + extent.cx,
			 top + extent.cy} ;	// 省略時も可視部分だけです。
	RECT clipped{} ;			// Columnの外へ出た文字幅を採用しません。
	return measured && extent.cx > 0 && extent.cy > 0 && IntersectRect( &clipped, &run, &cell) &&
		   IntersectRect( &textRect, &clipped, &client) && PtInRect( &textRect, point) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 標準table入力を保持し、実hover文字だけにtracking balloonを表示する。
 * @param[in] table 同dialogの実table。
 * @param[in] message 標準window message。
 * @param[in] wordParameter 元messageの値。
 * @param[in] longParameter 元messageの座標等。
 * @param[in] subclassId 当該subclass識別子。
 * @param[in] reference 同期dialog所有stateの借用pointer。
 * @return 標準controlの処理結果。
 */
//------------------------------------------------------------------------------
LRESULT CALLBACK deviceDetailTableProc( HWND table, UINT message, WPARAM wordParameter,
									   LPARAM longParameter, UINT_PTR subclassId,
									   DWORD_PTR reference) noexcept
{
	auto &state =
		*reinterpret_cast<DeviceDetailDialog *>( reference) ;	// 同UI thread内の同期寿命です。
	try {
		// Hover期限と表示直前の両方で実row/param/文字を再照合します。
		if( message == WM_MOUSEMOVE || message == WM_MOUSEHOVER) {
			const POINT point{GET_X_LPARAM( longParameter),
							  // table座標です。
							  GET_Y_LPARAM( longParameter)} ;
			int			row{-1}, column{-1} ;	// 未判定を先頭へ補完しません。
			RECT		text{} ;				// 実文字の可視部分です。
			const bool	hit =
				// 選択行と独立です。
				hitDeviceDetailText( state, point, row, column, text) ;
			const bool same = hit && state.hoverRow == row && state.hoverColumn == column &&
							  // 座標移動も区別します。
							  EqualRect( &state.hoverText, &text) ;
			// 別cell/余白へ移った時は以前の吹き出しを先に消します。
			if( !same) {
				hideDeviceDetailTip( state) ;
				// 新しい文字上だけで通常hover待ちを開始します。
				if( hit && message == WM_MOUSEMOVE) {
					state.hoverRow	  = row ;
					state.hoverColumn = column ;
					state.hoverText	  = text ;
					TRACKMOUSEEVENT tracking{sizeof( tracking), TME_HOVER | TME_LEAVE, table,
											 HOVER_DEFAULT} ;	// 標準hover時間です。
					TrackMouseEvent( &tracking) ;
				}
			}
			// 同じ文字runの通常hover期限でだけ表示します。
			else if( message == WM_MOUSEHOVER && state.tooltip != nullptr) {
				TTTOOLINFOW tool{sizeof( tool)} ;	// 以前の借用文字列を非表示にしてから差し替えます。
				tool.hwnd = state.dialog ;
				tool.uId  = DETAIL_TIP_ID ;
				SendMessageW( state.tooltip, TTM_TRACKACTIVATE, FALSE,
							 reinterpret_cast<LPARAM>( &tool)) ;
				state.activeTip = state.entries[static_cast<std::size_t>( row)]
									  .tips[static_cast<std::size_t>( column)] ;
				tool.lpszText = state.activeTip.data() ;
				SendMessageW( state.tooltip, TTM_UPDATETIPTEXTW, 0, reinterpret_cast<LPARAM>( &tool)) ;
				POINT position{text.left, text.bottom + 4} ;	// Hoverした文字の直下です。
				ClientToScreen( table, &position) ;
				SendMessageW( state.tooltip, TTM_TRACKPOSITION, 0,
							 MAKELPARAM( position.x, position.y)) ;
				SendMessageW( state.tooltip, TTM_TRACKACTIVATE, TRUE,
							 reinterpret_cast<LPARAM>( &tool)) ;
				// Trackingだけの有限表示期限であり、state/sessionの監視はしません。
				if( SetTimer( state.dialog, DETAIL_TIP_ID, 5000U, nullptr) == 0U) {
					hideDeviceDetailTip( state) ;
				}
			}
		}
		// 入力/viewport変化では古い座標の説明を解除します。
		else if( message == WM_MOUSELEAVE || message == WM_MOUSEWHEEL || message == WM_MOUSEHWHEEL ||
				message == WM_VSCROLL || message == WM_HSCROLL || message == WM_KEYDOWN ||
				message == WM_SYSKEYDOWN || message == WM_LBUTTONDOWN ||
				message == WM_RBUTTONDOWN || message == WM_MBUTTONDOWN || message == WM_SIZE) {
			hideDeviceDetailTip( state) ;
		}

		// Dialogより先にtableが破棄されても借用callbackを残しません。
		if( message == WM_NCDESTROY) {
			hideDeviceDetailTip( state) ;
			RemoveWindowSubclass( table, deviceDetailTableProc, subclassId) ;
		}
	} catch( ...) {
		hideDeviceDetailTip( state) ;
	}

	return DefSubclassProc( table, message, wordParameter, longParameter) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元の匿名化済み結果を短くし、原診断の数値を優先保持する。
 * @param[in] text 既存UIが生成した成否/数値だけの文字列。
 * @return 有限の要約。元本文・ID・pathを渡さない。
 */
//------------------------------------------------------------------------------
std::wstring deviceResultCodes( const std::wstring_view text)
{
	std::wstring result ;		// 検証した原数値だけです。
	std::size_t	 position{} ;	// 元診断のhex数値だけを走査します。
	// 表示済み原数値を最大四つ保持し、Windows文言や秘密値を追加しません。
	for( unsigned count{};
		count < 4U && (position = text.find( L"0x", position)) != std::wstring_view::npos;
		++position) {
		const auto code = text.substr( position, 10U) ;	// 固定8桁の原数値です。
		// 不正な文字列を診断値として表示しません。
		if( code.size() == 10U &&
		   std::ranges::all_of( code.substr( 2U),
							   []( const wchar_t ch) {
								   return (ch >= L'0' && ch <= L'9') ||
										  (ch >= L'A' && ch <= L'F') || (ch >= L'a' && ch <= L'f') ;
							   }) &&
		   result.find( code) == std::wstring::npos) {
			result += L" " + std::wstring( code) ;
			++count ;
		}
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存UIが生成した一候補の成否と原数値だけを短く保持する。
 * @param[in] text 匿名化済みの元候補の結果。元本文/ID/pathを渡さない。
 * @return 有限の成否要約と原数値。
 */
//------------------------------------------------------------------------------
std::wstring shortDeviceResult( const std::wstring_view text)
{
	return std::wstring( text.substr( 0U, 160U)) + (text.size() > 160U ? L"…" : L"") +
		   deviceResultCodes( text) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実controlの唯一選択と所有entryのordinalを再照合する。
 * @param[in] dialog 同期dialogの借用handle。
 * @param[in] state Dialog中に固定した元順の所有snapshot。
 * @return 全照合を満たす借用entry。不正または未選択ならnullptr。
 */
//------------------------------------------------------------------------------
const DeviceDetailEntry *selectedDeviceDetailEntry( const HWND				 dialog,
												   const DeviceDetailDialog &state) noexcept
{
	const HWND table = GetDlgItem( dialog, IDC_DEVICE_DETAIL_CANDIDATES) ;	// 当該dialogの実table。
	// 未選択・複数選択・項目追加を別entryへ補完しない。
	if( table == nullptr || ListView_GetSelectedCount( table) != 1U ||
	   ListView_GetItemCount( table) < 0 ||
	   static_cast<std::size_t>( ListView_GetItemCount( table)) != state.entries.size()) {
		return nullptr ;
	}

	const int row = ListView_GetNextItem( table, -1, LVNI_SELECTED) ;	// 実controlの唯一選択です。
	return deviceDetailEntryAtRow( table, state, row) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正選択では以前のbutton許可を残さない。
 * @param[in] dialog 同期dialogの借用handle。
 */
//------------------------------------------------------------------------------
void clearDeviceDetailPage( const HWND dialog) noexcept
{
	EnableWindow( GetDlgItem( dialog, IDYES), FALSE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実tableの一entryだけを明示選択buttonへ反映する。
 * @param[in] dialog 同期dialogの借用handle。
 * @param[in] state 同期dialog中の所有snapshot。
 * @return 有効な一entryを照合できた場合true。
 */
//------------------------------------------------------------------------------
bool updateDeviceDetailPage( const HWND dialog, const DeviceDetailDialog &state) noexcept
{
	const auto *entry = selectedDeviceDetailEntry( dialog, state) ;	// 元順とparamを照合済みです。
	EnableWindow( GetDlgItem( dialog, IDYES), entry != nullptr && entry->selectable ? TRUE : FALSE) ;
	return entry != nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既dialog単位を使い、tableと明示buttonを非重複で並べる。
 * @param[in] dialog 当該dialogの借用handle。
 * @note Columnは利用者の幅変更を保持し、狭幅では標準水平scrollを使用する。
 */
//------------------------------------------------------------------------------
void layoutDeviceDetails( const HWND dialog) noexcept
{
	RECT client{} ;					// 当該dialogだけのclient寸法。
	RECT units{10, 8, 130, 18} ;	// Margin/隙間/選択buttonを元fontのDLUから変換する。
	// 初期化中や最小化中に負のcontrol寸法を渡さない。
	if( !GetClientRect( dialog, &client) || !MapDialogRect( dialog, &units) || client.right <= 0 ||
	   client.bottom <= 0) {
		return ;
	}

	const int width		 = std::max( 1L, client.right - 2L * units.left) ;	// 横幅。
	const int closeWidth = MulDiv( units.right, 80, 130) ;					// 元close buttonのDLU比。
	const int buttonsY	 = client.bottom - units.top - units.bottom ;		// 最下段。
	MoveWindow( GetDlgItem( dialog, IDC_DEVICE_DETAIL_CANDIDATES), units.left, units.top, width,
			   std::max( 1L, buttonsY - units.top * 2), TRUE) ;
	MoveWindow( GetDlgItem( dialog, IDYES),
			   client.right - units.left - closeWidth - units.left - units.right, buttonsY,
			   units.right, units.bottom, TRUE) ;
	MoveWindow( GetDlgItem( dialog, IDOK), client.right - units.left - closeWidth, buttonsY,
			   closeWidth, units.bottom, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 標準controlへ同deviceの候補を表示し、明示buttonだけから一候補を返す。
 * @param[in] dialog 同期dialogの借用handle。
 * @param[in] message Windows通知。
 * @param[in] wordParameter Button IDまたはcontrol ID。
 * @param[in] longParameter 初期化snapshot/同期通知/最小寸法を借用するWin32境界。
 * @return 処理済みの場合TRUE。
 * @note Callbackから例外を漏らさず、失敗時は選択しない。
 */
//------------------------------------------------------------------------------
INT_PTR CALLBACK detailDialogProc( const HWND dialog, const UINT message, const WPARAM wordParameter,
								  const LPARAM longParameter) noexcept
{
	try {
		// Pointer-sized保存領域はDialogBoxParamW呼出し元の寿命内だけ借用する。
		auto *state = reinterpret_cast<DeviceDetailDialog *>( GetWindowLongPtrW( dialog, DWLP_USER)) ;
		// 元fontのDLUと同monitorの作業領域だけで、狭幅時の有限最小寸法を定める。
		if( message == WM_GETMINMAXINFO && longParameter != 0) {
			auto	   *limits = reinterpret_cast<MINMAXINFO *>( longParameter) ;	// 同期Win32構造体。
			RECT		minimum{0, 0, 500, 220} ;									// 既fontを維持する最小client DLU。
			RECT		outer{} ;													// 現windowの非client差。
			RECT		client{} ;													// 同じwindowのclient。
			MONITORINFO monitor{sizeof( MONITORINFO)} ;								// 当該windowの作業領域。
			// API失敗時はWindows標準寸法へ残し、未知のscreen値を合成しない。
			if( MapDialogRect( dialog, &minimum) && GetWindowRect( dialog, &outer) &&
			   GetClientRect( dialog, &client) &&
			   GetMonitorInfoW( MonitorFromWindow( dialog, MONITOR_DEFAULTTONEAREST), &monitor)) {
				limits->ptMinTrackSize.x =
					std::min( minimum.right + outer.right - outer.left - client.right,
							 monitor.rcWork.right - monitor.rcWork.left) ;
				limits->ptMinTrackSize.y =
					std::min( minimum.bottom + outer.bottom - outer.top - client.bottom,
							 monitor.rcWork.bottom - monitor.rcWork.top) ;
			}

			return TRUE ;
		}

		// Control生成時だけsnapshotを登録し、entry元順とordinalを固定する。
		if( message == WM_INITDIALOG) {
			// 同期所有値の借用。
			state = reinterpret_cast<DeviceDetailDialog *>( longParameter) ;
			// Win32のsigned int indexへ安全に写せないsnapshotを拒否する。
			if( state == nullptr || state->entries.empty() ||
			   state->entries.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
			   (state->initialEntry != std::numeric_limits<std::size_t>::max() &&
				state->initialEntry >= state->entries.size()) ||
			   !SetWindowTextW( dialog, state->title.c_str())) {
				EndDialog( dialog, -1) ;
				return TRUE ;
			}

			SetWindowLongPtrW( dialog, DWLP_USER, reinterpret_cast<LONG_PTR>( state)) ;
			const HWND table = GetDlgItem( dialog, IDC_DEVICE_DETAIL_CANDIDATES) ;	// 実control。
			ListView_SetExtendedListViewStyle( table, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) ;
			state->table  = table ;
			state->dialog = dialog ;
			// 標準の切れたlabel tooltipを切り離し、二重表示を防ぎます。
			const HWND previousTip =
				// このListViewの既定tipだけです。
				ListView_SetToolTips( table, nullptr) ;
			// 切り離した当該ListViewの既定popupだけを破棄します。
			if( previousTip != nullptr) {
				DestroyWindow( previousTip) ;
			}

			state->tooltip = CreateWindowExW(
				WS_EX_TOPMOST | WS_EX_NOACTIVATE, TOOLTIPS_CLASSW, nullptr,
				WS_POPUP | TTS_BALLOON | TTS_NOPREFIX | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT,
				CW_USEDEFAULT, CW_USEDEFAULT, dialog, nullptr, GetModuleHandleW( nullptr), nullptr) ;
			// Tooltip生成失敗は選択の補完や汎用巨大本文へ切り替えません。
			if( state->tooltip != nullptr) {
				TTTOOLINFOW tool{sizeof( tool)} ;	// 文字列は所有stateが保持します。
				tool.uFlags	  = TTF_TRACK ;
				tool.hwnd	  = dialog ;
				tool.uId	  = DETAIL_TIP_ID ;
				tool.lpszText = state->activeTip.data() ;
				SendMessageW( state->tooltip, TTM_SETMAXTIPWIDTH, 0,
							 MulDiv( 360, static_cast<int>( GetDpiForWindow( dialog)), 96)) ;
				// 不完全なtool/subclassを残さず説明だけを無効にします。
				if( !SendMessageW( state->tooltip, TTM_ADDTOOLW, 0,
								 reinterpret_cast<LPARAM>( &tool)) ||
				   !SetWindowSubclass( table, deviceDetailTableProc, DETAIL_TIP_ID,
									  reinterpret_cast<DWORD_PTR>( state))) {
					DestroyWindow( state->tooltip) ;
					state->tooltip = nullptr ;
				}
			}

			layoutDeviceDetails( dialog) ;
			RECT bounds{} ;	// 初期の列幅だけを実table幅から定める。
			GetClientRect( table, &bounds) ;
			constexpr std::array<int, 5> weights{22, 16, 13, 19, 30} ;	// 元順の五列の幅比。
			// 見出しはresource文字列をcontrolへ同期copyし、並べ替えを提供しない。
			for( std::size_t column{}; column < state->columnLabels.size(); ++column) {
				LVCOLUMNW heading{} ;	// Common control APIの非const文字列境界。
				heading.mask	= LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM ;
				heading.pszText = state->columnLabels[column].data() ;
				heading.cx		= MulDiv(
					 bounds.right - GetSystemMetricsForDpi( SM_CXVSCROLL, GetDpiForWindow( dialog)),
					 weights[column], 100) ;
				heading.iSubItem = static_cast<int>( column) ;
				// 欠けた列のまま別契約の選択画面を出さない。
				if( ListView_InsertColumn( table, static_cast<int>( column), &heading) < 0) {
					EndDialog( dialog, -1) ;
					return TRUE ;
				}
			}

			// 元entry順を保ち、文字列や通知indexをidentityへ転用しない。
			for( std::size_t row{}; row < state->entries.size(); ++row) {
				auto   &entry = state->entries[row] ;	// 同期copyする所有文字列。
				LVITEMW item{} ;						// LParamは生pointerではなくordinal+1。
				item.mask	 = LVIF_TEXT | LVIF_PARAM ;
				item.iItem	 = static_cast<int>( row) ;
				item.pszText = entry.columns[0].data() ;
				item.lParam	 = static_cast<LPARAM>( row + 1U) ;
				// 元順と異なる挿入位置を黙って採用しない。
				if( ListView_InsertItem( table, &item) != static_cast<int>( row)) {
					EndDialog( dialog, -1) ;
					return TRUE ;
				}

				// 全subitemを実controlへcopyし、未知欄も明示する。
				for( std::size_t column = 1U; column < entry.columns.size(); ++column) {
					item.iSubItem = static_cast<int>( column) ;
					item.pszText  = entry.columns[column].data() ;
					// 必須値copyに失敗した場合は明示選択も発行しない。
					if( !SendMessageW( table, LVM_SETITEMTEXTW, row,
									 reinterpret_cast<LPARAM>( &item))) {
						EndDialog( dialog, -1) ;
						return TRUE ;
					}
				}
			}

			// 比較可能な初期行がなければ、閲覧可能な未選択表として開きます。
			if( state->initialEntry < state->entries.size()) {
				ListView_SetItemState( table, static_cast<int>( state->initialEntry),
									  LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED) ;
				ListView_EnsureVisible( table, static_cast<int>( state->initialEntry), FALSE) ;
				// 指定した元順の一行を照合できない場合は生成失敗です。
				if( !updateDeviceDetailPage( dialog, *state)) {
					EndDialog( dialog, -1) ;
				}
			} else {
				clearDeviceDetailPage( dialog) ;
			}

			return TRUE ;
		}

		// 標準dialogのDPI変更に伴うclient変化も同じ局所layoutへ通す。
		if( message == WM_SIZE && state != nullptr) {
			hideDeviceDetailTip( *state) ;
			layoutDeviceDetails( dialog) ;
			return TRUE ;
		}

		// DPI変更は標準dialogへ残し、元の自動font/rect更新を妨げません。
		if( message == WM_DPICHANGED && state != nullptr) {
			hideDeviceDetailTip( *state) ;
			return FALSE ;
		}

		// Button/accelerator操作の前に閲覧用popupだけを解除します。
		if( message == WM_COMMAND && state != nullptr) {
			hideDeviceDetailTip( *state) ;
		}

		// 可視中の局所期限だけでpopupを閉じます。定期state監視はしません。
		if( message == WM_TIMER && wordParameter == DETAIL_TIP_ID && state != nullptr) {
			hideDeviceDetailTip( *state) ;
			return TRUE ;
		}

		// 同期snapshotが失われる前に借用control/callbackを解放します。
		if( message == WM_DESTROY && state != nullptr) {
			hideDeviceDetailTip( *state) ;
			RemoveWindowSubclass( state->table, deviceDetailTableProc, DETAIL_TIP_ID) ;
			// 所有popupの借用文字列をstate解放前に破棄します。
			if( state->tooltip != nullptr) {
				DestroyWindow( state->tooltip) ;
				state->tooltip = nullptr ;
			}

			SetWindowLongPtrW( dialog, DWLP_USER, 0) ;
		}

		// Enter・Escape・閉じるは閲覧終了だけであり、候補を適用しない。
		if( message == WM_CLOSE || (message == WM_COMMAND && (LOWORD( wordParameter) == IDOK ||
															 LOWORD( wordParameter) == IDCANCEL))) {
			EndDialog( dialog, IDOK) ;
			return TRUE ;
		}

		// 当該tableの実状態だけを採用し、通知のrow値や本文をidentityにしない。
		if( message == WM_NOTIFY && state != nullptr) {
			const auto *notification = reinterpret_cast<const NMHDR *>( longParameter) ;	// 同期借用。
			// Headerの幅/順序/track通知では以前の文字座標を無効にします。
			if( notification != nullptr &&
			   notification->hwndFrom == ListView_GetHeader( state->table)) {
				hideDeviceDetailTip( *state) ;
				return FALSE ;
			}

			// 標準header等の対象外通知を候補行の変更と誤認しない。
			if( wordParameter != IDC_DEVICE_DETAIL_CANDIDATES &&
			   (notification == nullptr || notification->idFrom != IDC_DEVICE_DETAIL_CANDIDATES)) {
				return FALSE ;
			}

			// Null/foreign通知を以前の許可や別controlの選択へ結び付けない。
			if( notification == nullptr ||
			   notification->hwndFrom != GetDlgItem( dialog, IDC_DEVICE_DETAIL_CANDIDATES) ||
			   notification->idFrom != IDC_DEVICE_DETAIL_CANDIDATES ||
			   wordParameter != IDC_DEVICE_DETAIL_CANDIDATES) {
				hideDeviceDetailTip( *state) ;
				clearDeviceDetailPage( dialog) ;
				return TRUE ;
			}

			// 標準の行移動・click・Enter/doubleclickは閲覧のみでbuttonを押さない。
			if( notification->code == LVN_ITEMCHANGED || notification->code == NM_CLICK ||
			   notification->code == NM_RETURN || notification->code == NM_DBLCLK) {
				static_cast<void>( updateDeviceDetailPage( dialog, *state)) ;
				return TRUE ;
			}
		}

		// 明示buttonでも実controlの一選択と所有ordinalを最後に再読する。
		if( message == WM_COMMAND && LOWORD( wordParameter) == IDYES && state != nullptr) {
			const auto *entry = selectedDeviceDetailEntry( dialog, *state) ;	// 通知状態を使わない。
			// Readonly/失効/不正param/無効buttonをcommand偽装でも許可しない。
			if( entry != nullptr && entry->selectable &&
			   IsWindowEnabled( GetDlgItem( dialog, IDYES))) {
				state->chosenCandidateIndex = entry->candidateIndex ;
				state->choiceRequested		= true ;
				EndDialog( dialog, IDYES) ;
			} else {
				clearDeviceDetailPage( dialog) ;
			}

			return TRUE ;
		}

		return FALSE ;
	} catch( ...) {
		EndDialog( dialog, -1) ;
		return TRUE ;
	}
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 検索時点のdriver登録・問題・読取り失敗を短く表示する。
 * @param[in] candidate 現在構成行。観測未収集を許す。
 * @return 状態を過大評価しないresource文字列。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatDeviceObservation( const UpdateCandidate &candidate) const
{
	// 観測未収集をdriver導入済みへ補完しない。
	if( !candidate.deviceObservation) {
		return loadString( IDS_DEVICE_OBSERVATION_MISSING) ;
	}

	// 古い型や異なるdeviceからの矛盾した観測を正常表示しない。
	if( !isCandidateDetailsValid( candidate)) {
		return loadString( IDS_ASSESSMENT_INCONSISTENT) ;
	}

	const auto	&observed = *candidate.deviceObservation ;	// 同じ現在構成の観測。
	std::wstring text = loadString( observed.driverPresence == DeviceDriverPresence::NOT_INSTALLED
									   ? IDS_DEVICE_PRESENCE_NOT_INSTALLED
								   : observed.driverPresence == DeviceDriverPresence::REGISTERED
									   ? IDS_DEVICE_PRESENCE_REGISTERED
									   : IDS_DEVICE_PRESENCE_UNKNOWN) ;	// 存在と動作成否を分離する。
	// 有効な問題codeがある場合だけWindowsの観測を付記する。
	if( observed.node.problemCode) {
		text += L" / " +
				formatResource( IDS_DEVICE_PROBLEM, std::to_wstring( *observed.node.problemCode)) ;
	}

	// Status API失敗を問題なしと表示しない。
	if( observed.node.read.state != DevicePropertyReadState::VALUE) {
		text += L" / " + loadString( IDS_DEVICE_STATUS_UNVERIFIED) ;
	}

	const std::array<const DevicePropertyReadStatus *, 10> reads{
		&observed.friendlyName,	   &observed.deviceDescription, &observed.manufacturer,
		&observed.deviceClass,	   &observed.driverKey,			&observed.infName,
		&observed.provider,		   &observed.version,			&observed.date,
		&observed.instanceIdentity} ;	// 固定属性。
	// 任意属性の不存在と実読取り失敗を区別し、失敗の要約を一回だけ付記する。
	for( const auto *read : reads) {
		// 失敗・不正・上限は詳細で元診断を示す。
		if( read->state == DevicePropertyReadState::FAILED ||
		   read->state == DevicePropertyReadState::INVALID_DATA ||
		   read->state == DevicePropertyReadState::LIMIT_REACHED) {
			text += L" / " + loadString( IDS_DEVICE_ATTRIBUTE_FAILURE) ;
			break ;
		}
	}

	return text ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有限な観測と候補検証の全詳細をread-only表示用に整形する。
 * @param[in] candidate 同じscanの候補。
 * @return 固定属性・軸・理由と次の操作。生の証拠や識別子を含めない。
 * @note 検証不整合は拒否表示を維持する。所有候補要素の過去実行結果だけは履歴として併記する。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatCandidateDetails( const UpdateCandidate &candidate) const
{
	const auto appendHistory = [this, &candidate]( std::wstring text) {
		const auto retained =
			std::find_if( candidates_.begin(), candidates_.end(), [&candidate]( const auto &item) {
				return &item == &candidate ;
			}) ; // 所有要素そのものだけです。
		// 同じIDの外部copyや別deviceの候補へ、所有する個別結果を流用しない。
		if( retained != candidates_.end()) {
			const auto index =
				// 元候補順です。
				static_cast<std::size_t>( retained - candidates_.begin()) ;
			// 未実行候補へ同deviceの別候補の結果を補完しない。
			if( index < candidateResultTexts_.size() && !candidateResultTexts_[index].empty()) {
				text += L"\r\n\r\n" + loadString( IDS_CANDIDATE_EXECUTION_HISTORY) + L"\r\n" +
						candidateResultTexts_[index] ;
			}
		}

		// 検証本文が拒否された場合も、失効済みのscanを現在の許可として表示しない。
		if( controller_.scanPurpose() != ScanPurpose::METADATA_ONLY &&
		   controller_.scanSessionId() == 0U) {
			text += L"\r\n" + loadString( IDS_MEASUREMENT_EXPIRED) ;
		}

		return text ;
	} ; // UI所有candidateとthisを同期整形中だけ借用し、結果は値で返す。
	// 表示に必要な結合を失った候補では原因を推測しない。
	if( !isCandidateDetailsValid( candidate)) {
		return appendHistory( loadString( IDS_ASSESSMENT_INCONSISTENT)) ;
	}

	std::wstring text =
		// 本文は全てこの関数が所有する。
		formatCandidateText( candidate) + L"\r\n\r\n" ;
	const auto diagnosticText = [this]( const DeviceDiagnostic &diagnostic) {
		const UINT resource =
			diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR ? IDS_DIAGNOSTIC_WIN32
			: diagnostic.domain == DeviceDiagnosticDomain::CONFIGURATION_MANAGER
				? IDS_DIAGNOSTIC_CONFIGRET
				: IDS_DIAGNOSTIC_HRESULT ;	// Windowsの生messageに含まれるpathを取り込まない。
		std::wstring value = L" [" + loadString( resource) + L": " +
							 // 固定幅codeのみ。
							 std::to_wstring( diagnostic.code) + L"]" ;
		// 権限拒否は安全な再確認が必要な失敗として明示する。
		if( diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR &&
		   diagnostic.code == ERROR_ACCESS_DENIED) {
			value += L" " + loadString( IDS_DEVICE_ACCESS_DENIED) ;
		}

		// Win32のdevice消失を固定の説明へ対応させる。
		if( diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR &&
		   diagnostic.code == ERROR_NO_SUCH_DEVINST) {
			value += L" " + loadString( IDS_DEVICE_DISAPPEARED) ;
		}

		return value ;
	} ; // thisは同期整形中だけ借用し、lambdaを保存しない。
	// 現在構成行は実行候補の検証と分離して属性観測を表示する。
	if( candidate.current) {
		text += formatDeviceObservation( candidate) + L"\r\n" +
				loadString( IDS_DEVICE_OBSERVATION_NOTE) + L"\r\n" ;
		// 未収集の観測を架空の属性成功で補完しない。
		if( candidate.deviceObservation) {
			const auto &observed =
				*candidate.deviceObservation ;	// 同じscanの固定属性だけを借用する。
			const std::array<std::pair<UINT, const DevicePropertyReadStatus *>, 11> reads{
				{{IDS_DEVICE_FIELD_NODE, &observed.node.read},
				 {IDS_DEVICE_FIELD_FRIENDLY, &observed.friendlyName},
				 {IDS_DEVICE_FIELD_DESCRIPTION, &observed.deviceDescription},
				 {IDS_DEVICE_FIELD_MANUFACTURER, &observed.manufacturer},
				 {IDS_DEVICE_FIELD_CLASS, &observed.deviceClass},
				 {IDS_DEVICE_FIELD_KEY, &observed.driverKey},
				 {IDS_DEVICE_FIELD_INF, &observed.infName},
				 {IDS_DEVICE_FIELD_PROVIDER, &observed.provider},
				 {IDS_DEVICE_FIELD_VERSION, &observed.version},
				 {IDS_DEVICE_FIELD_DATE, &observed.date},
				 {IDS_DEVICE_FIELD_IDENTITY,
				  &observed
					   .instanceIdentity}}} ;	// 生のkey・INF path・instance IDを表示せず成否だけにする。
			// 固定属性を一回ずつ整形し、欠損と読取り失敗を区別する。
			for( const auto &[label, read] : reads) {
				text += L"\r\n" + loadString( label) + L": " +
						loadString( resourceFor( read->state, READ_RESOURCES)) ;
				// 診断を持つ非成功状態だけに元codeを付記する。
				if( read->diagnostic.domain != DeviceDiagnosticDomain::NONE) {
					text += diagnosticText( read->diagnostic) ;
				}
			}
		}
	} else {
		// 旧Providerの詳細未収集を個別の署名・依存合格へ変換しない。
		if( !candidate.assessment) {
			text += loadString( IDS_ASSESSMENT_UNCOLLECTED) ;
		} else {
			const auto &detail = *candidate.assessment ;	// 所有候補が保持する固定八軸。
			text +=
				loadString( IDS_ASSESSMENT_COMPONENT_ROLE) + L": " +
				loadString( detail.componentRole ? resourceFor( *detail.componentRole, ROLE_RESOURCES)
												: IDS_ASSESSMENT_UNCOLLECTED) +
				L"\r\n" ;
			// 共通localの条件なし判定はpackage内の静的検査範囲に限定して説明する。
			if( detail.componentRole &&
			   (candidate.discoveryBasis == CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ||
				candidate.discoveryBasis ==
					CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION)) {
				text += loadString( IDS_ASSESSMENT_PACKAGE_SCOPE) + L"\r\n" ;
			}

			text += loadString( IDS_ASSESSMENT_AXIS_METHOD) + L": " +
					loadString( resourceFor( detail.installMethod, METHOD_RESOURCES)) + L" / " +
					loadString( detail.executorAvailable ? IDS_ASSESSMENT_EXECUTOR_AVAILABLE
														: IDS_ASSESSMENT_EXECUTOR_UNAVAILABLE) ;
			const std::array<std::pair<UINT, const CandidateAssessmentFinding *>, 8> axes{
				{{IDS_ASSESSMENT_AXIS_ORIGIN, &detail.origin},
				 {IDS_ASSESSMENT_AXIS_ACQUISITION, &detail.acquisition},
				 {IDS_ASSESSMENT_AXIS_SIGNATURE, &detail.signature},
				 {IDS_ASSESSMENT_AXIS_APPLICABILITY, &detail.applicability},
				 {IDS_ASSESSMENT_AXIS_SELECTION, &detail.windowsSelection},
				 {IDS_ASSESSMENT_AXIS_DRIVER_ONLY, &detail.driverOnly},
				 {IDS_ASSESSMENT_AXIS_REQUIREMENTS, &detail.requirements},
				 {IDS_ASSESSMENT_AXIS_METHOD,
				  &detail.method}}} ;	// 根拠の生情報を含まない主理由の借用。
			// 全八軸を同じ形式で表示し、拒否と確認失敗を分ける。
			for( const auto &[label, finding] : axes) {
				text += L"\r\n" + loadString( label) + L": " +
						loadString( resourceFor( finding->state, STATE_RESOURCES)) + L" — " +
						loadString( resourceFor( finding->reason, REASON_RESOURCES)) ;
				// 元API診断がある場合だけ固定codeを付記する。
				if( finding->diagnostic) {
					text += diagnosticText( *finding->diagnostic) ;
				}
			}

			// 最大16件の明示条件は、任意条件と不足・必要値未知を分けて示す。
			for( const auto &requirement : detail.explicitRequirements) {
				text += L"\r\n  " + loadString( resourceFor( requirement.role, ROLE_RESOURCES)) +
						L" / " +
						loadString( requirement.required ? IDS_ASSESSMENT_REQUIRED
														: IDS_ASSESSMENT_OPTIONAL) +
						L": " +
						loadString( requirement.state == CandidateRequirementState::SATISFIED
									   ? IDS_ASSESSMENT_REQUIREMENT_SATISFIED
								   : requirement.state == CandidateRequirementState::UNSATISFIED
									   ? IDS_ASSESSMENT_REQUIREMENT_UNSATISFIED
									   : IDS_ASSESSMENT_REQUIREMENT_UNVERIFIED) ;
			}
		}
	}

	text += L"\r\n\r\n" + loadString( IDS_ASSESSMENT_NEXT) ;
	return appendHistory( std::move( text)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 候補の方式と最初の未確認・拒否理由を一覧用に整形する。
 * @param[in] candidate 表示する候補。
 * @return 詳細未収集または方式と主理由。全軸は詳細画面に保持する。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatCandidateAssessment( const UpdateCandidate &candidate) const
{
	// 旧Providerの集約合格から個別検査を捏造しない。
	if( !candidate.assessment) {
		return loadString( IDS_ASSESSMENT_UNCOLLECTED) ;
	}

	// 不正な結合を一覧の合格表現へ流さない。
	if( !isCandidateDetailsValid( candidate)) {
		return loadString( IDS_ASSESSMENT_INCONSISTENT) ;
	}

	const auto	&detail = *candidate.assessment ;	// 同一候補が所有する詳細。
	std::wstring text =
		// 方式は実行許可とは別。
		loadString( resourceFor( detail.installMethod, METHOD_RESOURCES)) ;
	const std::array<const CandidateAssessmentFinding *, 8> axes{
		&detail.origin,			  &detail.acquisition,
		&detail.signature,		  &detail.applicability,
		&detail.windowsSelection, &detail.driverOnly,
		&detail.requirements,	  &detail.method} ;	// 固定順の主理由。
	// 最初の未完了軸だけを一覧へ追加し、全詳細はread-only画面に残す。
	for( const auto *finding : axes) {
		// 合格・委譲・検査済み非該当は保留理由にしない。
		if( finding->state != CandidateAssessmentState::PASSED &&
		   finding->state != CandidateAssessmentState::MANAGED_BY_WINDOWS &&
		   finding->state != CandidateAssessmentState::NOT_APPLICABLE) {
			text += L" / " + loadString( resourceFor( finding->reason, REASON_RESOURCES)) ;
			break ;
		}
	}

	return text ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択したdeviceの全観測・候補詳細と一候補の選択欄を標準dialogで表示する。
 * @return Device行を処理した場合true。分類行や処理中はfalse。
 * @note 閲覧は選択を変えない。明示buttonだけが同deviceの一候補を選ぶ。
 */
//------------------------------------------------------------------------------
bool MainWindow::showSelectedCandidateDetails()
{
	// 処理中または未作成のTreeViewからmodal表示を開始しない。
	if( updateTree_ == nullptr || IsWindowEnabled( updateTree_) == FALSE) {
		return false ;
	}

	TVITEMW item{} ;	// 選択された標準controlのrow parameterだけを読む。
	item.mask  = TVIF_PARAM ;
	item.hItem = TreeView_GetSelection( updateTree_) ;
	// 選択されていない行や消失したitemを参照しない。
	if( item.hItem == nullptr || TreeView_GetItem( updateTree_, &item) == FALSE) {
		return false ;
	}

	const auto *row = treeRowFromParameter( item.lParam) ;	// 本関数がdialogを開く前だけ借用する。
	// 分類のdouble clickは標準の展開操作に残す。
	if( row == nullptr || row->kind != TreeRowKind::DEVICE ||
	   row->deviceIndex >= candidates_.size()) {
		return false ;
	}

	const auto session = controller_.scanSessionId() ;	// Modal終了後にも元scanとの結合を確認する。
	const auto deviceIdentity =
		candidates_[row->deviceIndex].deviceIdentity ;	// 同deviceの不透明な結合値。
	DeviceDetailDialog state{} ;						// Modal中は元候補vectorを借用せず所有snapshotだけを参照する。
	state.title		   = row->primaryText + L" — " + loadString( IDS_ASSESSMENT_TITLE) ;
	state.columnLabels = {loadString( IDS_DEVICE_DETAIL_COLUMN_CANDIDATE),
						  loadString( IDS_VERSION_LABEL), loadString( IDS_COLUMN_DATE),
						  loadString( IDS_DEVICE_DETAIL_COLUMN_SOURCE),
						  loadString( IDS_DEVICE_DETAIL_COLUMN_STATE)} ;
	std::map<std::wstring, std::vector<std::size_t>> displayGroups ;	// 同tokenだけを有限比較します。
	std::optional<std::size_t> resultEntry, explicitEntry, currentEntry, reportEntry,
		preparationEntry ;	// 初期閲覧だけの局所対応です。
	const auto preparationIndex =
		// 実行choiceとは別の元参照表示です。
		preparationDisplayCandidate( *row) ;
	// 同deviceの全候補を保持し、検査後候補の存在で元metadataや過去版を失わせない。
	for( const auto index : row->candidateIndexes) {
		// 破損した表示indexを別deviceの先頭候補へ補完しない。
		if( index >= candidates_.size() || candidates_[index].deviceIdentity != deviceIdentity) {
			continue ;
		}

		const auto		 &candidate = candidates_[index] ;	// 本entryを作る間だけの同scan候補の借用。
		DeviceDetailEntry entry{} ;							// 候補選択欄と本文の同じsnapshot。
		entry.candidateIndex = index ;
		entry.selectable	 = controller_.state() == ApplicationState::SCAN_READY &&
						   controller_.scanPurpose() == ScanPurpose::STANDARD && session != 0U &&
						   isSelectableCandidate( candidate) &&
						   (!showRecommendedOnly_ || visibleInRecommendedFilter( candidate)) ;
		const auto unknown = loadString( IDS_VALUE_UNKNOWN) ;	// 欠損値を版や日付へ補完しない。
		const auto version = candidate.version.empty() && candidate.metadataDistribution
								 ? candidate.metadataDistribution->version
								 : candidate.version ;	// 元参照版を保持する。
		entry.columns	   = {candidate.current ? loadString( IDS_DEVICE_DETAIL_CURRENT)
												: candidate.title,
						  version.empty() ? unknown : version,
						 candidate.driverDate.empty() ? unknown : candidate.driverDate,
						 candidate.sourceName.empty() ? unknown : candidate.sourceName,
						 formatCandidateState( candidate)} ;
		UINT stateResource = IDS_DETAIL_TIP_UNKNOWN ;	// 表示文字列ではなく元状態から説明を作ります。
		const bool pending =
			!candidate.installable && candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
			!candidate.preparationTargetIdentity.empty() ;	// 取得前の比較は導入actionと区別します。
		// 現在観測は導入候補として説明しません。
		if( candidate.current) {
			stateResource =
				candidate.deviceObservation && candidate.deviceObservation->driverPresence ==
												   DeviceDriverPresence::NOT_INSTALLED
					? IDS_DETAIL_TIP_CURRENT_MISSING
					: IDS_DETAIL_TIP_CURRENT ;
		}
		// 元検索が既に失効したsnapshotを説明します。
		else if( controller_.state() != ApplicationState::SCAN_READY || session == 0U) {
			stateResource = IDS_DETAIL_TIP_STALE ;
		}
		// 明示的な不適合を未知と区別します。
		else if( candidate.audit.systemApplicability == CandidateAuditGateState::REJECTED) {
			stateResource = IDS_DETAIL_TIP_INAPPLICABLE ;
		}
		// 元の取得/導入計画を持たない候補は新旧の分類と独立して選択できません。
		else if( !isSelectableCandidate( candidate)) {
			stateResource = IDS_DETAIL_TIP_NO_PLAN ;
		}
		// 未導入の実観測に結び付く初回候補です。
		else if( candidate.action == DriverAction::INITIAL_INSTALL ||
				isInitialPreparationReference( candidate)) {
			stateResource = IDS_DETAIL_TIP_INITIAL ;
		}
		// 申告バージョンの比較を未検査のまま説明します。
		else if( pending) {
			const auto relation = classifyPendingReferenceVersion(
				candidate, candidates_, session) ;	// 元同device観測の比較です。
			stateResource =
				relation == PendingReferenceVersion::NEWER	 ? IDS_DETAIL_TIP_PENDING_NEWER
				: relation == PendingReferenceVersion::SAME	 ? IDS_DETAIL_TIP_PENDING_SAME
				: relation == PendingReferenceVersion::OLDER ? IDS_DETAIL_TIP_PENDING_OLDER
															 : IDS_DETAIL_TIP_UNKNOWN ;
		}
		// 検査済み候補の元操作分類を使います。
		else if( candidate.installable) {
			stateResource = candidate.action == DriverAction::DOWNGRADE	  ? IDS_DETAIL_TIP_OLDER
							: candidate.action == DriverAction::REINSTALL ? IDS_DETAIL_TIP_SAME
																		  : IDS_DETAIL_TIP_NEWER ;
		}

		std::wstring explanation = loadString( stateResource) ;	// Snapshotの短い説明だけです。
		// 推奨filterの影響は元の選択条件と区別して付記します。
		if( !candidate.current && showRecommendedOnly_ && isSelectableCandidate( candidate) &&
		   !visibleInRecommendedFilter( candidate)) {
			explanation += L" " + loadString( IDS_DETAIL_TIP_FILTERED) ;
		}

		entry.tips = {
			(candidate.current ? L"" : loadString( IDS_DETAIL_TIP_NAME) + L" ") + explanation,
			loadString( version.empty() ? IDS_DETAIL_TIP_VERSION_UNKNOWN : IDS_DETAIL_TIP_VERSION) +
				L" " + explanation,
			loadString( candidate.driverDate.empty() ? IDS_DETAIL_TIP_DATE_UNKNOWN
					   : candidate.current			? IDS_DETAIL_TIP_DATE_CURRENT
					   : candidate.installable		? IDS_DETAIL_TIP_DATE_CHECKED
													: IDS_DETAIL_TIP_DATE_PENDING) +
				L" " + explanation,
			loadString( candidate.current			  ? IDS_DETAIL_TIP_SOURCE_CURRENT
					   : pending					  ? IDS_DETAIL_TIP_SOURCE_INDEX
					   : candidate.sourceName.empty() ? IDS_DETAIL_TIP_SOURCE_UNKNOWN
													  : IDS_DETAIL_TIP_SOURCE) +
				L" " + explanation,
			explanation} ;
		// 元候補の匿名化済み実行結果と原診断だけを保持し、失効を導入許可に戻しません。
		if( index < candidateResultTexts_.size() && !candidateResultTexts_[index].empty()) {
			entry.columns[4] = candidateResultTexts_[index] ;
			entry.tips[4]	 = loadString( IDS_CANDIDATE_EXECUTION_HISTORY) + L" " +
							shortDeviceResult( candidateResultTexts_[index]) + L" " +
							loadString( IDS_DETAIL_TIP_STALE) ;
		}

		const bool hasResult =
			index < candidateResultTexts_.size() &&
			!candidateResultTexts_[index].empty() ;	// 個別結果は他行へ吸収しません。
		auto &possibleTwins =
			displayGroups[candidate.detailDisplayIdentity] ;	// 空tokenは検索しません。
		const auto twin			   = std::ranges::find_if( possibleTwins, [&]( const auto position) {
			   const auto &existing = state.entries[position] ;					// 元順の表示slotです。
			   const auto &original = candidates_[existing.candidateIndex] ;	// 構築中だけ借用します。
			   return !candidate.current && !original.current && !hasResult &&
					  (existing.candidateIndex >= candidateResultTexts_.size() ||
					   candidateResultTexts_[existing.candidateIndex].empty()) &&
					  !candidate.detailDisplayIdentity.empty() &&
					  candidate.detailDisplayIdentity == original.detailDisplayIdentity &&
					  candidate.providerId == original.providerId &&
					  candidate.deviceIdentity == original.deviceIdentity &&
					  candidate.preparationTargetIdentity == original.preparationTargetIdentity &&
					  candidate.packageIdentity == original.packageIdentity &&
					  candidate.action == original.action &&
					  candidate.installable == original.installable &&
					  candidate.allContentCached == original.allContentCached &&
					  candidate.requiredExtensionCount == original.requiredExtensionCount &&
					  candidate.requiredDriverComponentCount ==
						  original.requiredDriverComponentCount &&
					  entry.selectable == existing.selectable && entry.columns == existing.columns &&
					  entry.tips == existing.tips ;
		   }) ; // 表示だけの同一性で、元plan/record/routingは変更しません。
		const auto displayPosition = twin == possibleTwins.end()
										 ? state.entries.size()
										 : *twin ;	// 元indexから表示位置へ写します。
		// 個別結果の元順を保持し、未取得候補の最大値へ置換しません。
		if( hasResult) {
			resultEntry = displayPosition ;
		}

		// 元参照の閲覧位置だけを保持し、同内容groupの元indexや選択可否を変更しません。
		if( preparationIndex && *preparationIndex == index) {
			preparationEntry = displayPosition ;
		}

		// 単一候補や推奨からの暗黙指定は、利用者の明示指定と区別します。
		if( row->hasCandidateChoice && row->explicitCandidateChoice &&
		   row->candidateIndex == index) {
			explicitEntry = displayPosition ;
		}

		// 現在観測の位置を0行目と仮定しません。
		if( candidate.current && (!currentEntry || index == row->deviceIndex)) {
			currentEntry = displayPosition ;
		}

		// 後出の元選択memberも初出の表示位置の代表に保ちます。
		if( twin != possibleTwins.end()) {
			// 閲覧だけでは新しい元候補へ選択を移しません。
			if( row->hasCandidateChoice && row->candidateIndex == index) {
				state.entries[*twin] = std::move( entry) ;
			}
		} else {
			// 空tokenを同一性の根拠へ使わず、全件比較も増やしません。
			if( !candidate.detailDisplayIdentity.empty()) {
				possibleTwins.push_back( state.entries.size()) ;
			}

			state.entries.push_back( std::move( entry)) ;
		}
	}

	std::vector<std::size_t> distinctCounts(
		// 未証明の同表示だけを識別します。
		state.entries.size()) ;
	std::vector<std::size_t> distinctOrdinals( state.entries.size()) ;	// 表示順の短い連番です。
	std::map<std::array<std::wstring, 5>, std::vector<std::size_t>>
		identicalText ;	// 表示だけの局所索引です。
	// 名前を変更する前の五列値で別情報を数えます。
	for( std::size_t position{}; position < state.entries.size(); ++position) {
		const auto &entry = state.entries[position] ;	// 所有値だけを比較します。
		// 現在観測と実行結果に候補の識別suffixを付けません。
		if( candidates_[entry.candidateIndex].current ||
		   (entry.candidateIndex < candidateResultTexts_.size() &&
			!candidateResultTexts_[entry.candidateIndex].empty())) {
			continue ;
		}

		identicalText[entry.columns].push_back( position) ;
	}

	// 同じ表示のslotだけへ短い連番と件数を写します。
	for( const auto &group : identicalText) {
		// 原候補の順序や選択は変更しません。
		for( std::size_t member{}; member < group.second.size(); ++member) {
			const auto position		   = group.second[member] ;	// 対応する表示slotだけです。
			distinctCounts[position]   = group.second.size() ;
			distinctOrdinals[position] = member + 1U ;
		}
	}

	std::size_t candidateNumber{} ;	// 表示行確定後の連番で欠番を作りません。
	// 別の元情報は短い名前suffixと既hoverだけで識別します。
	for( std::size_t position{}; position < state.entries.size(); ++position) {
		auto &entry = state.entries[position] ;	// Modalで所有し続ける値です。
		// 現在構成の名称は候補番号に変えません。
		if( candidates_[entry.candidateIndex].current) {
			continue ;
		}

		entry.columns[0] =
			formatResource( IDS_DEVICE_DETAIL_CANDIDATE, std::to_wstring( ++candidateNumber)) +
			(entry.columns[0].empty() ? L"" : L": " + entry.columns[0]) ;
		// 不明な同一性を別内容の確定や導入許可にしません。
		if( distinctCounts[position] > 1U) {
			entry.columns[0] += formatResource( IDS_DEVICE_DETAIL_DISTINCT_INFORMATION,
											   std::to_wstring( distinctOrdinals[position])) ;
			entry.tips[0] += L" " + loadString( IDS_DETAIL_TIP_DISTINCT_INFORMATION) ;
		}
	}

	const auto candidateEntryCount =
		// reportの元indexを候補として読まない上限です。
		state.entries.size() ;
	// 元operationの全体reportを閲覧専用で残し、当該deviceだけの成功と解釈させない。
	if( !state.entries.empty() && !preparationResultText_.empty()) {
		DeviceDetailEntry report{} ;	// 選択を発行しない所有snapshot。
		report.columns = {loadString( IDS_DEVICE_DETAIL_PREPARATION_REPORT),
						  loadString( IDS_VALUE_UNKNOWN), loadString( IDS_VALUE_UNKNOWN),
						  loadString( IDS_VALUE_UNKNOWN),
						  loadString( IDS_DEVICE_DETAIL_REPORT_READONLY)} ;
		std::wstring summary ;												// 元reportの固定状態と数値だけを残します。
		std::wstring reportCodes ;											// 診断行の検証済み数値だけです。
		const auto	 approvalPattern = loadString( IDS_PREPARATION_ERROR) ;	// 固定診断行の先頭です。
		const auto	 approvalPrefix =
			// 対象名とは区別します。
			approvalPattern.substr( 0U, approvalPattern.find( L"%1")) ;
		constexpr std::array<UINT, 15> resultResources{
			IDS_PREPARATION_FAILED,
			IDS_PREPARATION_ACQUIRED,
			IDS_PREPARATION_NOT_SELECTED,
			IDS_PREPARATION_AWAITING_NETWORK,
			IDS_PREPARATION_CANCELLED,
			IDS_PREPARATION_REJECTED,
			IDS_PREPARATION_ITEM_FAILED,
			IDS_PREPARATION_PUBLICATION_FAILED,
			IDS_PREPARATION_PUBLICATION_NONE,
			IDS_PREPARATION_AUDIT_READY,
			IDS_PREPARATION_PUBLICATION_NOT_STARTED,
			IDS_INDEX_CONTENT_FAILED,
			IDS_INDEX_CONTENT_COMPLETED,
			IDS_INDEX_SCAN_PARTIAL,
			IDS_INDEX_SCAN_UNAVAILABLE} ;	// 本文/対象名を採用しない有限allowlistです。
		std::size_t start{} ;				// 元reportの読取りだけを行います。
		// 固定状態の重複を除き、巨大な全対象reportを移植しません。
		while( start < preparationResultText_.size()) {
			const auto end =
				// 行境界だけを読みます。
				preparationResultText_.find_first_of( L"\r\n", start) ;
			const auto line =
				std::wstring_view( preparationResultText_)
					.substr( start,
							end == std::wstring::npos ? std::wstring::npos
													  : end - start) ;	// 私有表示値は採用しません。
			const bool fixed = std::ranges::any_of( resultResources, [&]( const UINT id) {
				return line == loadString( id) ;
			}) ; // 既resourceとの完全一致だけを状態として表示します。
			// 固定状態だけが通常文言として要約へ入ります。
			if( fixed && summary.find( line) == std::wstring::npos &&
			   summary.size() + line.size() < 160U) {
				summary += std::wstring( line) + L" " ;
			}

			// 既formatNativeErrorの行と固定承認診断行だけを数値へ射影します。
			if( line.starts_with( L"0x") ||
			   (!approvalPrefix.empty() && line.starts_with( approvalPrefix))) {
				const auto codes = deviceResultCodes( line) ;	// 元数値だけを検証します。
				// 巨大な対象集合も有限の診断要約に留めます。
				if( reportCodes.size() + codes.size() <= 44U &&
				   reportCodes.find( codes) == std::wstring::npos) {
					reportCodes += codes ;
				}
			}

			// 不明な自由文を診断へ変換しません。
			if( end == std::wstring::npos) {
				break ;
			}

			start = end + 1U ;
		}

		// 元reportからは固定長を検証した数値だけを追加し、対象名/本文を転記しません。
		summary += reportCodes ;
		report.tips[0] = loadString( IDS_DETAIL_TIP_REPORT) ;
		report.tips[4] = report.tips[0] + L" " + summary ;
		reportEntry	   = state.entries.size() ;
		state.entries.push_back( std::move( report)) ;
	}

	// 有効entryを一件も作れなければ選択欄を空の成功画面にしない。
	if( state.entries.empty()) {
		return false ;
	}

	std::optional<std::size_t>	 latestEntry ;		// 明示button前には元selectionを変更しません。
	std::optional<std::uint64_t> latestVersion ;	// 表示文字列でなく既四要素数値だけです。
	const UpdateCandidate		*observed{} ;		// 同scan/deviceの一意な現在行を構築中だけ借用します。
	bool duplicateCurrent{} ;						// 複数の現在観測から都合のよい版を採用しません。
	// 現在観測の版と初回状態を元opaque deviceへ結びます。
	for( const auto &candidate : candidates_) {
		// 別deviceや非現在行を比較根拠へ加えません。
		if( candidate.current && candidate.deviceIdentity == deviceIdentity) {
			duplicateCurrent = duplicateCurrent || observed != nullptr ;
			observed		 = &candidate ;
		}
	}

	const bool validObservation =
		observed && !duplicateCurrent && session != 0U &&
		isCandidateDetailsValid( *observed, session) && observed->deviceObservation &&
		isDeviceObservationBound( *observed->deviceObservation, session,
								 deviceIdentity) ;	// 不明を初回へ補完しません。
	const bool initial =
		validObservation && observed->deviceObservation->driverPresence ==
								DeviceDriverPresence::NOT_INSTALLED ;	// 元未導入観測だけです。
	const auto currentVersion =
		validObservation &&
				observed->deviceObservation->driverPresence == DeviceDriverPresence::REGISTERED &&
				observed->deviceObservation->version.state == DevicePropertyReadState::VALUE
			? parseFourPartDriverVersion( observed->version)
			: std::nullopt ;	// 日付や公開番号で補いません。
	// 所有entryの代表を比較し、元同内容memberと元候補indexを維持します。
	for( std::size_t position{}; position < candidateEntryCount; ++position) {
		const auto &entry = state.entries[position] ;	// Modal生成前だけの元候補参照です。
		const auto &candidate =
			candidates_[entry.candidateIndex] ;	// 検査/取得の許可は変更しません。
		// 結果/readonly/不適合を自動候補へ昇格しません。
		if( !entry.selectable || candidate.current ||
		   (entry.candidateIndex < candidateResultTexts_.size() &&
			!candidateResultTexts_[entry.candidateIndex].empty()) ||
		   candidate.audit.systemApplicability == CandidateAuditGateState::REJECTED ||
		   !isCandidateDetailsValid( candidate, session)) {
			continue ;
		}

		const bool pending = !candidate.installable &&
							 // 元INF申告だけを分類します。
							 candidate.providerId == SIGNED_INDEX_PROVIDER_ID ;
		const bool windowsVersion =
			pending || candidate.discoveryBasis == CandidateDiscoveryBasis::LOCAL_INVENTORY ||
			(candidate.assessment &&
			 candidate.assessment->installMethod ==
				 CandidateInstallMethod::STANDARD_INF) ;	// 四要素という見た目だけを根拠にしません。
		const auto version = windowsVersion
								 ? parseFourPartDriverVersion( candidate.version)
								 : std::nullopt ;	// metadataDistributionの配布番号は比較しません。
		const bool eligible =
			initial
				? (candidate.action == DriverAction::INITIAL_INSTALL ||
				   isInitialPreparationReference( candidate))
				: (currentVersion && version && *version > *currentVersion &&
				   (candidate.action == DriverAction::UPDATE ||
					(pending && classifyPendingReferenceVersion( candidate, candidates_, session) ==
									PendingReferenceVersion::NEWER))) ;	// 初回と通常更新を分けます。
		// 比較不能/同じ/古い版を新しい日付で補完しません。
		if( !version || !eligible) {
			continue ;
		}

		// 暗黙の元指定は同じ最大値のtieだけで保持します。
		if( !latestVersion || *version > *latestVersion ||
		   (*version == *latestVersion && row->hasCandidateChoice &&
			entry.candidateIndex == row->candidateIndex)) {
			latestVersion = version ;
			latestEntry	  = position ;
		}
	}

	state.initialEntry = resultEntry.value_or( explicitEntry.value_or(
		preparationEntry.value_or( latestEntry.value_or( currentEntry.value_or( reportEntry.value_or(
			std::numeric_limits<
				std::size_t>::max())))))) ;	// 元結果と現在の明示指定を優先する閲覧順です。

	// 同期dialog呼出しの間だけ所有snapshotが生存するWin32境界。
	const INT_PTR result = DialogBoxParamW( instance_, MAKEINTRESOURCEW( IDD_DEVICE_DETAILS), window_,
										   detailDialogProc, reinterpret_cast<LPARAM>( &state)) ;
	// 標準templateの生成失敗時は固定案内だけを表示し、自動選択しません。
	if( result == -1) {
		MessageBoxW( window_, loadString( IDS_ASSESSMENT_INCONSISTENT).c_str(), state.title.c_str(),
					MB_OK | MB_ICONINFORMATION) ;
	}

	// 閲覧だけでは選択を変えず、元scanと同deviceの一候補を再検証してから結合する。
	if( result == IDYES && state.choiceRequested && controller_.scanSessionId() == session &&
	   state.chosenCandidateIndex < candidates_.size() &&
	   candidates_[state.chosenCandidateIndex].deviceIdentity == deviceIdentity) {
		static_cast<void>( selectDeviceCandidate( state.chosenCandidateIndex)) ;
	}

	return true ;
}

} // namespace drivercrate
