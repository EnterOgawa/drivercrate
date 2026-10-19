//------------------------------------------------------------------------------
/**
 * @file main_window.h
 * @brief DriverCrateメインウィンドウ定義。
 * @version 01.08.00
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測差分表示契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得確認と独立した操作状態を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  TreeTable表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  TreeTable font拡大。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Device class icon表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  TreeTable column sort追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  推奨更新表示filter追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Filter checkbox独自描画。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  上下message font拡大。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  更新候補一括選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  決定型進捗と自動再scan追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  下部全幅progress帯追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Install結果保持と候補失効表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider取得元設定と状態表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  同一版取得元選択表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Windows Server install確認追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local候補到達dialog追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  公式探索経路表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者指定Intel ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者指定Prolific ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者指定WCH ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH342／CH343系ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Silicon Labs CP210x ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用署名済みINF ZIP選択追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補監査状態列追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Scan時点の段階別計測表示を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の条件・取消し・表示専用結果を接続。
 * Ver.01.01.00 Shunji Ogawa  2026/09/14  種類別三階層と表示件数の契約を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  登録状態・候補検証理由と詳細画面を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  通常scanの協調取消しUIを追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  索引の取得・内容の独立結果表示を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  私有event dispatchと内部索引画面fixtureを接続。
 * Ver.01.05.01 Shunji Ogawa  2026/10/14  別live限定の通常scan read-only観測を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * Ver.01.07.00 Shunji Ogawa  2026/10/16  索引通信結果の可視導線と同版publicationの画面受入を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/16  索引通信詳細の全文と数値末尾の実control観測を追加。
 * </pre>
 *
 * @note Top-level Win32 Window、TreeTable、およびUI stateを定義します。全member functionは、worker notificationを除き
 *       UI threadで実行します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/operation_controller.h"
#include "core/provider_registry.h"
#include "core/update_types.h"
#include "platform/provider_worker.h"

// Windows.hはCommon ControlsとSetupAPIの基本型より先に必要である。
// clang-format off
#include <Windows.h>
#include <CommCtrl.h>
#include <SetupAPI.h>
// clang-format on

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// Window class定義。
//------------------------------------------------------------------------------

/**
 * @brief scan、selection、install result を表示する application Window である。
 */
class MainWindow final {
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
	// 内部targetだけで非通信factoryと状態の検査を許し、製品APIへ公開しない。
	friend struct MainWindowMetadataTestAccess ;
#endif
#if defined( DRIVERCRATE_INTERNAL_LIVE_INDEX_TESTS)
	// 明示live測定だけに通常workerの匿名件数とTree選択の観測を許します。
	friend struct MainWindowLiveIndexTestAccess ;
#endif
public:
	/**
	 * @brief 本classが所有するmessage font、TreeTable font、class image listを解放する。
	 * 本classが所有するUI resourceを解放する。
	 * DPI変更時に作成した上下message用font、TreeTable用font、SetupAPIから取得したclass image listを一度だけ解放する。
	 */
	~MainWindow() ;

	/**
	 * @brief Window class と top-level Window を作成する。
	 * 専用iconを設定したWindow classとtop-level Windowを作成する。Resource取得失敗時はWindows標準iconへfallbackする。
	 * @param[in] instance application module instance。
	 * @return Window 作成に成功した場合は `true`。
	 */
	[[nodiscard]] bool create( HINSTANCE instance) ;

	/**
	 * @brief Window を表示して UI message loop を実行する。
	 * Window を表示して UI message loop を実行する。 事前条件: `create` が成功していること。
	 * @param[in] showCommand `wWinMain` が受け取った初期表示 command。
	 * @return process exit code。
	 * @pre `create` が成功していること。
	 */
	[[nodiscard]] int  run( int showCommand) ;

private:
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
	/// Test所有の非通信Provider生成関数。空なら初期化を拒否する。
	ProviderFactory		 testProviderFactory_ ;
	/// Test所有の復旧fake生成関数。Windows APIへfallbackしない。
	RestorePointFactory	 testRestorePointFactory_ ;
	/// 隠した内部結果fixtureだけでmodal表示を抑制し、確定本文とcontrolを観測します。
	bool				 testSuppressPreparationResultDialog_{} ;
	/// 内部UI観測だけが、実dialogへ渡した所有本文の埋込NULとcopy境界を確認します。
	mutable std::wstring testIndexRefreshDetailBody_ ;
#endif
	/**
     * @brief TreeTableの分類、device、driver candidateの階層を表す。
     */
	enum class TreeRowKind {
		/// Windows setup class別の表示専用group。
		DEVICE_CLASS,
		/// 展開可能でinstall対象にならないdevice親行。
		DEVICE,
		/// Checkboxで選択できるdriver candidate子行。
		CANDIDATE,
	} ;

	/**
     * @brief TreeView item と複数のtable columnへ描画する一行分の表示値である。
     */
	struct TreeRow {
		/// 行の階層と選択可否を決定する分類。
		TreeRowKind	  kind{TreeRowKind::DEVICE} ;
		/// Tree階層を描く第一columnの表示文字列。
		std::wstring  primaryText ;
		/// 分類件数を含まないsort用の種類名。分類行だけで使用する。
		std::wstring  className ;
		/// trueの場合は分類未解決として末尾へ配置する。
		bool		  unknownClass{} ;
		/// Deviceで現在使用中のdriver version。
		std::wstring  currentVersion ;
		/// Candidateが提示するdriver version。
		std::wstring  candidateVersion ;
		/// 論理取得元とpolicy境界を示す場所。
		std::wstring  source ;
		/// Driver packageを提供するpublisher名。
		std::wstring  provider ;
		/// Providerが提示するdriver日付。
		std::wstring  date ;
		/// 最大download sizeまたはlocal cache状態。
		std::wstring  size ;
		/// 由来、取得、内容、適用性、install準備状態。
		std::wstring  audit ;
		/// 操作分類またはdownload/install結果。
		std::wstring  status ;
		/// Size columnの数値sortに使用するbyte数。
		std::uint64_t downloadBytes{} ;
		/// trueの場合はdownload_bytesが取得済み。
		bool		  hasDownloadBytes{} ;
		/// Candidate行が参照するscan結果内index。
		std::size_t	  candidateIndex{} ;
	} ;

	/**
     * @brief TreeView sort callbackで使用する一回のsort条件である。
     */
	struct TreeSortContext {
		/// Row parameterを解決する非所有MainWindow pointer。
		const MainWindow *window{} ;
		/// 0始まりのsort対象column index。
		std::size_t		  columnIndex{} ;
		/// trueの場合は昇順、falseの場合は降順。
		bool			  ascending{} ;
	} ;

	/// Provider workerのresult queue到着を通知するprivate Window message。
	static constexpr UINT		 WORKER_NOTIFICATION_MESSAGE = WM_APP + 1 ;
	/// TreeTableに表示する固定column数。
	static constexpr std::size_t TREE_COLUMN_COUNT = 9 ;

	/**
	 * @brief Win32 callback を instance method へ転送する。
	 * @param[in] window 対象 Window。
	 * @param[in] message Win32 message ID。
	 * @param[in] wordParameter message 固有の WPARAM。
	 * @param[in] longParameter message 固有の LPARAM。
	 * @return message 処理結果。
	 */
	static LRESULT CALLBACK		 windowProc( HWND window, UINT message, WPARAM wordParameter,
											LPARAM longParameter) noexcept ;

	/**
	 * @brief 標準checkboxの動作を維持したまま背景をWindowと一体化して描画する。
	 * 推奨更新filter checkboxの描画messageを処理する。
	 * Checkboxの標準入力処理をDefSubclassProcへ委譲し、paintだけを親Windowと同じ背景へ置き換える。WM_NCDESTROYでsubclassを必ず解除する。
	 * @param[in] window 対象checkbox Window。
	 * @param[in] message Win32 message ID。
	 * @param[in] wordParameter message固有のWPARAM。
	 * @param[in] longParameter message固有のLPARAM。
	 * @param[in] subclassId 登録時に指定したsubclass ID。
	 * @param[in] referenceData 非所有MainWindow pointerの整数表現。
	 * @return message処理結果。
	 */
	static LRESULT CALLBACK recommendedFilterProc( HWND window, UINT message, WPARAM wordParameter,
												  LPARAM longParameter, UINT_PTR subclassId,
												  DWORD_PTR referenceData) noexcept ;

	/**
	 * @brief TreeView itemの表示値を指定columnと方向で比較する。
	 * 分類行は種類名の昇順とし、不明分類は末尾へ置く。Device親行は対象値を持つcolumnだけでsortする。
	 * Candidate子行は選択columnでsortし、同値は第一columnの昇順で安定化する。
	 * @param[in] leftParameter 左側itemの1始まりrow index。
	 * @param[in] rightParameter 右側itemの1始まりrow index。
	 * @param[in] contextParameter 本呼出し中だけ有効なTreeSortContext pointer。
	 * @return 左側が先なら負、等しければ0、右側が先なら正の値。
	 */
	static int CALLBACK		compareTreeItems( LPARAM leftParameter, LPARAM rightParameter,
											 LPARAM contextParameter) noexcept ;

	/**
	 * @brief instance に関連付けられた Win32 message を処理する。
	 * @param[in] message Win32 message ID。
	 * @param[in] wordParameter message 固有の WPARAM。
	 * @param[in] longParameter message 固有の LPARAM。
	 * @return message 処理結果。
	 */
	LRESULT					handleMessage( UINT message, WPARAM wordParameter, LPARAM longParameter) ;

	/**
	 * @brief 推奨更新filter checkboxのcheck記号、label、およびfocusを描画する。
	 * 推奨更新filter checkboxを背景枠なしで描画する。
	 * 親Windowと同じ背景上へ標準check記号、label、および必要時のfocus枠だけを描画する。Button control全体を囲む背景矩形は描画せず、有効状態変更後も白背景へ再
	 * 描画する。
	 * @param[in] deviceContext 本描画中だけ有効な描画先device context。
	 */
	void					drawRecommendedFilter( HDC deviceContext) const noexcept ;

	/**
	 * @brief 下部status帯へ通常messageまたは全幅progressとmessageを描画する。
	 * 処理中は帯全体へ確定済み完了率を塗り、塗り部分と未塗り部分でsystem text色を切り替えて同一messageを描画する。
	 * @param[in] drawItem `WM_DRAWITEM`中だけ有効な描画情報。 WM_DRAWITEM中だけ有効な描画情報。
	 */
	void					drawStatusBand( const DRAWITEMSTRUCT &drawItem) const noexcept ;

	/**
	 * @brief child control と Provider worker を初期化する。
	 * @return 全必須 resource を初期化できた場合は `true`。
	 */
	[[nodiscard]] bool		onCreate() ;

	/**
	 * @brief client size と DPI に合わせて child control を配置する。
	 */
	void					layoutControls() noexcept ;

	/**
	 * @brief 現在DPIに合わせて上下message用fontを更新する。
	 * Windowsのmessage fontを基準に10 point以上のfontを作成し、上部の説明文と下部のstatusへ適用する。System設定が既に大きい場合は縮小せず、新font
	 * 適用後に旧fontを解放する。
	 * @param[in] dpi fontを作成する対象DPI。
	 * @return fontを作成してcontrolへ適用できた場合は`true`。
	 */
	[[nodiscard]] bool		updateMessageFont( UINT dpi) noexcept ;

	/**
	 * @brief 現在DPIに合わせてTreeTable用fontと行高を更新する。
	 * Windowsのmessage fontを基準に11 point以上のfontを作成し、Header、TreeView、custom draw、行高へ一括適用する。新fontの適用後に旧
	 * fontを解放し、controlの参照を残さない。
	 * @param[in] dpi fontを作成する対象DPI。
	 * @return fontを作成してcontrolへ適用できた場合は`true`。
	 */
	[[nodiscard]] bool		updateTreeFont( UINT dpi) noexcept ;

	/**
	 * @brief Windows標準のsetup class image listをTreeTableへ設定する。
	 * Device Manager形式に近いSetupAPI class image listを使用し、GUIDを取得できない候補用のUnknown iconも解決する。image listの
	 * ownershipはMainWindowが保持する。
	 * @return image listを取得しTreeViewへ設定できた場合は`true`。
	 */
	[[nodiscard]] bool		initializeDeviceClassImages() noexcept ;

	/**
	 * @brief Candidateのsetup class GUIDに対応するimage indexを取得する。
	 * DTOのcanonical GUIDだけをSetupAPIへ渡し、hardware IDやdevice instance IDをUI threadへ持ち込まない。
	 * @param[in] candidate 表示対象のcandidate。
	 * @return SetupAPI class image index。取得できない場合は汎用image index。 SetupAPI class image index。取得できない場
	 *         合は汎用index。
	 */
	[[nodiscard]] int		deviceClassImageIndex( const UpdateCandidate &candidate) noexcept ;

	/**
	 * @brief 表示GUIDを正規化し、種類groupのkeyへ変換する。
	 * @param[in] value 現在行を優先して選んだ表示用GUID。
	 * @return Brace付きGUID。不正・欠損は空文字列。
	 * @note Device照合や導入権限の根拠には使用しない。
	 */
	[[nodiscard]] std::wstring deviceClassKey( std::wstring_view value) const ;

	/**
	 * @brief Local Windowsの分類説明を有限bufferで読み取る。
	 * @param[in] key 正規GUID。空または取得失敗はその他の分類とする。
	 * @return Windowsの分類説明。取得不能は空文字列。
	 * @note UI threadで種類ごとに一回だけ使用し、network・device列挙を行わない。
	 */
	[[nodiscard]] std::wstring deviceClassName( std::wstring_view key) const ;

	/**
	 * @brief 表示中の三階層からdevice数と情報／通常更新device数を集計する。
	 * @param[in] expired trueならinstall後の失効表示とし、導入可能件数を提示しない。
	 * @note Candidateを変更せず、分類行の表示値とaccessibility本文だけを更新する。
	 */
	void					   updateDeviceClassSummaries( bool expired = false) ;

	/**
	 * @brief TreeTable の固定columnをresource文字列から作成する。
	 * @return 全columnを作成できた場合は `true`。
	 */
	[[nodiscard]] bool		   initializeTreeColumns() ;

	/**
	 * @brief Window幅の変化に合わせて利用者が調整したcolumn比率を維持する。
	 * @param[in] tableWidth TreeTable controlへ割り当てた幅（physical pixel）。
	 */
	void					   resizeTreeColumns( int tableWidth) noexcept ;

	/**
	 * @brief Header clickに応じてsort columnと昇順・降順を更新する。
	 * 新しいcolumnは昇順、同じcolumnの再clickは方向を反転し、Header矢印とTreeView順序を同じ状態へ更新する。
	 * @param[in] columnIndex clickされた0始まりcolumn index。
	 */
	void					   handleHeaderClick( int columnIndex) noexcept ;

	/**
	 * @brief 現在のsort条件をHeaderの方向矢印へ反映する。
	 * HDF_SORTUPとHDF_SORTDOWNを選択columnだけに設定し、以前のcolumnに残った方向表示を除去する。
	 */
	void					   updateTreeSortIndicator() const noexcept ;

	/**
	 * @brief 種類・device・driver候補の各階層を表示値で並べ替える。
	 * TreeViewのitem自体をsortし、item handle、checkbox、展開状態、candidate indexとidentityの対応を変更しない。
	 */
	void					   sortTreeItems() noexcept ;

	/**
	 * @brief TreeViewの標準階層描画後に各table columnの値とgridを描画する。
	 * @param[in] customDraw `NM_CUSTOMDRAW`中だけ有効なTreeView描画情報。
	 */
	void					   drawTreeRow( const NMTVCUSTOMDRAW &customDraw) const noexcept ;

	/**
	 * @brief 利用者操作または operation state に応じて button を更新する。
	 * 利用者操作またはoperation stateに応じてscan、install、一括選択、filter controlの有効状態を更新する。
	 */
	void					   updateCommandState() const noexcept ;

	/**
	 * @brief 現在のscan結果とfilter状態に対応する件数statusを表示する。
	 * Scan結果とfilter状態に対応する件数statusを表示する。
	 * Filter中は表示中の推奨更新件数を示す。Filter解除時は全install可能候補件数とProvider warningを復元する。
	 */
	void					   updateScanSummaryStatus() ;

	/**
	 * @brief Checkboxの状態を推奨更新表示filterへ反映してTreeTableを再構築する。
	 * Checkboxの状態を推奨更新表示filterへ反映する。
	 * ScanReadyの間だけfilterを変更し、保持済みselectionから表示対象のcheck状態を復元する。非表示候補はinstall対象へ含めない。
	 */
	void					   handleRecommendedFilterChange() ;

	/**
	 * @brief 推奨かつinstall可能な候補を一device一件ずつ一括選択する。
	 * 推奨かつinstall可能な候補を一括選択する。
	 * ScanReadyの間だけ、Providerが推奨するinstall可能候補を一device一件ずつ選択する。現在版と過去版は選択せず、利用者が選んでいた旧版も推奨更新へ置き換える。
	 */
	void					   selectAllRecommendedUpdates() ;

	/**
	 * @brief 現在のscan sessionにある全候補の選択を解除する。
	 * 全candidateの選択を解除する。
	 * ScanReadyの間だけ、表示状態にかかわらず現在scan sessionの全candidate selectionを解除してTreeTableへ反映する。
	 */
	void					   clearCandidateSelection() ;

	/**
	 * @brief 組み込みProvider状態とlocal候補到達dialog入口をpopupへ表示する。
	 * Provider状態とlocal候補到達dialog入口を表示する。
	 * Button直下のcheck付きpopupでProvider設定を切り替え、前回scanのlocal候補到達dialogを開く。
	 */
	void					   showProviderSourcesMenu() ;

	/**
	 * @brief 区分C Providerへ渡すZIPを利用者に一件選択させる。
	 * 区分C ProviderのZIPを一件選択する。
	 * 選択pathはprocess memoryだけに保持する。取消とdialog失敗を区別し、失敗時だけ診断値を利用者へ表示する。最大path領域はstackを圧迫しないよう動的領域へ確保す
	 * る。
	 * @param[in] noticeResourceId 由来と利用許諾の確認文字列resource ID。 選択前確認文字列resource ID。
	 * @param[in] titleResourceId File dialog titleのresource ID。 Dialog titleのresource ID。
	 * @param[in] filterResourceId ZIP filter表示名のresource ID。
	 * @param[out] selectedPath 成功時に上書きする選択local path。 成功時だけ更新するlocal path。
	 * @return Fileを選択した場合は`true`、取消またはdialog失敗時は`false`。 Fileを選択した場合は`true`、取消または失敗時は`false`。
	 * @note 選択pathはprocess memoryだけに保持し、表示、永続log、networkへ渡さない。
	 */
	[[nodiscard]] bool		   selectUserPackage( UINT noticeResourceId, UINT titleResourceId,
												 UINT filterResourceId, std::wstring &selectedPath) ;

	/**
	 * @brief 未計測、確定値、下限値、取得不能を色に依存しない文字列へ変換する。
	 * @param[in] measurement 表示する件数と確定度。
	 * @return Resource文字列だけを使った日本語表示値。
	 */
	[[nodiscard]] std::wstring formatMeasurementCount( const CountMeasurement &measurement) const ;

	/**
	 * @brief T／Q／R／A／Iの五段階を固定順の表示文字列へ変換する。
	 * @param[in] measurement 同じ母数に対する段階別device件数。
	 * @return 各件数の確定度を保持したresource format文字列。
	 */
	[[nodiscard]] std::wstring formatStageMeasurement( const StageDeviceCounts &measurement) const ;

	/**
	 * @brief 公式HTTP resourceの実取得経路を種類別件数へ要約する。
	 * @param[in] resources URLを含まない固定source取得根拠。
	 * @return Network本文、fresh cache、304再検証、不明のresource件数。
	 */
	[[nodiscard]] std::wstring formatMeasurementAcquisitions(
		std::span<const MeasurementResource> resources) const ;

	/**
	 * @brief 前回scanのmanufacturer／setup class別候補到達件数を表示する。
	 * 前回scanのmanufacturer／class別候補到達件数を表示する。
	 * S63+未列挙groupを先に並べ、端末内だけに保持した集計値を標準Task Dialogへ表示する。Review状態や候補0件を最新、対応済み、または適用可能とは表示しない。
	 */
	void					   showLocalCoverageDialog() const ;

	/** @brief 確定した索引通信結果を操作中以外に閲覧できるか判定します。
	 * @return 受理済みrefreshがあり、現在の操作が終端ならtrueです。
	 */
	[[nodiscard]] bool		   canShowIndexRefreshDetails() const noexcept ;
	/** @brief 取得元menuへ非機密な通信結果の独立入口を追加します。
	 * @param[in] menu 呼出し中に借用する有効なpopup menuです。所有権を取得しません。
	 */
	void					   appendIndexRefreshMenu( HMENU menu) const ;
	/** @brief 受理済みsummaryを既存のread-only詳細dialogへ表示します。
	 * @note UI thread限定です。取得計画・進捗・導入権限を変更しません。
	 */
	void					   showIndexRefreshDetails() const ;

	/**
	 * @brief UIで有効にしたProvider IDと利用者指定fileから次回scan設定を作る。
	 * 次回scanへ渡すProviderと利用者指定file設定を作る。
	 * 全無効を既定値と誤解せず、利用者選択pathは対応Providerだけへ渡す明示設定を作る。
	 * @return 未知IDを含まず、区分C Providerと一件のfileを対応付けた明示設定。 UIで有効にしたstable Provider IDと区分C fileの対応。
	 */
	[[nodiscard]] ScanOptions  currentScanOptions() const ;

	/**
	 * @brief Provider取得元buttonへ有効数を表示する。
	 * Provider取得元buttonへ現在の有効数を表示する。
	 * Popupを開かなくても有効Provider数を確認できるようにする。
	 */
	void					   updateProviderSourcesCaption() const ;

	/**
	 * @brief Providerの前回scan状態をresource文字列へ変換する。
	 * Provider scan状態を短い表示文字列へ変換する。
	 * 候補有無、対象外、一般失敗、監査段階別拒否を区別する。
	 * @param[in] state 表示対象のProvider状態。 表示する取得元別scan状態。
	 * @return Popup menuへ付加する短い日本語状態。 Popup menuへ付加するresource文字列。
	 */
	[[nodiscard]] std::wstring providerStateText( ProviderScanState state) const ;

	/**
	 * @brief 新しい WUA scan を開始する。
	 * 選択した取得元による新しいscanを開始する。
	 * UIのProvider選択を固定した新しいscan sessionを開始する。
	 */
	void					   beginScan() ;

	/** @brief 通常scanの開始または同operationの協調取消しを要求する。 */
	void					   handleScanCommand() ;
	/** @brief 通常scanを取消し待ちへ移し、確定進捗とWindowを維持する。 */
	void					   cancelScan() ;

	/**
	 * @brief Registryから初期選択空の情報検索条件dialogを作る。
	 * @param[out] request 開始を明示承認した場合だけ更新する今回の要求。
	 * @return 専用能力と非空集合を再検証して承認した場合true。
	 */
	[[nodiscard]] bool		   showMetadataSearchDialog( MetadataSearchRequest &request) ;

	/** @brief 情報検索の条件確認または同operationの協調取消しを要求する。 */
	void					   handleMetadataSearchCommand() ;
	/** @brief 同operationの取消し待ちへ移し、確定進捗を維持する。 */
	void					   cancelMetadataSearch() ;
	/** @brief 表示専用の終端packetを検証して保持する。@param[in] event Workerの所有結果。 */
	void					   processMetadataSearchCompleted( const WorkerEvent &event) ;
	/** @brief 検索用途に応じて配布版と現在INF版を区別した見出しへ更新する。 */
	void					   updateMetadataSearchColumns() ;
	/** @brief 情報検索の停止理由と未測定を表示する。 */
	void					   updateMetadataSearchStatus() ;
	/** @brief 情報検索の条件と全Providerの停止理由を標準controlで表示する。 */
	void					   showMetadataSearchDetails() const ;
	/** @brief 固定理由をresourceへ変換する。@param[in] reason 検証済み停止理由。@return 日本語の理由。 */
	[[nodiscard]] std::wstring metadataSearchReasonText( MetadataSearchReason reason) const ;

	/**
	 * @brief 情報検索の標準listviewと今回限りの通信判断を処理する。
	 * @param[in] dialog 同期dialogの非所有handle。
	 * @param[in] message Windows message ID。
	 * @param[in] wordParameter Control ID等のmessage値。
	 * @param[in] longParameter 初期化時の借用snapshotまたは通知buffer。
	 * @return 処理済みならTRUE。例外・表示不整合は取消しで終端する。
	 */
	static INT_PTR CALLBACK	   metadataSearchDialogProc( HWND dialog, UINT message,
														WPARAM wordParameter,
														LPARAM longParameter) noexcept ;

	/**
	 * @brief checked candidate を確認して download/install を開始する。
	 * Provider registryから注意種別を検証し、device、現在版から候補版への操作、取得元、およびOS別の復旧条件を表示する。不明なProvider、操作、Server条件で
	 * はworkerを呼ばない。
	 */
	void					   beginInstall() ;

	/**
	 * @brief EULA全文の標準dialog messageを処理する。例外を境界外へ漏らさない。
	 * 初期化時に全文とrevisionをcopyし、HTMLや外部linkを実行しない。本文の切詰めを許さない。取得前提の確認が必要な対象では未確認の同意を拒否する。
	 * @param[in] dialog 本callback中の非所有dialog handle。 Windowsが所有する同期dialog handle。
	 * @param[in] message Windows message ID。
	 * @param[in] wordParameter Button ID等のmessage値。
	 * @param[in] longParameter 初期化時だけ有効な非所有対象pointer。 初期化時だけの非所有対象pointer。
	 * @return Messageを処理した場合TRUE。初期focus指定時はFALSE。 処理済みの場合TRUE。初期focusを指定した場合FALSE。
	 */
	static INT_PTR CALLBACK	   preparationEulaDialogProc( HWND dialog, UINT message,
														 WPARAM wordParameter,
														 LPARAM longParameter) noexcept ;

	/**
	 * @brief 対象のEULA全文とrevisionを表示して今回だけの同意を確認する。
	 * 同期dialogの寿命中だけsnapshotを参照する。拒否は他対象への拒否へ拡大しない。
	 * @param[in] target 本文とrevisionを固定した当該対象。 今回同意を求める対象の固定本文とrevision。
	 * @return 明示同意した場合true。拒否・取消し・表示失敗はfalse。 全文表示後に同意を明示した場合true。
	 */
	[[nodiscard]] bool confirmPreparationEula( const OfficialPreparationTarget &target) const ;

	/**
	 * @brief 取得中は協調取消しだけを送り、未使用計画があれば確認し、消費後は結果だけを表示する。
	 */
	void			   handlePreparationCommand() ;

	/**
	 * @brief 個別取得条件を確認し、承認された対象だけをworkerへ送る。
	 * 確認の最後まで通信しない。EULA本文未提示対象を選択不可とし、全承認をworkerへ渡す。
	 */
	void			   beginPreparationReview() ;

	/**
	 * @brief URLを含まない取得対象の表示を構築する。
	 * Provider名称は既存registryを正本とし、device数を適用性合格数として表示しない。
	 * @param[in] target 表示する固定対象snapshot。
	 * @param[in] index 0始まりの対象番号。 計画内の0始まり対象番号。
	 * @return Provider、配布参照、上限、条件を含む表示。 URLを含まない対象明細。
	 */
	[[nodiscard]] std::wstring formatPreparationTarget( const OfficialPreparationTarget &target,
													   std::size_t index) const ;

	/**
	 * @brief 取得確認用の標準dialogを表示する。
	 * 既定は取得拒否で、network checkboxは未選択。Dialog失敗時の自動承認は行わない。
	 * @param[in] content Dialogの要約。
	 * @param[in] details 対象明細。 固定対象の明細。
	 * @param[in] select trueは一対象の取得可否確認、falseは閲覧のみ。
	 * @param[out] network 今回だけの課金／不明network承認。閲覧時と拒否時はfalse。 当該対象への明示network承認。拒否と閲覧はfalse。
	 * @return Button ID。表示失敗はIDCANCELとして通信を開始しない。 選択button ID。表示失敗はIDCANCEL。
	 */
	[[nodiscard]] int		   showPreparationDialog( const std::wstring &content,
													 const std::wstring &details, bool select,
													 bool &network) const ;

	/**
	 * @brief 取得対象の確定件数を下部progressへ反映する。
	 * 件数に整合する単調な進捗だけを表示し、時間経過による推定率を使わない。
	 * @param[in] event 現在操作の取得進捗。 workerが確定した取得件数。
	 */
	void					   processPreparationProgress( const WorkerEvent &event) ;

	/**
	 * @brief 取得結果を検証し、対象別に表示して元の一覧を保持する。
	 * 既存行の監査を更新し、全監査合格候補を未選択で追加する。現在版と既存選択を保ち、自動scanしない。
	 * @param[in] result workerの取得完了内容。 非機密の取得結果と独立した監査report。
	 * @param[in] indexSummary 同operation／scan／planの有限な索引内容結果。空では索引未実施です。
	 * @note 元承認・確定transfer・通常内容上限と矛盾する索引summaryは全拒否し、未確認理由を表示します。
	 */
	void processPreparationCompleted( const OfficialPreparationOperationResult &result,
									 const IndexPreparationSummary			  &indexSummary = {}) ;

	/**
	 * @brief worker result queue を到着順に処理する。
	 */
	void processWorkerEvents() ;

	/**
	 * @brief 現在operationの一通知を種別ごとの検証へ渡します。
	 * @param[in] event 同期呼出し中だけ借用するworker通知。
	 * @note 製品queueと内部friendが同じ私有dispatchを使用します。古い通知は表示を変更しません。
	 */
	void processWorkerEvent( const WorkerEvent &event) ;

	/**
	 * @brief Provider進捗eventを状態機械と決定型progress表示へ反映する。
	 * 現在operationの段階遷移を検証し、件数と全体完了率を表示する。
	 * @param[in] event Provider workerから受け取った進捗event。
	 */
	void processOperationProgress( const WorkerEvent &event) ;

	/**
	 * @brief scan 完了 event を UI と状態機械へ反映する。
	 * @param[in] event Provider worker から受け取った event。
	 */
	void processScanCompleted( const WorkerEvent &event) ;

	/**
	 * @brief install 完了 event を UI と状態機械へ反映する。
	 * @param[in] event Provider worker から受け取った event。
	 */
	void processInstallCompleted( const WorkerEvent &event) ;

	/**
	 * @brief Providerの推奨順から一device一候補の初期selectionを作成する。
	 * Providerが明示した検証根拠から推奨通常更新を一device一件選択する。矛盾した候補はfail-closedで全て未選択にする。
	 */
	void initializeCandidateSelection() ;

	/**
	 * @brief 保持しているcandidate selectionを表示中TreeTableへ反映する。
	 * 保持selectionを表示中TreeTableへ反映する。
	 * Filterで表示中のinstall可能候補へ保持selectionを反映する。現在版等の表示専用候補からstate imageを除き、操作対象と誤認されないようにする。
	 */
	void applyCandidateSelectionToTree() noexcept ;

	/**
	 * @brief scan candidateを種類・device・driverの三階層TreeTableへ表示する。
	 * Filter有効時はinstall可能なrecommended候補だけを表示し、非表示候補のselectionは保持する。
	 * 全種類とdeviceを初期折畳みにし、現在行優先の名前・分類と表示中device単位の件数を示す。
	 * @param[in] candidates 表示する immutable candidate 群。
	 */
	void populateCandidates( std::span<const UpdateCandidate> candidates) ;

	/**
	 * @brief install resultをTreeTableへ表示し、失効した候補を表示専用へ変更する。
	 * install result を対応するTreeTable子行の結果columnへ表示する。
	 * install resultを対応するTreeTable子行の結果columnへ表示し、失効したscan sessionの全候補を表示専用へ変更する。
	 * @param[in] result Provider が返した update ごとの結果。
	 */
	void displayInstallResult( const InstallResult &result) ;

	/**
	 * @brief TreeView の一つの driver 候補が checked になった際の radio selection を反映する。
	 * TreeViewのcheck状態を永続selectionへ反映する。Checked時は非表示候補を含む同一deviceの他候補を解除する。
	 * @param[in] item 状態が変化した child item。
	 * @param[in] checked 新しい check state。
	 */
	void handleTreeCheckChange( HTREEITEM item, bool checked) ;

	/**
	 * @brief TreeView item parameterから検証済みの表示行を取得する。
	 * @param[in] parameter itemへ格納した1始まりのrow index。
	 * @return 有効な場合はTreeRowへの非所有pointer、それ以外は`nullptr`。
	 */
	[[nodiscard]] const TreeRow *treeRowFromParameter( LPARAM parameter) const noexcept ;

	/**
	 * @brief accessibility用にcandidateの全metadataを一行のitem textへ整形する。
	 * @param[in] candidate 表示対象。
	 * @return 制御文字を除いた表示文字列。
	 */
	[[nodiscard]] std::wstring	 formatCandidateText( const UpdateCandidate &candidate) const ;

	/**
	 * @brief Candidateの公式探索経路区分を表示文字列へ変換する。
	 * 探索方法だけを示し、安全性または適用性の格付けにはしない。
	 * @param[in] candidate 表示対象。
	 * @return 公式区分A～Cのresource文字列。WUA／localの場合は空文字列。
	 */
	[[nodiscard]] std::wstring	 formatCandidateDiscoveryBasis(
		  const UpdateCandidate &candidate) const ;

	/**
	 * @brief 一つの監査gate状態を段階別のresource文字列へ変換する。
	 * 一つの候補監査gateを表示文字列へ変換する。
	 * Windows委譲、Provider照合、利用者指定を独立状態として保ち、DriverCrateによる合格へ読み替えない。
	 * @param[in] state 表示対象の監査gate状態。
	 * @param[in] passedResourceId 当該gateの合格表示resource ID。
	 * @param[in] pendingResourceId 当該gateの未完了表示resource ID。
	 * @return 監査結果を過大評価しない短い日本語文字列。 監査結果を過大評価しないresource文字列。
	 */
	[[nodiscard]] std::wstring formatCandidateAuditGate( CandidateAuditGateState state,
														UINT					passedResourceId,
														UINT pendingResourceId) const ;

	/**
	 * @brief Candidateの監査gateとinstall準備状態を一列の表示値へ変換する。
	 * Candidate監査状態とinstall準備状態を整形する。
	 * Scan時点のimmutableな監査事実を一列へ段階名付きで表示し、operation結果列とは混在させない。
	 * @param[in] candidate 表示対象。
	 * @return 由来、download、内容、system、installの独立状態。 由来、取得、内容、system、installの独立状態。
	 */
	[[nodiscard]] std::wstring formatCandidateAudit( const UpdateCandidate &candidate) const ;

	/**
	 * @brief candidateの操作、公式release観測差分、同一版取得元を表示文字列へ変換する。導入不可の公式配布情報は現在版と誤表示せず未監査と明示する。
	 * @param[in] candidate 表示対象。
	 * @return resourceから取得した操作分類と非機密観測差分の文字列。
	 */
	[[nodiscard]] std::wstring formatCandidateState( const UpdateCandidate &candidate) const ;
	/** @brief 索引refreshの元診断とcommit事実だけを表示本文へ変換します。
	 * @param[in] summary 同operationから受理した非機密summaryです。
	 * @return 未実行なら空、それ以外はURL/ID/pathを含まない独立本文です。
	 */
	[[nodiscard]] std::wstring formatIndexRefreshSummary( const IndexScanSummary &summary) const ;

	/**
	 * @brief 検索時点のdriver登録・問題・読取り失敗を短く表示する。
	 * @param[in] candidate 現在構成行。観測未収集を許す。
	 * @return 状態を過大評価しないresource文字列。
	 */
	[[nodiscard]] std::wstring formatDeviceObservation( const UpdateCandidate &candidate) const ;

	/**
	 * @brief 有限な観測と候補検証の全詳細をread-only表示用に整形する。
	 * @param[in] candidate 同じscanの候補。
	 * @return 固定属性・軸・理由と次の操作。生の証拠や識別子を含めない。
	 */
	[[nodiscard]] std::wstring formatCandidateDetails( const UpdateCandidate &candidate) const ;

	/**
	 * @brief 候補の方式と最初の未確認・拒否理由を一覧用に整形する。
	 * @param[in] candidate 表示する候補。
	 * @return 詳細未収集または方式と主理由。全軸は詳細画面に保持する。
	 */
	[[nodiscard]] std::wstring formatCandidateAssessment( const UpdateCandidate &candidate) const ;

	/**
	 * @brief 選択した候補行のread-only詳細を標準dialogで表示する。
	 * @return 候補行を処理した場合true。分類・device親行や処理中はfalse。
	 * @note UI thread限定。取得・導入・復旧・同意操作を行わない。
	 */
	[[nodiscard]] bool		   showSelectedCandidateDetails() const ;

	/**
	 * @brief candidateのdownload sizeまたはlocal取得状態を表示文字列へ変換する。
	 * 正確なbyte数を優先し、次に公式pageの概算表示を使用する。どちらもないlocal候補は取得済み状態を表示する。
	 * @param[in] candidate 表示対象。
	 * @param[in] unknown 欠損値へ使用する代替表示。
	 * @return TreeTableのsize columnへ表示する文字列。
	 */
	[[nodiscard]] std::wstring formatCandidateSize( const UpdateCandidate &candidate,
												   std::wstring_view	  unknown) const ;

	/**
	 * @brief TreeTableでcheckedのcandidate indexを取得する。
	 * @return candidate vector の有効 index 群。
	 */
	[[nodiscard]] std::vector<std::size_t> checkedCandidateIndexes() const ;

	/**
	 * @brief static resource 文字列を読み取る。
	 * @param[in] resourceId STRINGTABLE ID。
	 * @return 未定義時は空文字列。
	 */
	[[nodiscard]] std::wstring			   loadString( UINT resourceId) const ;

	/**
	 * @brief `%1` placeholder 一つを指定値で置換する。
	 * @param[in] resourceId format string の resource ID。
	 * @param[in] value `%1` と置換する文字列。
	 * @return format 済み文字列。
	 */
	[[nodiscard]] std::wstring		formatResource( UINT resourceId, std::wstring_view value) const ;

	/**
	 * @brief status text と決定型progressの表示状態を更新する。
	 * @param[in] text 新しい status text。
	 * @param[in] busy 長時間 operation 実行中の場合は `true`。
	 */
	void							setStatus( std::wstring_view text, bool busy) ;

	/**
	 * @brief Providerの段階、件数、および全体完了率を下部status帯へ表示する。
	 * 現在段階、完了件数、総件数、および全体百分率を表示する。
	 * @param[in] progress Providerが確定したoperation進捗値。
	 */
	void							setOperationProgress( const ProviderProgress &progress) ;

	/**
	 * @brief 実行中 operation を確認して Window を安全に閉じる。
	 */
	void							requestClose() ;

	/// Executable moduleの非所有instance handle。
	HINSTANCE						instance_{} ;
	/// 本classが所有するtop-level Window handle。
	HWND							window_{} ;
	/// 説明文を表示するstatic control handle。
	HWND							header_{} ;
	/// TreeView columnを表示するHeader control handle。
	HWND							treeHeader_{} ;
	/// Deviceとdriver候補を表示するTreeView handle。
	HWND							updateTree_{} ;
	/// Scan開始buttonのcontrol handle。
	HWND							scanButton_{} ;
	/// 選択候補のinstall開始button handle。
	HWND							installButton_{} ;
	/// 推奨更新を一括選択するbutton handle。
	HWND							selectAllButton_{} ;
	/// 全候補の選択を解除するbutton handle。
	HWND							clearSelectionButton_{} ;
	/// 取得元Provider設定popupを開くbutton handle。
	HWND							providerSourcesButton_{} ;
	/// 上部の取得準備確認／取消し／結果button。
	HWND							preparationButton_{} ;
	/// 今回だけの情報検索開始／取消しbutton。
	HWND							metadataSearchButton_{} ;
	/// 推奨更新表示filterのcheckbox handle。
	HWND							recommendedOnlyCheckbox_{} ;
	/// 件数、進捗、結果を表示するstatus control handle。
	HWND							status_{} ;
	/// OSが所有し、本classは解放しない標準UI font handle。
	HFONT							uiFont_{} ;
	/// DPIに合わせて生成し、本classが解放する上下message font。
	HFONT							messageFont_{} ;
	/// DPIに合わせて生成し、本classが解放するTreeTable font。
	HFONT							treeFont_{} ;
	/// SetupDiDestroyClassImageListで解放するWindows標準class image list。
	SP_CLASSIMAGELIST_DATA			deviceClassImages_{} ;
	/// GUID未取得時の汎用device icon index。
	int								fallbackDeviceImageIndex_{I_IMAGENONE} ;
	/// trueの場合は新規operationを拒否して終了処理中である。
	bool							closing_{} ;
	/// trueの場合はprogrammatic check変更の再入を抑止する。
	bool							updatingTreeChecks_{} ;
	/// 前回column layoutを行ったTreeTable幅（physical pixel）。
	int								treeTableWidth_{} ;
	/// 現在の0始まりsort column index。
	std::size_t						sortedColumn_{} ;
	/// trueの場合は現在のsort方向が昇順。
	bool							sortAscending_{true} ;
	/// trueの場合はsortが有効。初期値は名前昇順とし、Header clickで条件を変更する。
	bool							sortActive_{true} ;
	/// trueの場合はinstall可能な推奨更新だけを表示する。
	bool							showRecommendedOnly_{} ;
	/// trueの場合はstatus帯を全幅progressとして描画する。
	bool							statusBusy_{} ;
	/// Status帯へ描画する0～100の全体完了率。
	std::uint32_t					statusPercentage_{} ;

	/// 確認dialog中のcommand再入を拒否する。
	bool							preparationReviewOpen_{} ;
	/// 情報検索の条件dialog中のcommand再入と親Window破棄を拒否する。
	bool							metadataReviewOpen_{} ;
	/// 情報検索の終端eventまでWindowを維持してから閉じる。
	bool							closeAfterMetadataSearch_{} ;
	/// 通常scanの取消し終端eventまでWindowを維持してから閉じる。
	bool							closeAfterScan_{} ;
	/// 協調取消しの完了通知後にWindowを閉じる。
	bool							closeAfterPreparation_{} ;
	/// 結果表示用の対象snapshot。
	OfficialPreparationApproval		preparationApproval_ ;
	/// 次のscanまで端末内だけに保持する取得結果。
	std::wstring					preparationResultText_ ;
	/// 同scanの索引読取り件数。実device適合や候補数ではありません。
	IndexScanSummary				indexScanSummary_ ;
	/// 同operationで照合した非機密の取得・内容結果。新scan時に破棄します。
	IndexPreparationSummary			indexPreparationSummary_ ;
	/// 今回取得を選択した対象数。
	std::uint32_t					preparationTotal_{} ;
	/// 最後に受理した確定件数。
	std::uint32_t					preparationCompleted_{} ;
	/// UI operationの状態とidentityを検証する状態機械。
	OperationController				controller_ ;
	/// Blocking処理を所有するworker。
	std::unique_ptr<ProviderWorker> worker_ ;
	/// 最後に成功したscanの結果分類。
	OutcomeCode						scanOutcome_{OutcomeCode::NOT_STARTED} ;
	/// 現在のscan sessionで表示中の候補。
	std::vector<UpdateCandidate>	candidates_ ;
	/// 次回scanで有効にするProvider ID集合。
	std::vector<std::wstring>		enabledProviderIds_ ;
	/// 利用者が明示選択したIntel Wireless ZIP path。Process終了時またはProvider無効化時に破棄する。
	std::wstring					selectedIntelWirelessPackagePath_ ;
	/// 利用者が明示選択したProlific DCHU ZIP path。Provider無効化時に破棄する。
	std::wstring					selectedProlificSerialPackagePath_ ;
	/// 利用者が明示選択したSilicon Labs CP210x ZIP path。Provider無効化時に破棄する。
	std::wstring					selectedSiliconLabsSerialPackagePath_ ;
	/// 利用者が明示選択したWCH CH341SER ZIP path。Provider無効化時に破棄する。
	std::wstring					selectedWchSerialPackagePath_ ;
	/// 利用者が明示選択したWCH CH343SER ZIP path。Provider無効化時に破棄する。
	std::wstring					selectedWchMultiSerialPackagePath_ ;
	/// 利用者が明示選択した取得元未証明driver-only ZIP path。Provider無効化時に破棄する。
	std::wstring					selectedGenericInfPackagePath_ ;
	/// 前回scanの取得元別状態。
	std::vector<ProviderScanReport> providerReports_ ;
	/// 前回scanから端末内だけで保持するmanufacturer／setup class別候補到達件数。
	std::vector<LocalCoverageEntry> localCoverage_ ;
	/// Candidate index別に保持する利用者の選択状態。
	std::vector<bool>				candidateSelected_ ;
	/// Candidate indexに対応する非所有tree item。
	std::vector<HTREEITEM>			candidateItems_ ;
	/// Candidate indexに対応するrow index。
	std::vector<std::size_t>		candidateRowIndexes_ ;
	/// TreeView item parameterから参照する安定した表示行集合。
	std::vector<TreeRow>			treeRows_ ;
	/// TreeViewへ渡す文字列の安定領域。
	std::vector<std::wstring>		candidateDisplayTexts_ ;
} ;

} // namespace drivercrate
