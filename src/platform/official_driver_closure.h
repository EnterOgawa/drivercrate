//------------------------------------------------------------------------------
/**
 * @file official_driver_closure.h
 * @brief 公式archiveの選択的driver閉包抽出定義。
 * @version 01.03.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  由来を持たない共通archive入力を分離。
 * Ver.01.02.00 Shunji Ogawa  2026/10/05  保守専用の非実行内容閉包を導入閉包と分離。
 * Ver.01.03.00 Shunji Ogawa  2026/10/07  一rootの保守構造・有限依存と全参照の独立状態を追加。
 * </pre>
 *
 * @note G11-Bで固定した公式ZIP／CABから、選択INF、CATおよびINFが参照するfileだけを保護workspaceへ分離し、任意codeは実行しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include "platform/official_acquisition.h"
#include "platform/official_cab.h"
#include "platform/official_driver_package.h"
#include "platform/inf_dependency_native.h"
#include "platform/official_zip.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief 内容検査だけに使う固定済みarchiveのworker内入力である。
 * @note 公式由来、署名、適合性、導入許可を表さない。Pathは所有workspaceの存続中だけ有効。
 */
struct DriverArchiveInput {
	/// 入力を固定した0ではないscan session。
	ScanSessionId scanSessionId{} ;
	/// 呼出し側の保護workspaceが所有する通常file絶対path。
	std::wstring  inspectionPath ;
	/// 固定した入力の実byte数。
	std::uint64_t byteCount{} ;
	/// 固定した入力の64桁SHA-256。同一性だけを表す。
	std::wstring  sha256 ;
} ;

/**
 * @brief 選択的driver閉包が受理するarchive形式を表す。
 */
enum class OfficialDriverArchiveFormat {
	/// Minizで静的解析するZIP。
	ZIP,
	/// SetupAPIで静的列挙する単一CAB。
	CABINET,
} ;

/**
 * @brief 選択的driver閉包抽出の有限上限とINF検証条件を表す。
 */
struct OfficialDriverClosurePolicy {
	/// ZIPの入力と展開量上限。
	OfficialZipExtractionPolicy zipPolicy ;
	/// CABの入力と展開量上限。
	OfficialCabExtractionPolicy cabPolicy ;
	/// 選択INFの構造、class、Provider条件。
	OfficialInfInspectionPolicy infPolicy ;
	/// 一つの閉包に同時選択できるINF数上限。
	std::size_t					maximumInfCount ;
	/// 選択INF閉包に含める一意file数上限。
	std::size_t					maximumClosureFiles ;
	/// 選択INF閉包の展開後合計byte数上限。
	std::uint64_t				maximumClosureBytes ;
	/// Archive入力sizeに対する展開後合計の倍率上限。
	std::uint32_t				maximumExpansionRatio ;
	/// 0または1の許可archive入れ子深度。
	std::uint32_t				maximumNestedArchiveDepth ;
} ;

/** @brief 公式由来の証拠と独立したarchive一覧化要求である。 */
struct DriverArchiveInventoryRequest {
	/// 呼出し中有効な内容検査入力。Nullを拒否する。
	const DriverArchiveInput   *input{} ;
	/// 実行せず解析する外側形式。
	OfficialDriverArchiveFormat archiveFormat{OfficialDriverArchiveFormat::ZIP} ;
	/// 空またはinventoryで確認した一段nested archive相対path。
	std::wstring_view			nestedArchivePath ;
} ;

/** @brief 由来を変更せず選択INFの内容閉包を作る要求である。 */
struct DriverClosureRequest {
	/// 呼出し中有効な内容検査入力。Nullを拒否する。
	const DriverArchiveInput		  *input{} ;
	/// 実行せず解析する外側形式。
	OfficialDriverArchiveFormat		   archiveFormat{OfficialDriverArchiveFormat::ZIP} ;
	/// 空またはinventoryで確認した一段nested archive相対path。
	std::wstring_view				   nestedArchivePath ;
	/// 有限inventoryから選択したINF相対path群。
	std::span<const std::wstring_view> selectedInfPaths ;
	/// 出力保護workspaceのASCII識別子。
	std::wstring_view				   workspaceTag ;
} ;

/**
 * @brief G11-B取得fileと選択INFを閉包抽出へ渡す入力を表す。
 *
 * @note Path、SHA-256とINF名はworker内だけで保持し、UIまたはlogへ渡さない。
 */
struct OfficialDriverClosureRequest {
	/// 本呼出し中有効なG11-B `ACQUIRED_FOR_INSPECTION`結果への非所有pointer。
	const OfficialAcquisitionResult	  *acquisition{} ;
	/// 外側形式。
	OfficialDriverArchiveFormat		   archiveFormat{OfficialDriverArchiveFormat::ZIP} ;
	/// 空または外側archive内の一段nested ZIP／CAB。
	std::wstring_view				   nestedArchivePath ;
	/// 検査対象archive内の選択INF。
	std::span<const std::wstring_view> selectedInfPaths ;
	/// 出力保護workspaceのASCII識別子。
	std::wstring_view				   workspaceTag ;
} ;

/**
 * @brief G11-B取得fileの全通常fileを展開せず一覧化する入力を表す。
 *
 * @note 一段nested archiveを指定する場合も外側と内側の全entryを有限検証する。
 */
struct OfficialDriverArchiveInventoryRequest {
	/// 本呼出し中有効なG11-B `ACQUIRED_FOR_INSPECTION`結果への非所有pointer。
	const OfficialAcquisitionResult *acquisition{} ;
	/// 外側形式。
	OfficialDriverArchiveFormat		 archiveFormat{OfficialDriverArchiveFormat::ZIP} ;
	/// 空または外側archive内の一段nested ZIP／CAB。
	std::wstring_view				 nestedArchivePath ;
} ;

/**
 * @brief 取得identityと有限上限を検証したarchiveの通常file一覧を表す。
 *
 * @note SHA-256はfileを展開しないため空であり、候補または内容監査合格を意味しない。
 */
struct OfficialDriverArchiveInventory {
	/// 検査対象archiveの全通常file。
	std::vector<OfficialZipEntry> entries ;
	/// 0は外側直下、1は一段nested archive。
	std::uint32_t				  archiveDepth{} ;
} ;

/**
 * @brief 選択INFから確定したdriver閉包と静的構造を表す。
 *
 * @note 本結果はPnP適用性、rank、署名またはinstall可能を意味しない。
 */
struct OfficialDriverClosure {
	/// INF、CAT、参照fileだけの検証済み一覧。
	std::vector<OfficialZipEntry>	entries ;
	/// 各選択INFの静的構造。
	std::vector<OfficialInfPackage> packages ;
	/// 0は外側直下、1は一段nested archive。
	std::uint32_t					archiveDepth{} ;
	/// 閉包entryの展開後合計byte数。
	std::uint64_t					expandedBytes{} ;
} ;

/** @brief 導入作用を許可しない保守専用の内容閉包。導入用型へ暗黙変換しない。 */
struct MaintenanceDriverClosure {
	/// 固定したpackage側の内容。未解決用途はreferencesへ残し、全閉包成功を意味しない。
	OfficialDriverClosure				  content ;
	/// 一rootの全現在OS選択と個別構造診断。worker内だけに保持する。
	MaintenanceInfStructure				  structure ;
	/// rootと到達package INFの有限file用途・位置観測。
	std::vector<MaintenanceInfReferences> references ;
	/// 同じ一runの依存graph・独立署名診断とSYSTEM用途観測。全payload署名ではない。
	InfDependencyNativeResult			  dependency ;
	/// rootと到達参照の全署名。未解決ではNOT_CHECKED、既知FAILEDは保持する。
	MaintenanceInspectionFinding		  integrity ;
} ;

/**
 * @brief 導入作用を実行せず、保守検証だけに使う内容閉包を抽出する。
 * @param[in] request 元hashへ固定したarchiveと一root INF選択。複数rootは今回未対応。
 * @param[in] policy 内容構文と参照・展開量の条件。導入作用を拒否する条件は別検査する。
 * @param[in,out] workspace 未初期化領域。生成物をscope終了まで単独所有する。
 * @param[out] closure 成功時の保守用内容。失敗時は空。
 * @return 有限観測と元identity再確認成功0。用途未対応・依存未解決も結果へ残す。全体失敗はHRESULT。
 * @note Blockingする。抽出成功は全参照・全署名の合格ではなく、通常導入の条件を変更しない。
 * @see docs/adr/0258-maintenance-package-verdict-separation.md
 */
[[nodiscard]] NativeError extractMaintenanceDriverClosure( const DriverClosureRequest &request,
														  const OfficialDriverClosurePolicy &policy,
														  OfficialDownloadWorkspace &workspace,
														  MaintenanceDriverClosure	&closure) ;

/**
 * @brief 固定したarchiveを由来判定なしで有限一覧化する。
 * @param[in] request 保護fileの固定identityと解析対象。
 * @param[in] policy Archive、展開倍率、nested深度の有限上限。
 * @param[out] inventory 成功時の一覧。失敗時は空。
 * @return 全entryと解析前後のsize／hashが一致した場合0、それ以外はHRESULT。
 * @note Worker内でblockingする。結果は内容一覧だけで公式取得の証拠にならない。
 */
[[nodiscard]] NativeError inspectDriverArchiveInventory(
	const DriverArchiveInventoryRequest &request, const OfficialDriverClosurePolicy &policy,
	OfficialDriverArchiveInventory &inventory) ;

/**
 * @brief 固定したarchiveから選択INFの内容閉包を非実行抽出する。
 * @param[in] request 保護fileの固定identityと選択INF群。
 * @param[in] policy Archive、INF、閉包の有限上限。
 * @param[in,out] workspace 未初期化の出力領域。生成fileをscope終了まで所有する。
 * @param[out] closure 全成功時だけ閉包を保持し、失敗時は空。
 * @return 静的検査と解析前後のsize／hash一致時0、それ以外はHRESULT。
 * @note Worker内でblockingする。署名、由来、PnP、導入許可は別の検証を必要とする。
 */
[[nodiscard]] NativeError extractDriverClosure( const DriverClosureRequest		 &request,
											   const OfficialDriverClosurePolicy &policy,
											   OfficialDownloadWorkspace		 &workspace,
											   OfficialDriverClosure			 &closure) ;

/**
 * @brief G11-B取得済みZIP／CABの全通常fileを展開せず一覧化する。
 * 取得済み公式archiveの全通常fileを一覧化する。
 * 外側および任意の一段nested archiveを実行せず一覧化し、解析前後のsizeとSHA-256差替えを拒否する。
 * @param[in] request G11-B取得結果、archive形式および任意の一段nested選択。 G11-B取得結果、形式と一段nested選択。
 * @param[in] policy Archiveと展開倍率の有限上限。一段nestedの許可も含む。 Archive、展開倍率、nested深度の有限上限。
 * @param[out] inventory 成功時の全通常file一覧とarchive深度。 成功時の全通常file一覧と深度。
 * @return 一覧化成功時は0、identity差替え、構造または有限上限違反時はHRESULT。 全entryと取得identityの検証成功時は0。
 * @note 処理はblockingのためProvider worker threadで実行し、任意codeを起動しない。
 */
[[nodiscard]] NativeError inspectOfficialDriverArchiveInventory(
	const OfficialDriverArchiveInventoryRequest &request, const OfficialDriverClosurePolicy &policy,
	OfficialDriverArchiveInventory &inventory) ;

/**
 * @brief 取得済み公式ZIP／CABから選択INFのdriver閉包だけを抽出する。
 * 取得済み公式archiveから選択INFのdriver閉包を抽出する。
 * INFだけを先行展開し、CATと参照fileの閉包確定後に追加展開する。
 * @param[in] request G11-B取得結果、一段nested選択、INF選択と出力識別子。 G11-B取得結果、nested archiveとINF選択。
 * @param[in] policy Archive、INF、閉包の有限上限と許可値。
 * @param[in,out] workspace 成功閉包を所有する未初期化の保護workspace。 成功閉包を所有する保護領域。
 * @param[out] closure 全検証成功時の選択file、INF構造、合計size。 全検証成功時の選択fileとINF構造。
 * @return 閉包の選択展開成功時は0、identity差替えまたは構造違反時はHRESULT。 選択的閉包の完全な抽出とidentity再検証成功時は0。
 * @note 処理はblockingのためProvider worker threadで実行し、任意codeを起動しない。
 */
[[nodiscard]] NativeError extractOfficialDriverClosure( const OfficialDriverClosureRequest &request,
													   const OfficialDriverClosurePolicy  &policy,
													   OfficialDownloadWorkspace &workspace,
													   OfficialDriverClosure	 &closure) ;

} // namespace drivercrate
