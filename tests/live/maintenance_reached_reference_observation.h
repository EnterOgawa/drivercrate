//------------------------------------------------------------------------------
/**
 * @file maintenance_reached_reference_observation.h
 * @brief 同じ保守閉包の最終参照をprivacy保持で借用する研究専用契約。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/08  同scope最終参照とv2実byteを結ぶ有限研究観測を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/08  保持済み用途・作用gapの明示細分類modeを追加。
 * </pre>
 *
 * @note 一同期呼出しのstack所有者だけが使用し、名前・path・IDを保持しません。
 * 通常platform／Provider／UI／索引へ公開せず、導入能力を追加しません。
 * @see docs/adr/0315-maintenance-reached-reference-observation-boundary.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/common_driver_package.h"

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 元観測と保持済み残件細分類の固定研究mode。通常判定へ渡さない。 */
enum class ReachedReferenceMode {
	/// 元53のschemaと保存境界を保持する。
	REACHED,
	/// 新54のschemaと保存境界で独立分類を追加する。
	RESIDUAL
} ;

/** @brief 保持済みclosureだけを射影し、元成功後に確定する具体的な研究collector。 */
class ReachedReferenceCollector final {
public:
	/** @brief 一同期scopeで使用する固定研究modeを保持する。
	 * @param[in] mode 元53または新54。未知値は計測拒否とする。
	 */
	explicit ReachedReferenceCollector(
		ReachedReferenceMode mode = ReachedReferenceMode::REACHED) noexcept ;
	/** @brief 同scopeの最終closureと通常rowを同期借用する。
	 * @param[in] closure 再照会しない保持済み結果。空は元抽出失敗の未観測。
	 * @param[in] row 同じINFの通常射影。原状態とHRESULTを変更しない。
	 * @param[in] ordinal Archive順の0起点root連番。
	 * @note 容量・整合・例外は独立計測失敗として保持し、元判定へ返さない。
	 */
	void append( const MaintenanceDriverClosure &closure, const MaintenanceInfInspection &row,
				std::size_t ordinal) noexcept ;
	/** @brief 元全体判定の成功後だけ仮観測を確定する。
	 * @param[in] inspection 取消し・累積量・最終byte再照合を完了した元結果。
	 * @note 元失敗では部分観測を破棄する。
	 */
	void finish( const MaintenanceDriverPackageInspection &inspection) noexcept ;
	/** @brief 独立計測の元診断を返す。
	 * @return 計測正常0、それ以外は保持したHRESULT。
	 */
	[[nodiscard]] NativeError				 error() const noexcept ;
	/** @brief 計測失敗と元全体失敗で部分観測がないことを確認する。
	 * @return 仮保持中または確定済みroot数。
	 */
	[[nodiscard]] std::size_t				 rootCount() const noexcept ;
	/** @brief 確定済み観測と送信するv2全byteを有限sidecarへ結ぶ。
	 * @param[in] runId 1～64文字の有限ASCII識別子。
	 * @param[in] inspection 元全体成功の同じ通常結果。
	 * @param[in] stdoutBytes CRLFを含む実際に送信するUTF-8全byte。
	 * @return 全整合と1 MiB上限を満たすJSON、計測・整合失敗なら空。
	 */
	[[nodiscard]] std::optional<std::string> serialize(
		std::string_view runId, const MaintenanceDriverPackageInspection &inspection,
		std::string_view stdoutBytes) const noexcept ;

private:
	/// 構築後に変えない研究専用mode。
	ReachedReferenceMode	  mode_ ;
	/// 固定語・hash・数だけで構築した各root。原名前は保持しない。
	std::vector<std::string>  roots_ ;
	/// 各rootの元INF hash。空は元未解析。
	std::vector<std::wstring> hashes_ ;
	/// Append前に確認する射影全体のbyte使用量。
	std::size_t				  bytes_{} ;
	/// 独立計測失敗の最初のHRESULT。
	NativeError				  error_{} ;
	/// 元全体成功後だけtrue。
	bool					  committed_{} ;
} ;

/** @brief 研究専用compile内だけで元loopとstack collectorを接続する。
 * @param[in] input 固定済み元archive。
 * @param[in] format ZIPまたはCAB。
 * @param[out] inspection 既存通常row。元失敗では空。
 * @param[in,out] collector この同期呼出しだけの未使用所有者。
 * @param[in] cancellation 既存と同じ取消し契約。
 * @return 元判定のHRESULT。独立計測失敗はcollector.errorに分離する。
 */
[[nodiscard]] NativeError inspectReachedMaintenanceDriverPackage(
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	MaintenanceDriverPackageInspection &inspection, ReachedReferenceCollector &collector,
	const std::function<bool()> &cancellation = {}) ;

/** @brief 固定研究modeの正確な絶対pathへCREATE_NEWで全byteを保存する。
 * @param[in] path modeごとのworkspaceとstem／run IDが完全一致する出力先。
 * @param[in] runId 1～64文字の有限ASCII識別子。
 * @param[in] bytes 全serialization成功済みの1～1 MiB byte列。
 * @param[in] mode 元53または新54。未知値はopen前に拒否する。
 * @return 保存成功0、既存file・逸脱・reparse・書込失敗のHRESULT。
 * @note 親handleを保持して付替えを拒否する。部分fileを削除・再送しない。
 */
[[nodiscard]] NativeError writeReachedReferenceSidecar(
	std::wstring_view path, std::string_view runId, std::string_view bytes,
	ReachedReferenceMode mode = ReachedReferenceMode::REACHED) noexcept ;

/** @brief 同じ実byteをCRT変換なしで標準出力へ送る。
 * @param[in] bytes Hash済みCRLF付きの1～256 KiB byte列。
 * @return 全送信0、それ以外は元HRESULT。
 */
[[nodiscard]] NativeError writeReachedReferenceStdout( std::string_view bytes) noexcept ;

} // namespace drivercrate
