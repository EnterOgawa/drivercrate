//------------------------------------------------------------------------------
/**
 * @file indexed_driver_package_inspection.h
 * @brief 索引hintと固定済みarchiveの通常共通検査を結合する。
 * @version 01.01.00
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  取得済みarchiveへの非導入結合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * </pre>
 *
 * @note Worker内だけで使用する。Hintはmetadata参照であり、索引署名、公式由来、取得許可、
 *       適合性または導入許可を保証しない。通常の内容署名policyを保守検査へ切り替えない。
 * @see docs/adr/0262-index-hint-to-acquired-package-inspection.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/common_driver_package.h"

#include <cstdint>
#include <functional>
#include <string>

namespace drivercrate {

/** @brief 呼出し側が検査した索引metadataへの参照と期待archive identity。 */
struct IndexedDriverArchiveHint {
	/// 呼出し側が保持する索引原byteの小文字SHA-256。署名認証を表さない。
	std::wstring  indexSha256 ;
	/// 索引から一意に選択したrecord正規byteの小文字SHA-256。
	std::wstring  recordSha256 ;
	/// 当該recordへ結合した元取得archiveの小文字SHA-256。
	std::wstring  archiveSha256 ;
	/// 元取得archiveの期待byte数。1～128 MiB。
	std::uint64_t archiveBytes{} ;
} ;

/** @brief 内容合格と独立した索引入力の非導入到達段階。 */
enum class IndexedDriverInspectionState {
	/// 入力を受理していない既定状態。
	NOT_STARTED,
	/// Hint・session・形式・実file identityを拒否した。
	INPUT_REJECTED,
	/// 明示取消しで部分内容結果を破棄した。
	CANCELLED,
	/// 入力結合後の全体検査が失敗した。
	INSPECTION_FAILED,
	/// 通常検査が完了した。個別INFの全拒否やINFなしを含む。
	INSPECTION_COMPLETED,
	/// 全原byteと共通Authenticode/publisherを検査した公式installerです。INF検査/導入ではありません。
	INSTALLER_INSPECTION_COMPLETED,
} ;

/** @brief 保護閉包を所有するworker専用結果。由来・適合・導入許可は含めない。 */
struct IndexedDriverPackageInspection {
	/// 入力結合または通常検査の到達段階。
	IndexedDriverInspectionState  state{IndexedDriverInspectionState::NOT_STARTED} ;
	/// 全体失敗の元HRESULT。検査完了時だけ0。
	NativeError					  error{} ;
	/// 実fileのsize・hashまでhintへ結合済みの場合true。公式由来を意味しない。
	bool						  inputBound{} ;
	/// 全体検査完了時だけ個別成功・拒否と保護閉包を所有する通常結果。
	CommonDriverPackageInspection inspection ;
} ;

/**
 * @brief 索引hintと固定済み入力の有限identityだけを非I/Oで照合する。
 * @param[in] activeScanSessionId 現在の0ではないworker scan session。
 * @param[in] hint 呼出し側が選択した期待値。全hashは小文字64桁。
 * @param[in] input 既存保護copyまたは共通取得層が固定したarchive。
 * @param[in] format ZIPまたはCABINET。実行形式の推測は行わない。
 * @return Session・hash・size・local path構文・形式が一致する場合true。
 * @note 実byte、索引本文・署名、公式取得根拠や許可の検査を代替しない。
 */
[[nodiscard]] bool		  matchesIndexedDriverArchiveHint( ScanSessionId activeScanSessionId,
														  const IndexedDriverArchiveHint &hint,
														  const DriverArchiveInput		 &input,
														  OfficialDriverArchiveFormat	  format) noexcept ;

/**
 * @brief 索引の期待値と実fileを再照合し、通常の共通内容・署名検査へ接続する。
 * @param[in] activeScanSessionId 現在のworker scan session。
 * @param[in] hint 呼出し側が選択した元取得archiveの期待identity。
 * @param[in] input 呼出し中に変更しない、既存の保護archive入力。
 * @param[in] format ZIPまたはCABINET。未対応形式は拒否する。
 * @param[out] result 全体完了時だけ通常検査結果を保持する。失敗時は段階・診断だけ。
 * @param[in] cancellation 空またはworker内の非blocking取消し照会。
 * @return 通常検査完了時0。それ以外は元HRESULT。0件内容合格も完了に含む。
 * @pre Inputの保護workspaceは全呼出し中有効であり、入力はresultとaliasしない。
 * @note Blockingする。通常policyを維持し、保守根拠・grant・Windows適合・導入へ昇格しない。
 */
[[nodiscard]] NativeError inspectIndexedDriverPackage(
	ScanSessionId activeScanSessionId, const IndexedDriverArchiveHint &hint,
	const DriverArchiveInput &input, OfficialDriverArchiveFormat format,
	IndexedDriverPackageInspection &result, const std::function<bool()> &cancellation = {}) ;

} // namespace drivercrate
