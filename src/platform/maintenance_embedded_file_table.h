//------------------------------------------------------------------------------
/**
 * @file maintenance_embedded_file_table.h
 * @brief 保守専用PE内固定長ファイル表の非実行解析定義。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  保守専用の有限表解析を追加。
 * </pre>
 *
 * @note byte列を借用する純粋な構造検査です。実行・展開・署名・端末照合・導入を行いません。
 * @see docs/adr/0260-maintenance-pe-flat-file-table.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief 構造検査で得た原入力内の一file範囲を表す。 */
struct MaintenanceEmbeddedFile {
	/// ASCIIの安全なflat file名。署名や導入対象を意味しません。
	std::string name ;
	/// 原EXE内の先頭offset。呼出し後も入力identityの検証が必要です。
	std::size_t offset{} ;
	/// Paddingを除いたbyte数。DLL placeholderのみ0を許容します。
	std::size_t bytes{} ;
} ;

/** @brief 一意に検査した保守専用file表を表す。導入型との互換性はありません。 */
struct MaintenanceEmbeddedFileTable {
	/// 264 byte項目表の原EXE内offset。
	std::size_t							 tableOffset{} ;
	/// 全項目表直後の原EXE内offset。
	std::size_t							 blobOffset{} ;
	/// 各file末尾の検証済みzero paddingを含むdata長。
	std::size_t							 blobBytes{} ;
	/// 表順の安全なfile範囲。失敗時は空です。
	std::vector<MaintenanceEmbeddedFile> files ;
} ;

/**
 * @brief PE32+ x64のreadonly dataにある唯一の260名＋uint32長表を静的検査する。
 * 入力64 MiB、PE section96、file128、候補16に制限します。
 * @param[in] executable 呼出し中だけ借用する不変byte。署名検証は呼出し側の責務です。
 * @param[out] layout 全構造成功時だけ確定する原file範囲。失敗時は空です。
 * @return 成功0、不正・未対応・曖昧時は失敗HRESULT、allocation失敗時はE_OUTOFMEMORY。
 * @note Blocking I/O・実行・LoadLibraryは行いません。内容署名や導入許可を発行しません。
 */
[[nodiscard]] NativeError inspectMaintenanceEmbeddedFileTable(
	std::span<const std::byte> executable, MaintenanceEmbeddedFileTable &layout) noexcept ;

} // namespace drivercrate
