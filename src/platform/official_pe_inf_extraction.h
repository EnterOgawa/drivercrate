//------------------------------------------------------------------------------
/**
 * @file official_pe_inf_extraction.h
 * @brief PE内の検証済みINFと署名補助CAT原範囲を非実行で抽出する定義。
 * @version 01.01.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  全表検査と全INFの原範囲抽出を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  旧INF-onlyを維持するCAT補助抽出APIを追加。
 * </pre>
 *
 * @note 構造・byte結合だけを扱い、公式由来・署名・導入許可を発行しない。
 * @see docs/adr/0275-sealed-pe-inf-range-binding.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/maintenance_embedded_file_table.h"
#include "platform/official_zip.h"

#include <cstddef>
#include <span>
#include <vector>

namespace drivercrate {
class OfficialDownloadWorkspace ;
/**
 * @brief 唯一のPE flat-table全体を検査し、全INF原byteだけを保護領域へ複写する。
 * @param[in] executable 本呼出し中に不変の全PE byte。最大64 MiB。
 * @param[in,out] workspace 初期化済み空の保護領域。新fileは同領域の追跡に残る。
 * @param[out] entries 全成功時だけ原名・実size・原byte SHA-256を保持する全INF。
 * @param[out] table 全成功時だけ元PE内の全member原範囲を保持する。認証能力はない。
 * @return 全抽出0、形式・危険項目・容量・byte差・API・例外のHRESULT。
 * @pre 全入力storageは出力とaliasしない。同期workerで使用する。
 * @post 失敗時はentriesとtableを空にする。部分fileはworkspaceの追跡に従い回収する。
 * @note Parserの原規則を緩和しない。CAT／SYS／DLL／EXEを展開・実行しない。
 * 取得証拠や生存sessionを扱わず、単独成功を公式由来にしない。
 */
[[nodiscard]] NativeError extractPeTableInfFiles( std::span<const std::byte>		executable,
												 OfficialDownloadWorkspace	   &workspace,
												 std::vector<OfficialZipEntry> &entries,
												 MaintenanceEmbeddedFileTable  &table) ;
/**
 * @brief 唯一のPE表から全INFと署名補助CATだけを同じ原範囲で抽出する。
 * @param[in] executable 呼出し中に不変の全PE byte。最大64 MiB。
 * @param[in,out] workspace 初期化済み空の保護領域。部分fileも追跡する。
 * @param[out] entries 成功時だけ全INF／CATの原名・実size・原SHA-256を保持する。
 * @param[out] table 成功時だけ元表の全範囲を保持し、認証能力を持たない。
 * @return 完了0、形式・位置・容量・byte差・API・例外のHRESULT。
 * @pre 同期worker専用。入力storageと出力はaliasしない。
 * @post 失敗時は全出力を空にし、部分fileはworkspaceで回収する。
 * @note INF64／個別1 MiB／合計16 MiB、CAT64／個別32 MiB、全metadata64 MiB。
 * SYS／DLL／EXEを抽出・実行せず、CATの存在を署名合格や公式由来にしない。
 */
[[nodiscard]] NativeError extractPeTableInfCatalogFiles( std::span<const std::byte>	   executable,
														OfficialDownloadWorkspace	  &workspace,
														std::vector<OfficialZipEntry> &entries,
														MaintenanceEmbeddedFileTable  &table) ;
} // namespace drivercrate
