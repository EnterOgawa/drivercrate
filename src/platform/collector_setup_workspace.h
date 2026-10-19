//------------------------------------------------------------------------------
/**
 * @file collector_setup_workspace.h
 * @brief 収集setup専用の保護rootと固定runtimeによる明示操作を定義します。
 * @version 01.02.01
 * @date 2026/10/16
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/16 保護rootと非通信monitor adapter起動を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/17 root非重複とAPI診断の契約を明示。
 * Ver.01.01.00 Shunji Ogawa  2026/10/17 v5の信頼済み取得処理と明示一回操作を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/17 正式原点選択と生きたnative leaseの接続を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/17 bind済みverify／exportの原点結合契約を明記。
 * </pre>
 *
 * @note v4は非通信、v5は実原点と保持中native writerへ結合した非共有PAGEだけを扱います。
 *       共有・未知scopeはHOLDへ残し、Taskや既存ACL修復は行いません。
 * @see docs/adr/0355-collector-protected-workspace-adapter.md
 */
//------------------------------------------------------------------------------
#pragma once

#include <filesystem>
#include <functional>
#include <string_view>

namespace drivercrate {

/**
 * @brief 存在する親の直下に保護DACL付き新規rootを作成します。
 * @param[in] root 固定drive上の新規絶対path。親は既存であること。
 * @throws std::exception 不適格path、既存先、実handle／ACL検査または作成失敗。
 * @note 親や既存ACLは変更せず、部分作成は保持します。同じuserと管理者を信頼します。
 */
void			  createCollectorSetupProtectedRoot( const std::filesystem::path &root) ;

/**
 * @brief 固定payloadを新規fileへcopyし、sourceのACLを持ち込みません。
 * @param[in] source 検証済み通常fileの絶対path。
 * @param[in] target 保護root内の新規固定path。親は既存であること。
 * @throws std::exception 実handle検査、容量、読取り、CREATE_NEW、flush失敗。
 * @note コピー先は親の三principal ACLを作成時に継承し、部分fileは保持します。
 */
void			  copyCollectorSetupProtectedFile( const std::filesystem::path &source,
												  const std::filesystem::path &target) ;

/**
 * @brief 検査済み固定runtimeで明示されたmonitor操作を一回実行します。
 * @param[in] package 導入済みv4またはv5 packageの絶対path。
 * @param[in] action initialize、verify、export、import、resume、v5専用bind-origins／run-onceの固定操作。
 * @param[in] root 操作対象の保護workspace。
 * @param[in] transfer export先またはimport元snapshot。run-onceでは固定同意flag、他は空path。
 * @param[in] verifyPackage 実fileを固定した後の既存package／receipt検査。同期呼出し中だけ借用。
 * @param[in] nativeOrigin bind-originsだけの既存native原点。他の操作では空です。
 * @param[in] monitorOrigin bind-originsだけの停止済みmonitor正本。他の操作では空です。
 * @return 子終了値0、拒否2、通信不可を示す結果は標準出力へ別fieldで通知します。
 * @throws std::exception path／ACL／handle／起動／有限待機の失敗。部分stateは保持します。
 * @note 呼出し元が明示同意と停止申告を検査します。任意commandやmanifest scriptを受けません。
 *       package・root・transferの同一／祖先／子孫は作成前に拒否します。
 *       API失敗の固定stageと元codeを保持し、意味拒否へstale codeを付けません。
 *       非通信は180秒、v5一回操作は660秒です。未接続の共有native予約はHOLDへ残します。
 *       bind済みverify／exportも同じnative原点・実identity・保護anchorを要求します。
 */
[[nodiscard]] int runCollectorSetupWorkspace( const std::filesystem::path &package,
											 std::wstring_view			  action,
											 const std::filesystem::path &root,
											 const std::filesystem::path &transfer,
											 const std::function<void()> &verifyPackage,
											 const std::filesystem::path &nativeOrigin	= {},
											 const std::filesystem::path &monitorOrigin = {}) ;
} // namespace drivercrate
