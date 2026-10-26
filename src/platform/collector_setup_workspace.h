//------------------------------------------------------------------------------
/**
 * @file collector_setup_workspace.h
 * @brief 収集setup専用の保護rootと固定runtimeによる明示操作を定義します。
 * @version 01.09.00
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/16 保護rootと非通信monitor adapter起動を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/17 root非重複とAPI診断の契約を明示。
 * Ver.01.01.00 Shunji Ogawa  2026/10/17 v5の信頼済み取得処理と明示一回操作を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/17 正式原点選択と生きたnative leaseの接続を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/17 bind済みverify／exportの原点結合契約を明記。
 * Ver.01.03.00 Shunji Ogawa  2026/10/20 単体EXEの保護stagingと固定local-index起動を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/23 新user Taskの保護metadata検査を共有。
 * Ver.01.05.00 Shunji Ogawa  2026/10/23 専用origin初期化と配布取得の保護親子操作を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/23 active data取込みと別の明示日次同意を接続。
 * Ver.01.06.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理。
 * Ver.01.06.02 Shunji Ogawa  2026/10/24 root直下Actionの親を明示protected契約へ区別。
 * Ver.01.07.00 Shunji Ogawa  2026/10/25 同schema原hashを明示reviewするpackage切替契約を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/26 一hostの原因reviewと固定原byte監査を非通信接続。
 * Ver.01.09.00 Shunji Ogawa  2026/10/26 未署名候補の非通信受渡しと原byte固定を明記。
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
#include <string>
#include <span>
#include <cstdint>

namespace drivercrate {

/**
 * @brief 三principal保護rootと祖先を固定して同期操作を行います。
 * @param[in] root 検査する既存絶対directory。
 * @param[in] operation 呼出し期間だけ借用する処理。
 * @throws std::exception 実handle、owner、DACLまたは操作失敗。
 */
void					  withCollectorSetupProtectedRoot( const std::filesystem::path &root,
														  const std::function<void()> &operation) ;

/**
 * @brief 保護child fileの実path/ACLを固定して非変更検査を行います。
 * @param[in] path 保護root直下または継承child directoryにある既存通常file。
 * @param[in] operation 同期で借用する非変更検査。
 * @param[in] protectedParent trueなら直接の親へ完全なprotected-root契約を要求します。
 * @throws std::exception 実handle、owner/DACLまたは検査失敗。
 */
void					  withCollectorSetupProtectedFile( const std::filesystem::path &path,
														  const std::function<void()> &operation,
														  bool						   protectedParent = false) ;

/**
 * @brief 継承三principalの通常fileから有限metadataを読みます。
 * @param[in] path 保護root直下の固定file。
 * @return 65536byte以下のUTF-8原byte。
 * @throws std::exception ACL、単一link、実pathまたは読取り失敗。
 */
[[nodiscard]] std::string readCollectorSetupProtectedMetadata( const std::filesystem::path &path) ;

/**
 * @brief 新規一時fileのflushと読戻し後にmetadataを原子的に保存します。
 * @param[in] path 保護root直下の固定file。
 * @param[in] bytes 65536byte以下の所有metadata。
 * @param[in] replace 既存の検査済みmetadataを置換する場合true。
 * @throws std::exception 保存、保護、flush、renameまたは読戻し失敗。部分fileを保持します。
 */
void writeCollectorSetupProtectedMetadata( const std::filesystem::path &path, std::string_view bytes,
										  bool replace) ;

/** @brief resource検査済みの借用byteとcompile時の固定相対名・hashです。 */
struct CollectorSetupEmbeddedFile {
	/// 子終了まで呼出し側が保持する固定相対名。
	std::wstring_view path ;
	/// resource実byte。呼出し期間中に変更されません。
	std::string_view  bytes ;
	/// compile時に固定された小文字SHA-256。
	std::wstring_view sha256 ;
} ;

/**
 * @brief 検査済みresourceを新規保護stagingへ保存し、固定内部setupだけを実行します。
 * @param[in] files 呼出し期間中生存する固定閉包。各64MiB、合計64MiB、128file以内。
 * @param[in] installRoot 明示新規配置先。空なら内部setupの既定先です。
 * @param[in] yes 明示された非対話同意。
 * @return 子のDWORD終了値をint32の同じbit列で保持します。成功は0だけです。
 * @throws std::exception path／ACL／hash／実handle／起動／180秒待機失敗。
 * @note 全stagingを保持します。内部検査とinstallの終了まで実fileと祖先を固定します。
 */
[[nodiscard]] std::int32_t runCollectorSetupEmbedded(
	std::span<const CollectorSetupEmbeddedFile> files, const std::filesystem::path &installRoot,
	bool yes) ;

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
 * @param[in] package 正規receiptを持つ導入済みv7 packageの絶対path。
 * @param[in] action 既存workspace操作、switch-package、review-held-host、stage-candidate、distribution-run-once、initialize-distribution-origins、import-data。
 * @param[in] root 操作対象の保護workspace。
 * @param[in] transfer export先/import元snapshot、stage-candidateの事前作成済み空directory、run-onceの固定同意flag、switch-packageの原raw SHA-256、review-held-hostのrequest。他は空path。
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
 *       switch-packageだけが事前reviewした原bindingを受け、原byteを保持して二hashをatomic切替します。
 *       切替は正規receipt/既存原点/確定停止を要求し、通信・Task・原履歴更新を行いません。
 *       review-held-hostは同じ非保存native leaseと固定三入力を保持し、Pythonの一host CAS/原監査だけへ接続します。
 *       stage-candidateは原distributionを読取り専用handleで保持し、未署名dataだけを別directoryへ受渡します。
 */
[[nodiscard]] int runCollectorSetupWorkspace( const std::filesystem::path &package,
											 std::wstring_view			  action,
											 const std::filesystem::path &root,
											 const std::filesystem::path &transfer,
											 const std::function<void()> &verifyPackage,
											 const std::filesystem::path &nativeOrigin	= {},
											 const std::filesystem::path &monitorOrigin = {}) ;
/**
 * @brief 別の明示日次同意を保護保存するか、既存同意から同じ配布callerを起動します。
 * @param[in] package 全byte検査する導入済みv7 packageです。
 * @param[in] workspace 同意登録時だけの保護workspace。dispatcherでは空です。
 * @param[in] confirmed 新しいpayload範囲/予算/日次への明示同意ならtrueです。
 * @param[in] verifyPackage 同期借用するpackage/receipt全検査です。
 * @return 登録成功0、実runでは同じpipelineの完全成功0/拒否2です。
 * @throws std::exception 保護同意、原点、実identity、固定scopeまたは検査失敗。
 * @note Task操作は行いません。登録は非通信、未同意dispatcherは子起動前に拒否します。
 */
[[nodiscard]] int runCollectorSetupDistributionDaily( const std::filesystem::path &package,
													 const std::filesystem::path &workspace,
													 bool						  confirmed,
													 const std::function<void()> &verifyPackage) ;
/**
 * @brief OS既定導入先のDriverCrate親一階層だけを新規保護作成または検査します。
 * @param[in] localAppData 製品ではOS KnownFolderから得る既存絶対directory。
 * @throws std::exception reparse、通常file、既存の不適格ACL、作成失敗。
 * @note v6の既定先・全bundle検査と同意後にだけ呼びます。既存ACLは変更せず、作成親を保持します。
 */
void			  prepareCollectorSetupDefaultParent( const std::filesystem::path &localAppData) ;
} // namespace drivercrate
