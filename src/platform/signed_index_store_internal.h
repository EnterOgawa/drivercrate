//------------------------------------------------------------------------------
/**
 * @file signed_index_store_internal.h
 * @brief 自作の隔離fixture rootだけへ保存障害診断を限定します。
 * @version 01.01.00
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  実DPAPIとdiskを使う隔離test能力を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/19  旧head不変の移動を隔離rootで検証する能力を追加。
 * </pre>
 *
 * @note 製品rootへ使えず、成功や署名を注入しません。任意pathを受理しません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/signed_index_store.h"
#include "platform/signed_index_manifest_internal.h"
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

namespace drivercrate::signed_index_store_detail {

/** @brief 自作sandbox内だけで使う固定三leafです。 */
enum class NamespaceLeaf {
	/// 移行前の共用名です。
	LEGACY,
	/// 完全公開pin付き検証用名です。
	LOCAL,
	/// 鍵更新でも変えない通常配布名です。
	DISTRIBUTION
} ;

/** @brief Testが指定する有限な失敗点です。成功を返すhookはありません。 */
enum class Fault {
	/// 全ての実APIを通常実行します。
	NONE,
	/// DPAPIへ入る前に拒否します。
	BEFORE_PROTECT,
	/// Stagingを作成する前に拒否します。
	BEFORE_STAGE,
	/// 実stagingへ半分だけ書き、commit前に拒否します。
	PARTIAL_WRITE,
	/// 実write後のflush前に拒否します。
	BEFORE_FLUSH,
	/// Flush成功後のrename前に拒否します。
	BEFORE_REPLACE,
	/// 実rename後のacknowledgementを拒否します。
	AFTER_REPLACE,
	/// 実rename後のreadbackを拒否します。
	READBACK,
	/// 実rename後の確保例外を起こします。
	AFTER_COMMIT_ALLOCATION
} ;

/** @brief Isolated storeだけへ実lockの単独所有を発行します。 */
class TestLock final {
public:
	/** @brief 取得したlockを閉じます。 */
	~TestLock() noexcept ;
	/** @brief Handleの二重解放を防ぎます。 */
	TestLock( const TestLock &) = delete ;
	/** @brief Handleのcopy代入を禁止します。
	 * @return 呼出しは禁止されます。
	 */
	TestLock &operator=( const TestLock &) = delete ;

private:
	/** @brief 検査済みの実lockを所有します。
	 * @param[in] handle 非nullの実file handle。
	 */
	explicit TestLock( HANDLE handle) noexcept ;
	friend struct Access ;
	/// share0で所有する実file handle。
	HANDLE handle_{} ;
} ;

/** @brief Native unit専用RAM trustと自作temp rootだけを扱う内部能力です。 */
struct Access {
	/** @brief 自作parentの固定三leafだけを通常と同じdomain規則で開きます。
	 * @param[in] parent 自作隔離rootを所有するsandboxです。
	 * @param[in] leaf 固定三名の選択です。
	 * @param[in] trust 人工RAM公開鍵だけです。
	 * @param[in] createMissing 初回作成を許可する場合trueです。
	 * @return 保護/旧root guard成功時だけstoreです。
	 */
	[[nodiscard]] static IndexStoreOpenResult openNamespaceIsolated(
		const SignedIndexStore &parent, NamespaceLeaf leaf,
		std::span<const signed_index_detail::TrustKey> trust, bool createMissing = true) noexcept ;
	/** @brief 自作namespaceで製品と同じ分類/移動/再実行を実行します。
	 * @param[in,out] store Sandbox内の固定leaf所有です。同時呼出しを行いません。
	 * @param[in] expectedHeadSha256 原ciphertextの完全pinです。
	 * @param[in] nowUtc 現在UTCです。
	 * @return 実移動と世代/拒否です。製品pathを受理しません。
	 */
	[[nodiscard]] static IndexStoreMigrationResult migrateNamespaceIsolated(
		SignedIndexStore &store, std::string_view expectedHeadSha256,
		std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/** @brief 実作成と共通のSDDL生成規則をRAM fixtureへ返します。
	 * @param[in] store Isolated能力とprocess SIDを持つstore。
	 * @param[in] directory Directory用OICIを要求する場合true。
	 * @param[in] product 管理者二ACE profileを要求する場合true。
	 * @return RAMだけのSDDL。製品storeまたは任意pathは扱いません。
	 */
	[[nodiscard]] static std::wstring protectionSddl( const SignedIndexStore &store, bool directory,
													 bool product) ;
	/** @brief 実同handle検査と共通のprofile検査をRAM内descriptorへ適用します。
	 * @param[in] store Isolated能力とprocess SIDを持つstore。
	 * @param[in] sddl RAM内の人工descriptor。実fileへ設定しません。
	 * @param[in] directory Directory用OICIを要求する場合true。
	 * @param[in] product 管理者二ACE profileを要求する場合true。
	 * @return 完全一致時true。製品store・不正SDDL・例外はfalseです。
	 */
	[[nodiscard]] static bool		  acceptsProtectionSddl( const SignedIndexStore &store,
															std::wstring_view sddl, bool directory,
															bool product) noexcept ;
	/** @brief 一意な保護temp rootを自分で作成します。
	 * @param[in] trust UnitのRAM public keyだけ。所有copyを作ります。
	 * @param[in] migration 移動専用fixtureでrootのDELETE権限を要求する場合trueです。
	 * @return 実保護初期化後だけstore。任意pathや製品storeを受理しません。
	 */
	[[nodiscard]] static IndexStoreOpenResult createIsolated(
		std::span<const signed_index_detail::TrustKey> trust, bool migration = false) noexcept ;
	/** @brief 自作隔離rootを同親の固定suffixへ認証移動します。
	 * @param[in,out] store 移動専用に自作した隔離storeです。
	 * @param[in] expectedHeadSha256 原ciphertextの完全pinです。
	 * @param[in] nowUtc 現在信頼UTCです。
	 * @param[in] fault BEFORE_REPLACE/AFTER_REPLACEまたはNONEだけです。
	 * @return 歴史認証と実rename結果。製品rootへ使用できません。
	 */
	[[nodiscard]] static IndexStoreMigrationResult migrateIsolated(
		SignedIndexStore &store, std::string_view expectedHeadSha256,
		std::optional<std::chrono::sys_seconds> nowUtc, Fault fault = Fault::NONE) noexcept ;
	/** @brief 同じ隔離rootを指す別のstore ownerを作ります。
	 * @param[in] store Isolated能力を持つstore。
	 * @return 製品storeは拒否します。Headのauthorityをcopyしません。
	 */
	[[nodiscard]] static IndexStoreOpenResult reopenIsolated(
		const SignedIndexStore &store) noexcept ;
	/** @brief 自作isolated rootのpathだけをtestへ開示します。
	 * @param[in] store Isolated能力を持つstore。
	 * @return 製品storeなら空pathです。
	 */
	[[nodiscard]] static std::filesystem::path isolatedRoot( const SignedIndexStore &store) ;
	/** @brief 同じ実保存経路へ有限な失敗だけを指定します。
	 * @param[in,out] store Isolated能力を持つstore。
	 * @param[in] receipt 保存前receipt。
	 * @param[in] envelope 原外側byte。
	 * @param[in] gzip 原転送byte。
	 * @param[in] nowUtc 現在の信頼UTC。
	 * @param[in] fault 有限の拒否点。
	 * @return 実commit結果。製品storeや定義外faultは拒否します。
	 */
	[[nodiscard]] static IndexStoreResult	   commitWithFault(
			 SignedIndexStore &store, const IndexRecordsSchemaReceipt &receipt,
			 std::string_view envelope, std::span<const std::byte> gzip,
			 std::optional<std::chrono::sys_seconds> nowUtc, Fault fault) noexcept ;
	/** @brief 競合試験だけへshare0の実lockを保持します。
	 * @param[in] store Isolated能力を持つstore。
	 * @return 検査済みowner。製品storeまたは競合時は空です。
	 */
	[[nodiscard]] static std::unique_ptr<TestLock> holdLock( const SignedIndexStore &store) ;
	/** @brief 実DPAPIからisolated headのplainを読みます。
	 * @param[in] store Isolated能力を持つstore。
	 * @param[out] plain 成功時のwire。失敗時空です。
	 * @return 元error。Testが暗号とwireの異なる拒否を作る用途だけです。
	 */
	[[nodiscard]] static NativeError			   readPlain( const SignedIndexStore &store,
															 std::vector<std::byte> &plain) ;
	/** @brief 改変wireも実DPAPI保護してisolated headへ書きます。
	 * @param[in] store Isolated能力を持つstore。
	 * @param[in] plain 有限なtest wire。Crypto／schema検証成功を注入しません。
	 * @return 元error。製品rootでは拒否します。
	 */
	[[nodiscard]] static NativeError			   replacePlain( const SignedIndexStore	  &store,
																std::span<const std::byte> plain) ;
} ;

} // namespace drivercrate::signed_index_store_detail
