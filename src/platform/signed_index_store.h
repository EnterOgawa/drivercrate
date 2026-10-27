//------------------------------------------------------------------------------
/**
 * @file signed_index_store.h
 * @brief 保護headの原子保存後だけ発行する署名索引snapshotを定義します。
 * @version 01.03.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  原envelopeとgzipを一headへ保護保存する境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.02.00 Shunji Ogawa  2026/10/19  用途別storeと旧head不変の明示移動を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理。
 * Ver.01.03.00 Shunji Ogawa  2026/10/27  Openの履歴下限と現在snapshotの能力を区別。
 * </pre>
 *
 * @note Workerで同期I/Oします。通常UI・通信・端末照合・導入許可を実装しません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/signed_index_records.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

// 索引専用wire／保存policyの初版。Collectorの上限を変更しません。
inline constexpr std::uint32_t INDEX_STORE_POLICY_VERSION = 1U ;

namespace signed_index_store_detail {
struct Access ;
enum class Fault ;
}
class SignedIndexStore ;

/** @brief 全再認証と保存確認後だけ構築するworker所有の不変snapshotです。 */
class AuthenticatedIndexSnapshot final {
public:
	/** @brief 原index／recordと段階・UNKNOWNを保持するschema receiptを借用します。
	 * @return Snapshotの寿命まで有効な不変参照。
	 */
	[[nodiscard]] const IndexRecordsSchemaReceipt &schemaReceipt() const noexcept ;
	/** @brief 再読取りで実署名を確認した原envelopeを借用します。
	 * @return Snapshotの寿命まで有効な原UTF-8 byte。
	 */
	[[nodiscard]] std::string_view				   originalEnvelope() const noexcept ;
	/** @brief 実hash／GZip検査を確認した原gzipを借用します。
	 * @return Snapshotの寿命まで有効な圧縮byte。
	 */
	[[nodiscard]] std::span<const std::byte>	   originalGzip() const noexcept ;
	/** @brief Snapshotを発行した索引保存policy版を返します。
	 * @return Store policy v1。
	 */
	[[nodiscard]] std::uint32_t					   storePolicyVersion() const noexcept ;

private:
	/** @brief 実head確認が終わった所有値だけを受け取ります。
	 * @param[in] receipt 全schema再認証済みの所有値。
	 * @param[in] envelope 実headから読んだ原外側byte。
	 * @param[in] gzip 実headから読んだ原転送byte。
	 */
	AuthenticatedIndexSnapshot( IndexRecordsSchemaReceipt receipt, std::string envelope,
							   std::vector<std::byte> gzip) noexcept ;
	friend class SignedIndexStore ;
	/// 原manifest・asset・index／record hashと型付き元申告の所有receipt。
	IndexRecordsSchemaReceipt receipt_ ;
	/// Crypto再認証へ使った原envelope byte。
	std::string				  envelope_ ;
	/// Hash／単一GZip再認証へ使った原圧縮byte。
	std::vector<std::byte>	  gzip_ ;
} ;

/** @brief Snapshot発行と拒否・保存障害を区別します。 */
enum class IndexStoreStatus {
	/// Binary固定trustが未配備です。製品rootへアクセスしません。
	TRUST_UNAVAILABLE,
	/// 保存済みheadを全再認証し、現在有効なsnapshotを発行しました。
	SNAPSHOT_READY,
	/// 新規に作成されたgenesisだけがあり、受理世代はありません。
	EMPTY_STORE,
	/// 不完全receipt、異なる原入力、または不正呼出しです。
	INVALID_INPUT,
	/// 実manifest署名・意味・世代の再認証が拒否されました。
	MANIFEST_REJECTED,
	/// 実gzipのhash・size・展開が拒否されました。
	ASSET_REJECTED,
	/// 展開原index／recordのschemaが拒否されました。
	RECORDS_REJECTED,
	/// 既存head／lock欠損、保護wire破損・世代不一致です。
	STATE_REJECTED,
	/// 現在の信頼UTCを確認できません。Headを削除しません。
	TIME_UNAVAILABLE,
	/// 現在UTCが署名発行前です。Headを削除しません。
	NOT_YET_VALID,
	/// 現在UTCが署名期限以上です。Highwaterは保持します。
	EXPIRED,
	/// 同じdirectory／fileの属性・owner・DACL・DPAPIが不成立です。
	PROTECTION_FAILURE,
	/// Commit前の実I/O障害です。旧headは変更しません。
	IO_FAILURE,
	/// 別operationが実lockを保持しています。待機せず終了します。
	BUSY,
	/// Commit前の確保失敗です。
	OUT_OF_MEMORY,
	/// Commit成功後にacknowledgement／読戻し／確保が失敗し、snapshotはありません。
	COMMITTED_NO_SNAPSHOT,
	/// Rename APIの失敗後で結果が確定できません。Reloadが必要です。
	COMMIT_UNCERTAIN
} ;

/** @brief API拒否と実headの変更確定を別に報告します。 */
enum class IndexStoreCommitDisposition {
	/// この呼出しはheadを置換しませんでした。
	NO_CHANGE,
	/// Rename成功が確認でき、headがadvanceしました。
	COMMITTED,
	/// Rename失敗後の結果を推測しません。
	UNKNOWN
} ;

/** @brief 保存／reloadの結果です。成功snapshotは別の所有値です。 */
struct IndexStoreResult {
	/// 独立した保存または拒否区分。
	IndexStoreStatus						  status{IndexStoreStatus::STATE_REJECTED} ;
	/// 同世代再利用・拒否でも保存の有無を独立して報告します。
	IndexStoreCommitDisposition				  commit{IndexStoreCommitDisposition::NO_CHANGE} ;
	/// 元Win32 codeまたは前段HRESULT。未発生時0です。
	NativeError								  error{} ;
	/// Manifest拒否の元区分。未発生時はnulloptです。
	std::optional<SignedIndexManifestStatus>  manifestStatus ;
	/// Asset拒否の元区分。未発生時はnulloptです。
	std::optional<IndexAssetBytesStatus>	  assetStatus ;
	/// Record拒否の元区分。未発生時はnulloptです。
	std::optional<IndexRecordsStatus>		  recordsStatus ;
	/// 排他的なhead再認証から得た最大世代。Caller入力をauthorityにしません。
	std::optional<std::uint64_t>			  persistedGeneration ;
	/// 現在有効なheadの全確認後だけ存在します。
	std::optional<AuthenticatedIndexSnapshot> snapshot ;
} ;

struct IndexStoreOpenResult ;

/** @brief 一つの固定rootをpinし、operationごとの実lockでheadを保護します。
 * @note 同時呼出しはshare0 lockで一つだけ成功します。Blocking I/Oをworkerで実行します。
 */
class SignedIndexStore final {
public:
	/** @brief 固定既存rootだけを読み、初回root／genesisを作成しません。
	 * @param[in] nowUtc 現在信頼UTC。確認不能ではsnapshotを発行しません。
	 * @return 固定trust未配備・欠損・失敗を明示する実reload結果。
	 * @note 未配備時はProgramDataも照会しません。任意path／trustは受け付けません。
	 */
	[[nodiscard]] static IndexStoreResult reloadFixedExisting(
		std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/** @brief 固定ProgramData rootだけを保護して開きます。
	 * @return 成功時store、失敗時元error。通常と検証用の固定domainを分離します。
	 * @note 履歴下限だけを認証し、現在有効なcacheは保証しません。Reloadで全schema/現在期限を確認します。
	 * 旧共用rootが残る間はERROR_REVISION_MISMATCHで拒否し、既存dataを変更しません。
	 */
	[[nodiscard]] static IndexStoreOpenResult openFixedProtectedStore() noexcept ;
	/** @brief 保持directory handleを解放し、製品headを削除しません。 */
	~SignedIndexStore() ;
	/** @brief Storeの別名copyを禁止します。 */
	SignedIndexStore( const SignedIndexStore &) = delete ;
	/** @brief Storeのcopy代入を禁止します。
	 * @return 呼出しは禁止されます。
	 */
	SignedIndexStore			  &operator=( const SignedIndexStore &) = delete ;
	/** @brief Schema receiptと原入力を再認証し、最新headと一回のcommitで保存します。
	 * @param[in] receipt 完全な保存前receipt。Move元を拒否します。
	 * @param[in] envelope 元manifestを持つ原外側byte。本呼出し中不変に保ちます。
	 * @param[in] gzip 元転送byte。本呼出し中不変に保ちます。
	 * @param[in] nowUtc 現在の信頼UTC。確認不能では保存しません。
	 * @return Commit前／後を区別する結果。Save失敗ではsnapshotなしです。
	 */
	[[nodiscard]] IndexStoreResult commit( const IndexRecordsSchemaReceipt		 &receipt,
										  std::string_view						  envelope,
										  std::span<const std::byte>			  gzip,
										  std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/** @brief 保存済み原入力から実暗号・schema・現在期限を再確認します。
	 * @param[in] nowUtc 現在の信頼UTC。履歴highwater検証を現在期限の代用にしません。
	 * @return 有効headだけsnapshotを返し、期限切れ／破損を初回へ戻しません。
	 */
	[[nodiscard]] IndexStoreResult reload( std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

private:
	/** @brief root、DACL、entropy、内部固定trustを所有する実装専用stateです。 */
	struct State ;
	/** @brief 検証済みrootと内部固定trustを単独の入口から受け取ります。
	 * @param[in] state 保護初期化済みの所有state。
	 */
	explicit SignedIndexStore( std::shared_ptr<State> state) noexcept ;
	/** @brief 内部の有限拒否診断付きで同じ実保存経路を実行します。
	 * @param[in] receipt 保存前receipt。
	 * @param[in] envelope 原外側byte。
	 * @param[in] gzip 原転送byte。
	 * @param[in] nowUtc 現在信頼UTC。
	 * @param[in] fault Test専用の拒否点。製品入口ではNONEです。
	 * @return 保存とsnapshotを独立した区分へ変換した実結果。
	 */
	[[nodiscard]] IndexStoreResult commitImpl( const IndexRecordsSchemaReceipt		 &receipt,
											  std::string_view						  envelope,
											  std::span<const std::byte>			  gzip,
											  std::optional<std::chrono::sys_seconds> nowUtc,
											  signed_index_store_detail::Fault fault) noexcept ;
	friend struct signed_index_store_detail::Access ;
	/// 不変のroot資源。Testの再openだけは同じownerの寿命を延長します。
	std::shared_ptr<State> state_ ;
} ;

/** @brief 固定または内部fixture rootを開いた結果です。 */
struct IndexStoreOpenResult {
	/// 元Win32 codeまたはHRESULT。成功0です。
	NativeError						  error{} ;
	/// 保護初期化成功時だけ存在します。
	std::unique_ptr<SignedIndexStore> store ;
} ;

} // namespace drivercrate
