//------------------------------------------------------------------------------
/**
 * @file signed_index_store.h
 * @brief 保護headの原子保存後だけ発行する署名索引snapshotを定義します
 * @version 01.08.00
 * @date 2026/10/24
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続
 * Ver.01.02.00 Shunji Ogawa  2026/10/19  用途別storeと旧head不変の明示移動を追加
 * Ver.01.02.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理
 * Ver.01.03.00 Shunji Ogawa  2026/10/27  Openの履歴下限と現在snapshotの能力を区別
 * Ver.01.03.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.03.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.04.00 Shunji Ogawa  2026/11/20  端末用レコード位置と元領域の参照を追加
 * Ver.01.05.00 Shunji Ogawa  2026/11/20  同スキャンの端末機種型番を不変snapshotに保持
 * Ver.01.06.00 Shunji Ogawa  2026/11/23  同スキャンのWindows観測を不変snapshotに保持
 * Ver.01.06.01 Shunji Ogawa  2026/11/26  端末照合に借りる二領域の値を前置契約で説明
 * Ver.01.07.00 Shunji Ogawa  2026/11/27  隔離ストアの追加欄再読試験へ同じsnapshotを許可
 * Ver.01.08.00 Shunji Ogawa  2026/11/28  端末用レコードの使用期限を同じ行の確認期限へ結合
 * </pre>
 *
 * @note Workerで同期I/Oします。通常UI・通信・端末照合・導入許可を実装しません
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/signed_index_records.h"
#include "platform/windows_product_type.h"
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

// 索引専用wire／保存policyの初版。Collectorの上限を変更しません
inline constexpr std::uint32_t INDEX_STORE_POLICY_VERSION = 1U ;

namespace signed_index_store_detail {
struct Access ;
enum class Fault ;
}
class SignedIndexStore ;
class SignedIndexScanSession ;

/** @brief スキャンが保持する本文と追加欄を元の順序で借用するレコード参照です */
struct IndexConsumerRecordView {
	/// 署名済み本文の元レコードです
	std::span<const IndexDistributionRecord>	 base ;
	/// 同じassetの確認済み追加レコードです
	std::span<const IndexDistributionRecord>	 supplement ;
	/**
	 * @brief 同じ索引の両領域にある端末用レコードの合計件数を返します
	 * @return 本文と追加欄を合わせた件数です
	 */
	[[nodiscard]] std::size_t					 size() const noexcept ;
	/**
	 * @brief 本文の直後に追加欄を並べた位置から元レコードを借用します
	 * @param[in] index 両領域に連続する0起点の位置です
	 * @pre indexはsize()未満です
	 * @return 元領域が所有する不変レコードです
	 */
	[[nodiscard]] const IndexDistributionRecord &operator[]( std::size_t index) const noexcept ;
} ;

/** @brief 端末用レコードに対応する元本文又は追加欄の不変証拠です */
struct IndexConsumerRecordRegion {
	/// 同じ元領域の取得元です
	std::span<const IndexRecordSource> sources ;
	/// 同じ元領域の展開原byteのSHA-256です
	const IndexManifestSha256		  &indexSha256 ;
	/// このレコードに適用するmanifest・領域・元確認の最短期限です
	std::chrono::sys_seconds		   expiresAtUtc ;
} ;

/** @brief 同workerのoperation・scan・inventoryの結合contextです */
struct IndexLookupContext {
	/// 正のoperation identity
	std::uint64_t	   operationId{} ;
	/// 正のscan session identity
	std::uint64_t	   scanSessionId{} ;
	/// 正のinventory世代
	std::uint64_t	   inventoryGeneration{} ;
	/**
	 * @brief 全context fieldの完全一致を比較します
	 * @param[in] other 比較対象
	 * @return 全field一致の場合だけtrue
	 */
	[[nodiscard]] bool operator==( const IndexLookupContext &other) const noexcept = default ;
} ;

/** @brief 同一スキャンで確認した端末の製造元と型番です */
struct IndexPlatformMachineIdentity {
	/// 端末で観測した製造元の区分です。生の値は保持しません
	IndexPlatformMachineVendor vendor{IndexPlatformMachineVendor::UNKNOWN} ;
	/// 確認できた型番です。読み取り不能又は未対応の場合は空です
	std::string				   machineType ;
} ;

/** @brief 全再認証と保存確認後だけ構築するworker所有の不変snapshotです */
class AuthenticatedIndexSnapshot final {
public:
	/**
	 * @brief 原index／recordと段階・UNKNOWNを保持するschema receiptを借用します
	 * @return Snapshotの寿命まで有効な不変参照
	 */
	[[nodiscard]] const IndexRecordsSchemaReceipt &schemaReceipt() const noexcept ;
	/**
	 * @brief 同じ署名済み索引の端末用レコードを借用します
	 * @return 本文とスキャンが確認済みの追加欄を同じ順序で参照する値です
	 */
	[[nodiscard]] IndexConsumerRecordView		   consumerRecords() const noexcept ;
	/**
	 * @brief 同じ元位置に対応する取得元・展開hashと期限を借用します
	 * @param[in] index 端末用レコード参照の0起点位置です
	 * @pre indexはconsumerRecords().size()未満です
	 * @return 元領域の参照と、manifest・領域・同じレコードの元確認に基づく最短期限です
	 */
	[[nodiscard]] IndexConsumerRecordRegion consumerRecordRegion( std::size_t index) const noexcept ;
	/**
	 * @brief 同じスキャンで確認した端末内の型番を借用します
	 * @param[in] context 端末の観測を利用する同じ操作、スキャン、inventory世代です
	 * @return 元操作が一致する端末情報です。観測未実施又は別スキャンならnullです
	 */
	[[nodiscard]] const IndexPlatformMachineIdentity *platformMachine(
		const IndexLookupContext &context) const noexcept
	{
		return platformMachineContext_ && *platformMachineContext_ == context ? &platformMachine_
																			  : nullptr ;
	}
	/**
	 * @brief 同じスキャンで取得したWindowsの観測を借用します
	 * @param[in] context 観測を取得した操作・スキャン・インベントリ世代を識別する値です
	 * @return 同じ文脈の元観測です。未実施と別スキャンではnullです
	 * @note 観測の失敗も元の状態で返します。借用はこのsnapshotの寿命内に限ります
	 */
	[[nodiscard]] const WindowsHostPlatformObservation *windowsHost(
		const IndexLookupContext &context) const noexcept
	{
		return windowsHostContext_ && *windowsHostContext_ == context ? &windowsHost_ : nullptr ;
	}
	/**
	 * @brief 再読取りで実署名を確認した原envelopeを借用します
	 * @return Snapshotの寿命まで有効な原UTF-8 byte
	 */
	[[nodiscard]] std::string_view			 originalEnvelope() const noexcept ;
	/**
	 * @brief 実hash／GZip検査を確認した原gzipを借用します
	 * @return Snapshotの寿命まで有効な圧縮byte
	 */
	[[nodiscard]] std::span<const std::byte> originalGzip() const noexcept ;
	/**
	 * @brief Snapshotを発行した索引保存policy版を返します
	 * @return Store policy v1
	 */
	[[nodiscard]] std::uint32_t				 storePolicyVersion() const noexcept ;

private:
	/**
	 * @brief 実head確認が終わった所有値だけを受け取ります
	 * @param[in] receipt 全schema再認証済みの所有値
	 * @param[in] envelope 実headから読んだ原外側byte
	 * @param[in] gzip 実headから読んだ原転送byte
	 */
	AuthenticatedIndexSnapshot( IndexRecordsSchemaReceipt receipt, std::string envelope,
							   std::vector<std::byte> gzip) noexcept ;
	friend class SignedIndexStore ;
	friend class SignedIndexScanSession ;
	friend struct signed_index_store_detail::Access ;
	/// 原manifest・asset・index／record hashと型付き元申告の所有receipt
	IndexRecordsSchemaReceipt		  receipt_ ;
	/// Crypto再認証へ使った原envelope byte
	std::string						  envelope_ ;
	/// Hash／単一GZip再認証へ使った原圧縮byte
	std::vector<std::byte>			  gzip_ ;
	/// 通常スキャンが同じ原byteから検証した端末用追加欄です
	IndexConsumerSupplementResult	  consumerSupplement_ ;
	/// 通常スキャンが同じinventory contextで観測した端末情報です
	IndexPlatformMachineIdentity	  platformMachine_ ;
	/// 端末型番を採った元のinventory contextです
	std::optional<IndexLookupContext> platformMachineContext_ ;
	/// 通常スキャンが同じインベントリで取得したWindowsの元観測です
	WindowsHostPlatformObservation	  windowsHost_ ;
	/// Windowsの元観測を取得した操作・スキャン・インベントリ世代です
	std::optional<IndexLookupContext> windowsHostContext_ ;
} ;

/** @brief Snapshot発行と拒否・保存障害を区別します */
enum class IndexStoreStatus {
	/// Binary固定trustが未配備です。製品rootへアクセスしません
	TRUST_UNAVAILABLE,
	/// 保存済みheadを全再認証し、現在有効なsnapshotを発行しました
	SNAPSHOT_READY,
	/// 新規に作成されたgenesisだけがあり、受理世代はありません
	EMPTY_STORE,
	/// 不完全receipt、異なる原入力、または不正呼出しです
	INVALID_INPUT,
	/// 実manifest署名・意味・世代の再認証が拒否されました
	MANIFEST_REJECTED,
	/// 実gzipのhash・size・展開が拒否されました
	ASSET_REJECTED,
	/// 展開原index／recordのschemaが拒否されました
	RECORDS_REJECTED,
	/// 既存head／lock欠損、保護wire破損・世代不一致です
	STATE_REJECTED,
	/// 現在の信頼UTCを確認できません。Headを削除しません
	TIME_UNAVAILABLE,
	/// 現在UTCが署名発行前です。Headを削除しません
	NOT_YET_VALID,
	/// 現在UTCが署名期限以上です。Highwaterは保持します
	EXPIRED,
	/// 同じdirectory／fileの属性・owner・DACL・DPAPIが不成立です
	PROTECTION_FAILURE,
	/// Commit前の実I/O障害です。旧headは変更しません
	IO_FAILURE,
	/// 別operationが実lockを保持しています。待機せず終了します
	BUSY,
	/// Commit前の確保失敗です
	OUT_OF_MEMORY,
	/// Commit成功後にacknowledgement／読戻し／確保が失敗し、snapshotはありません
	COMMITTED_NO_SNAPSHOT,
	/// Rename APIの失敗後で結果が確定できません。Reloadが必要です
	COMMIT_UNCERTAIN
} ;

/** @brief API拒否と実headの変更確定を別に報告します */
enum class IndexStoreCommitDisposition {
	/// この呼出しはheadを置換しませんでした
	NO_CHANGE,
	/// Rename成功が確認でき、headがadvanceしました
	COMMITTED,
	/// Rename失敗後の結果を推測しません
	UNKNOWN
} ;

/** @brief 保存／reloadの結果です。成功snapshotは別の所有値です */
struct IndexStoreResult {
	/// 独立した保存または拒否区分
	IndexStoreStatus						  status{IndexStoreStatus::STATE_REJECTED} ;
	/// 同世代再利用・拒否でも保存の有無を独立して報告します
	IndexStoreCommitDisposition				  commit{IndexStoreCommitDisposition::NO_CHANGE} ;
	/// 元Win32 codeまたは前段HRESULT。未発生時0です
	NativeError								  error{} ;
	/// Manifest拒否の元区分。未発生時はnulloptです
	std::optional<SignedIndexManifestStatus>  manifestStatus ;
	/// Asset拒否の元区分。未発生時はnulloptです
	std::optional<IndexAssetBytesStatus>	  assetStatus ;
	/// Record拒否の元区分。未発生時はnulloptです
	std::optional<IndexRecordsStatus>		  recordsStatus ;
	/// 排他的なhead再認証から得た最大世代。Caller入力をauthorityにしません
	std::optional<std::uint64_t>			  persistedGeneration ;
	/// 現在有効なheadの全確認後だけ存在します
	std::optional<AuthenticatedIndexSnapshot> snapshot ;
} ;

struct IndexStoreOpenResult ;

/** @brief 一つの固定rootをpinし、operationごとの実lockでheadを保護します
 * @note 同時呼出しはshare0 lockで一つだけ成功します。Blocking I/Oをworkerで実行します
 */
class SignedIndexStore final {
public:
	/**
	 * @brief 固定既存rootだけを読み、初回root／genesisを作成しません
	 * @param[in] nowUtc 現在信頼UTC。確認不能ではsnapshotを発行しません
	 * @return 固定trust未配備・欠損・失敗を明示する実reload結果
	 * @note 未配備時はProgramDataも照会しません。任意path／trustは受け付けません
	 */
	[[nodiscard]] static IndexStoreResult reloadFixedExisting(
		std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/**
	 * @brief 固定ProgramData rootだけを保護して開きます
	 * @return 成功時store、失敗時元error。通常と検証用の固定domainを分離します
	 * @note 履歴下限だけを認証し、現在有効なcacheは保証しません。Reloadで全schema/現在期限を確認します。旧共用rootが残る間は
	 *       ERROR_REVISION_MISMATCHで拒否し、既存dataを変更しません
	 */
	[[nodiscard]] static IndexStoreOpenResult openFixedProtectedStore() noexcept ;
	/**
	 * @brief 保持directory handleを解放し、製品headを削除しません
	 */
	~SignedIndexStore() ;
	/**
	 * @brief Storeの別名copyを禁止します
	 */
	SignedIndexStore( const SignedIndexStore &) = delete ;
	/**
	 * @brief Storeのcopy代入を禁止します
	 */
	SignedIndexStore			  &operator=( const SignedIndexStore &) = delete ;
	/**
	 * @brief Schema receiptと原入力を再認証し、最新headと一回のcommitで保存します
	 * @param[in] receipt 完全な保存前receipt。Move元を拒否します
	 * @param[in] envelope 元manifestを持つ原外側byte。本呼出し中不変に保ちます
	 * @param[in] gzip 元転送byte。本呼出し中不変に保ちます
	 * @param[in] nowUtc 現在の信頼UTC。確認不能では保存しません
	 * @return Commit前／後を区別する結果。Save失敗ではsnapshotなしです
	 */
	[[nodiscard]] IndexStoreResult commit( const IndexRecordsSchemaReceipt		 &receipt,
										  std::string_view						  envelope,
										  std::span<const std::byte>			  gzip,
										  std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/**
	 * @brief 保存済み原入力から実暗号・schema・現在期限を再確認します
	 * @param[in] nowUtc 現在の信頼UTC。履歴highwater検証を現在期限の代用にしません
	 * @return 有効headだけsnapshotを返し、期限切れ／破損を初回へ戻しません
	 */
	[[nodiscard]] IndexStoreResult reload( std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

private:
	/** @brief root、DACL、entropy、内部固定trustを所有する実装専用stateです */
	struct State ;
	/**
	 * @brief 検証済みrootと内部固定trustを単独の入口から受け取ります
	 * @param[in] state 保護初期化済みの所有state
	 */
	explicit SignedIndexStore( std::shared_ptr<State> state) noexcept ;
	/**
	 * @brief 内部の有限拒否診断付きで同じ実保存経路を実行します
	 * @param[in] receipt 保存前receipt
	 * @param[in] envelope 原外側byte
	 * @param[in] gzip 原転送byte
	 * @param[in] nowUtc 現在信頼UTC
	 * @param[in] fault Test専用の拒否点。製品入口ではNONEです
	 * @return 保存とsnapshotを独立した区分へ変換した実結果
	 */
	[[nodiscard]] IndexStoreResult commitImpl( const IndexRecordsSchemaReceipt		 &receipt,
											  std::string_view						  envelope,
											  std::span<const std::byte>			  gzip,
											  std::optional<std::chrono::sys_seconds> nowUtc,
											  signed_index_store_detail::Fault fault) noexcept ;
	friend struct signed_index_store_detail::Access ;
	/// 不変のroot資源。Testの再openだけは同じownerの寿命を延長します
	std::shared_ptr<State> state_ ;
} ;

/** @brief 固定または内部fixture rootを開いた結果です */
struct IndexStoreOpenResult {
	/// 元Win32 codeまたはHRESULT。成功0です
	NativeError						  error{} ;
	/// 保護初期化成功時だけ存在します
	std::unique_ptr<SignedIndexStore> store ;
} ;

} // namespace drivercrate
