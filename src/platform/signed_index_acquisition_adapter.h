//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_adapter.h
 * @brief 保存署名索引を既存取得承認・一回grantと内容検査入力へ結びます。
 * @version 01.05.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  署名snapshotと同grant・共通取得の有限接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  完全内容根拠と取得policy一致の元関係を一取得taskへ保持。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  Local受入buildの独立固定能力を明示。
 * Ver.01.04.01 Shunji Ogawa  2026/10/16  通常配布の独立取得集合とlocal排他を説明。
 * Ver.01.05.00 Shunji Ogawa  2026/10/24  原関係集合とunique device数を分離する共有claim契約へ整合。
 * </pre>
 *
 * @note 同workerで直列使用します。通常profileは配布鍵のrevision1取得認可を別登録します。
 * 明示local受入でも独立optionの固定能力だけを使い、実適合・導入許可を発行しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/official_preparation.h"
#include "platform/official_acquisition.h"
#include "platform/official_http_client.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/signed_index_record_lookup.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace drivercrate {
namespace signed_index_acquisition_detail {
struct Access ;
}

/** @brief 対象と理由を区別し、未知を成功へ補完しない取得記述です。 */
struct SignedIndexPreparationDescription {
	/// 計画へ渡せる条件が全て成立した場合だけ存在する値。取得能力ではありません。
	std::optional<OfficialPreparationTarget> target ;
	/// 未対応・不足・拒否の具体的理由。成功時は空です。
	std::string								 reason ;
} ;

/** @brief 同scanの封印lookupと独立失効leaseを所有する共通取得adapterです。
 * @note 新scan等でinvalidateを呼びます。Snapshotの共有寿命を権限寿命にしません。
 */
class SignedIndexAcquisitionAdapter final {
public:
	/** @brief 未開始のadapterを作ります。 */
	SignedIndexAcquisitionAdapter() = default ;
	/** @brief Leaseを失効し、発行済みgrantを再使用不能にします。 */
	~SignedIndexAcquisitionAdapter() = default ;
	/** @brief Issuerの別名copyを禁止します。 */
	SignedIndexAcquisitionAdapter( const SignedIndexAcquisitionAdapter &) = delete ;
	/** @brief Issuerのcopy代入を禁止します。
	 * @return 呼出しは禁止されます。
	 */
	SignedIndexAcquisitionAdapter &operator=( const SignedIndexAcquisitionAdapter &) = delete ;
	/** @brief 保存snapshotを含む同worker lookupへ固定policyで結合します。
	 * @param[in] lookup 非公開構築の不変lookup。Null・不足を拒否します。
	 * @param[in] current 同workerのoperation・scan・inventory。
	 * @param[in] targetOs 現workerが確認したOS分類。端末適合の合格ではありません。
	 * @param[in] nowUtc 信頼UTC。確認不能を拒否します。
	 * @return 開始0。未配備の製品policy・stale・期限・不足は拒否HRESULT。
	 */
	[[nodiscard]] NativeError	   begin( std::shared_ptr<const SignedIndexRecordLookup> lookup,
										 IndexLookupContext current, IndexTargetOs targetOs,
										 std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/** @brief 私有issuerと未開始計画を失効します。原snapshotを修復・削除しません。 */
	void						   invalidate() noexcept ;
	/** @brief 新しい取得だけを閉鎖し、消費済み成功grantの同期限内再検証を保持します。 */
	void						   closeAcquisitionForInstall() noexcept ;
	/** @brief 元lookupの関係位置から取得対象を再記述します。
	 * @param[in] relationIndex 元lookup内の0起点位置。公開tupleは受理しません。
	 * @param[in] current 現worker context。
	 * @param[in] nowUtc 信頼UTC。
	 * @param[in] limits 共通preparationの有限予算。
	 * @param[out] description 全条件成功時だけtarget。失敗時は不足理由を保持します。
	 * @return 記述成功0、未知・未対応E_NOTIMPL、stale・権限・期限等の拒否HRESULT。
	 */
	[[nodiscard]] NativeError	   describe( std::size_t relationIndex, IndexLookupContext current,
											std::optional<std::chrono::sys_seconds> nowUtc,
											const OfficialPreparationLimits		   &limits,
											SignedIndexPreparationDescription	   &description) ;
	/** @brief 元認証規約を有限共通GETで取得し、全文と出典をRAMの記述へ固定します。
	 * @param[in] relationIndex 私有lookupの原関係位置です。
	 * @param[in] current 元scanの全contextです。
	 * @param[in] nowUtc 信頼UTCです。前後の期限を再照合します。
	 * @param[in,out] client 同workerの完全共通HTTP依存です。公開URLは受理しません。
	 * @param[in] cancellation 同scanの協調停止です。
	 * @return 全原byte/全文成立0、未対応/変更/失効は元HRESULTです。
	 * @note 同意を発行せず、未取得本文を空の同意不要へ変更しません。
	 */
	[[nodiscard]] NativeError readTermsText( std::size_t relationIndex, IndexLookupContext current,
											std::optional<std::chrono::sys_seconds> nowUtc,
											OfficialHttpClient					   &client,
											const HttpCancellationCallback		   &cancellation) ;
	/** @brief 実claim済みtaskから同じRecordScopedDownloadGrantを一回発行します。
	 * @param[in] preparation 実active taskを所有する同worker session。
	 * @param[in] task 利用者承認後の未変更task。
	 * @param[in] current 現worker context。
	 * @param[in] nowUtcSeconds 発行直前の信頼UTC秒。
	 * @param[out] grant 未発行object。成功時だけ同じgrant状態機械へ進めます。
	 * @return 全再照合成功0、改変・再使用・失効・期限は拒否HRESULT。
	 */
	[[nodiscard]] NativeError claimApprovedRecord( OfficialPreparationSession	&preparation,
												  const OfficialPreparationTask &task,
												  IndexLookupContext			 current,
												  std::uint64_t					 nowUtcSeconds,
												  RecordScopedDownloadGrant		&grant) ;
	/** @brief 共通取得sealを元recordと独立照合し、共通内容検査入力を生成します。
	 * @param[in] task 発行済みgrantと同じ実task。
	 * @param[in] current 現worker context。
	 * @param[in] nowUtcSeconds 封印入力確認直前の信頼UTC秒。
	 * @param[in] session 元取得sealのissuer。
	 * @param[in] workspace 元保護fileを所有する領域。
	 * @param[in] evidence 公開結果から構築できない元取得seal。
	 * @param[out] hint 全成功時だけ元index／record／実archiveの期待値。
	 * @param[out] input 全成功時だけ既存DriverArchiveInput。失敗時は空。
	 * @return 全実byteとrecord結合成功0、元HRESULTまたは拒否HRESULT。
	 * @note 内容署名・Windows適合・導入は別の共通検査で行います。
	 */
	[[nodiscard]] NativeError bindInspectionInput(
		const OfficialPreparationTask &task, IndexLookupContext current,
		std::uint64_t nowUtcSeconds, const OfficialAcquisitionSession &session,
		const OfficialDownloadWorkspace &workspace, const OfficialAcquiredFileEvidence &evidence,
		IndexedDriverArchiveHint &hint, DriverArchiveInput &input) const ;

private:
	/** @brief 製品policyと固定内部fixture policyを分離します。 */
	enum class AuthorityProfile {
		/// 通常は固定配布の独立取得集合、local受入は独立optionの固定集合です。
		PRODUCT,
		/// 隔離RAM署名fixtureだけの固定fixture-main／revision1です。
		INTERNAL_RAM_FIXTURE
	} ;
	/** @brief 一回の記述と実claimを元関係位置へ結合します。 */
	struct PreparedBinding {
		/// 元lookupの関係位置。
		std::size_t							   relationIndex{} ;
		/// Workerが記述した全対象snapshot。
		OfficialPreparationTarget			   target ;
		/// 記述時の共通予約予算。
		OfficialPreparationLimits			   limits ;
		/// 実claim後だけ存在するtoken。同recordの再発行を拒否します。
		std::optional<OfficialPreparationTask> claimedTask ;
		/// 元taskから発行した同issuer内のexact grant ID。未発行は0です。
		std::uint64_t						   grantId{} ;
		/// 同完全payload根拠と全取得policyへ結合した原関係位置。既存lookup最大32768枠内です。
		std::vector<std::size_t>			   relationIndices ;
	} ;
	/** @brief 原recordへ結合した有限全文のRAM所有値です。 */
	struct TermsSnapshot {
		/// 本文を取得した原関係位置です。
		std::size_t	 relationIndex{} ;
		/// 正確な全文とrevisionです。永続化しません。
		std::wstring text ;
		/// 原公開revisionまたは全文の算出revisionです。
		std::wstring revision ;
	} ;
	/** @brief 内部固定profileを使って同じ開始検査を行います。
	 * @param[in] lookup 保存済み元lookup。
	 * @param[in] current 現context。
	 * @param[in] targetOs 既知OS分類。
	 * @param[in] nowUtc 信頼UTC。
	 * @param[in] profile 外部設定ではない内部固定policy区分。
	 * @return 全開始検査成功0、それ以外は拒否HRESULT。
	 */
	[[nodiscard]] NativeError beginImpl( std::shared_ptr<const SignedIndexRecordLookup> lookup,
										IndexLookupContext current, IndexTargetOs targetOs,
										std::optional<std::chrono::sys_seconds> nowUtc,
										AuthorityProfile						profile) noexcept ;
	/** @brief 元tuple・descriptor・期限・通常driver条件を再照合します。
	 * @param[in] relationIndex 元関係位置。
	 * @param[in] current 現context。
	 * @param[in] nowUtc 信頼UTC。
	 * @param[out] reason 失敗時の具体的理由。成功時は空。
	 * @return 全条件成立0、それ以外は拒否または保留HRESULT。
	 */
	[[nodiscard]] NativeError validateRecord( std::size_t relationIndex, IndexLookupContext current,
											 std::optional<std::chrono::sys_seconds> nowUtc,
											 std::string							&reason) const ;
	/** @brief 私有共有bindingの全原recordと期限を再確認します。
	 * @param[in] binding 同issuerが記述した未変更の取得binding。
	 * @param[in] current 元scan context。
	 * @param[in] nowUtc 信頼UTC。
	 * @param[out] reason 最初の拒否理由。
	 * @return 全原関係成立0、それ以外は元HRESULTです。
	 */
	[[nodiscard]] NativeError validateBinding( const PreparedBinding					 &binding,
											  IndexLookupContext					  current,
											  std::optional<std::chrono::sys_seconds> nowUtc,
											  std::string							 &reason) const ;
	friend struct signed_index_acquisition_detail::Access ;
	friend class RecordScopedDownloadGrant ;
	friend class SignedIndexCandidateBindingSession ;
	/// 生存能力を表す独立issuer。Grantは弱参照だけを保持します。
	std::shared_ptr<const std::byte>			   issuer_ ;
	/// Issuerと独立した新規取得開始可否。閉鎖後は再開せず新scanを必要とします。
	std::shared_ptr<bool>						   acquisitionOpen_ ;
	/// 同scanの非公開構築lookupと原保存snapshot。
	std::shared_ptr<const SignedIndexRecordLookup> lookup_ ;
	/// 全発行対象の同worker context。
	IndexLookupContext							   context_ ;
	/// 現workerが確認した対象OS分類。
	IndexTargetOs								   targetOs_{IndexTargetOs::WINDOWS_11} ;
	/// 最大256件の記述と一回claimの元binding。
	std::vector<PreparedBinding>				   bindings_ ;
	/// 最大256本文かつplan全文上限以内の原RAM snapshotです。
	std::vector<TermsSnapshot>					   terms_ ;
	/// 同issuer内で単調増加するgrant ID。
	std::uint64_t								   nextGrantId_{1U} ;
} ;
} // namespace drivercrate
