//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_adapter.h
 * @brief 保存署名索引を既存取得承認・一回grantと内容検査入力へ結びます
 * @version 01.19.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  完全内容根拠と取得policy一致の元関係を一取得taskへ保持
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  Local受入buildの独立固定能力を明示
 * Ver.01.04.01 Shunji Ogawa  2026/10/16  通常配布の独立取得集合とlocal排他を説明
 * Ver.01.05.00 Shunji Ogawa  2026/10/24  原関係集合とunique device数を分離する共有claim契約へ整合
 * Ver.01.06.00 Shunji Ogawa  2026/11/03  同payload/取得policyの値比較を開発用集合観測と共用
 * Ver.01.07.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続
 * Ver.01.07.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.07.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.08.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * Ver.01.09.00 Shunji Ogawa  2026/11/18  同所有host取消しを論理constへ限定し標準INF入力を接続
 * Ver.01.10.00 Shunji Ogawa  2026/11/20  規約取得の送受信時点に同じ信頼UTCを再確認
 * Ver.01.11.00 Shunji Ogawa  2026/11/20  機種別の取得境界で同じ型番を再観測する契約を追加
 * Ver.01.12.00 Shunji Ogawa  2026/11/20  機器別の確認計画と本体取得の検証目的を分離
 * Ver.01.13.00 Shunji Ogawa  2026/11/20  取得承認と元端末の現在ファームウェア群を結合
 * Ver.01.14.00 Shunji Ogawa  2026/11/22  導入の全選択確認に使う非観測の保護ファイル再照合を分離
 * Ver.01.15.00 Shunji Ogawa  2026/11/22  ZIP規約の再取得と同意済み操作への照合を追加
 * Ver.01.16.00 Shunji Ogawa  2026/11/22  承認済み取得対象を同じ端末の現在HardwareIdsへ再照合
 * Ver.01.17.00 Shunji Ogawa  2026/11/23  WiXの検査専用取得を元機器と実公式アンカーへ結合
 * Ver.01.18.00 Shunji Ogawa  2026/11/23  同じWiX取得票の照合と端末の再観測を分ける
 * Ver.01.19.00 Shunji Ogawa  2026/11/27  二段の公式規約を取得前の同意へ結ぶ
 * </pre>
 *
 * @note 同workerで直列使用します。通常profileは配布鍵のrevision1取得認可を別登録します
 * 明示local受入でも独立optionの固定能力だけを使い、実適合・導入許可を発行しません
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/official_preparation.h"
#include "platform/official_acquisition.h"
#include "platform/official_http_client.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/signed_index_record_lookup.h"
#include "platform/windows_product_type.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
class DriverStoreProvider ;
namespace signed_index_acquisition_detail {
struct Access ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常adapterと同じ完全payload/取得policyの値比較を行います
 * @param[in] left 個別codec検査済みの原recordです
 * @param[in] right 別の個別codec検査済み原recordです
 * @return 全内容根拠と取得条件が一致する場合だけtrueです
 * @note 認証型、共有claim、通信許可、端末適用性や導入能力を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesSharedIndexPayloadEvidence( const IndexDistributionRecord &left,
													 const IndexDistributionRecord &right) noexcept ;

/** @brief 対象と理由を区別し、未知を成功へ補完しない取得記述です */
struct SignedIndexPreparationDescription {
	/// 計画へ渡せる条件が全て成立した場合だけ存在する値。取得能力ではありません
	std::optional<OfficialPreparationTarget> target ;
	/// 未対応・不足・拒否の具体的理由。成功時は空です
	std::string								 reason ;
} ;

/** @brief 同scanの全contextと一度の原host観測です。権限ではありません */
struct IndexScanHostSnapshot {
	/// 元operation/scan/inventoryを変更しません
	IndexLookupContext			   context ;
	/// 原API状態/domain/bitsと六fieldです
	WindowsHostPlatformObservation observation ;
} ;

/** @brief 同scanの封印lookupと独立失効leaseを所有する共通取得adapterです
 * @note 新scan等でinvalidateを呼びます。Snapshotの共有寿命を権限寿命にしません
 */
class SignedIndexAcquisitionAdapter final {
public:
	/**
	 * @brief 未開始のadapterを作ります
	 */
	SignedIndexAcquisitionAdapter() = default ;
	/**
	 * @brief Leaseを失効し、発行済みgrantを再使用不能にします
	 */
	~SignedIndexAcquisitionAdapter() = default ;
	/**
	 * @brief Issuerの別名copyを禁止します
	 */
	SignedIndexAcquisitionAdapter( const SignedIndexAcquisitionAdapter &) = delete ;
	/**
	 * @brief Issuerのcopy代入を禁止します
	 */
	SignedIndexAcquisitionAdapter &operator=( const SignedIndexAcquisitionAdapter &) = delete ;
	/**
	 * @brief 保存snapshotを含む同worker lookupへ固定policyで結合します
	 * @param[in] lookup 非公開構築の不変lookup。Null・不足を拒否します
	 * @param[in] current 同workerのoperation・scan・inventory
	 * @param[in] targetOs 現workerが確認したOS分類。端末適合の合格ではありません
	 * @param[in] nowUtc 信頼UTC。確認不能を拒否します
	 * @return 開始0。未配備の製品policy・stale・期限・不足は拒否HRESULT
	 */
	[[nodiscard]] NativeError	   begin( std::shared_ptr<const SignedIndexRecordLookup> lookup,
										 IndexLookupContext current, IndexTargetOs targetOs,
										 std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/**
	 * @brief 同scan fullhostと明示observerを所有して開始します
	 * @param[in] lookup 原署名とnative所有を保持するlookupです
	 * @param[in] current 元scanの全contextです
	 * @param[in] host 同contextへ一度だけ結んだ原観測です
	 * @param[in] observer 取得直前だけの明示再観測関数です。欠落をnativeで補完しません
	 * @param[in] nowUtc 原期限確認用UTCです
	 * @return 成立0。既拒否context/未知/未対応/所有不一致は拒否です
	 */
	[[nodiscard]] NativeError	   beginHost( std::shared_ptr<const SignedIndexRecordLookup> lookup,
											 IndexLookupContext current, IndexScanHostSnapshot host,
											 WindowsHostPlatformObserver			 observer,
											 std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
	/**
	 * @brief 実claim済みtaskを再確認してdispatch直前のhostを再観測します
	 * @param[in] task 当該issuerがclaimした未変更taskです
	 * @param[in] current 元scanの全contextです
	 * @param[in] nowUtc 原全期限を確認するUTCです
	 * @return 全record/所有/host一致0。変化/観測失敗は同contextへ不可逆に拒否を残します
	 */
	[[nodiscard]] NativeError	   revalidateHostForAcquisition(
			 const OfficialPreparationTask &task, IndexLookupContext current,
			 std::optional<std::chrono::sys_seconds> nowUtc) ;
	/**
	 * @brief 元host拒否を上書きしない診断値を借用せず返します
	 * @param[in] current 診断対象の完全contextです
	 * @return 最初の拒否、又は現contextの初回判定です。別contextは空です
	 */
	[[nodiscard]] std::optional<IndexHostGateResult> hostDecision(
		IndexLookupContext current) const noexcept ;
	/**
	 * @brief 私有issuerと未開始計画を失効します。原snapshotを修復・削除しません
	 */
	void					  invalidate() noexcept ;
	/**
	 * @brief 新しい取得だけを閉鎖し、消費済み成功grantの同期限内再検証を保持します
	 */
	void					  closeAcquisitionForInstall() noexcept ;
	/**
	 * @brief 元lookupの関係位置から取得対象を再記述します
	 * @param[in] relationIndex 元lookup内の0起点位置。公開tupleは受理しません
	 * @param[in] current 現worker context
	 * @param[in] nowUtc 信頼UTC
	 * @param[in] limits 共通preparationの有限予算
	 * @param[out] description 全条件成功時だけtarget。失敗時は不足理由を保持します
	 * @param[in] firmwareDeviceName 同じスキャンの機器名です。機器別の新しい確認対象を表示するために使います
	 * @return 記述成功0、未知・未対応E_NOTIMPL、stale・権限・期限等の拒否HRESULT
	 */
	[[nodiscard]] NativeError describe( std::size_t relationIndex, IndexLookupContext current,
									   std::optional<std::chrono::sys_seconds> nowUtc,
									   const OfficialPreparationLimits		  &limits,
									   SignedIndexPreparationDescription	  &description,
									   std::wstring_view firmwareDeviceName = {}) ;
	/**
	 * @brief 元認証規約を有限共通GETで取得し、全文と出典をRAMの記述へ固定します
	 * @param[in] relationIndex 私有lookupの原関係位置です
	 * @param[in] current 元scanの全contextです
	 * @param[in] utc 信頼UTCの取得処理です。送信前と受信後の期限を再照合します
	 * @param[in,out] client 同workerの完全共通HTTP依存です。公開URLは受理しません
	 * @param[in] cancellation 同scanの協調停止です
	 * @return 全原byte/全文成立0、未対応/変更/失効は元HRESULTです
	 * @note 同意を発行せず、未取得本文を空の同意不要へ変更しません
	 */
	[[nodiscard]] NativeError readTermsText(
		std::size_t relationIndex, IndexLookupContext current,
		const std::function<std::optional<std::chrono::sys_seconds>()> &utc,
		OfficialHttpClient &client, const HttpCancellationCallback &cancellation) ;
	/**
	 * @brief 実claim済みtaskから同じRecordScopedDownloadGrantを一回発行します
	 * @param[in] preparation 実active taskを所有する同worker session
	 * @param[in] task 利用者承認後の未変更task
	 * @param[in] current 現worker context
	 * @param[in] nowUtcSeconds 発行直前の信頼UTC秒
	 * @param[out] grant 未発行object。成功時だけ同じgrant状態機械へ進めます
	 * @return 全再照合成功0、改変・再使用・失効・期限は拒否HRESULT
	 */
	[[nodiscard]] NativeError claimApprovedRecord( OfficialPreparationSession	&preparation,
												  const OfficialPreparationTask &task,
												  IndexLookupContext			 current,
												  std::uint64_t					 nowUtcSeconds,
												  RecordScopedDownloadGrant		&grant) ;
	/**
	 * @brief 共通取得sealを元recordと独立照合し、共通内容検査入力を生成します
	 * @param[in] task 発行済みgrantと同じ実task
	 * @param[in] current 現worker context
	 * @param[in] nowUtcSeconds 封印入力確認直前の信頼UTC秒
	 * @param[in] session 元取得sealのissuer
	 * @param[in] workspace 元保護fileを所有する領域
	 * @param[in] evidence 公開結果から構築できない元取得seal
	 * @param[out] hint 全成功時だけ元index／record／実archiveの期待値
	 * @param[out] input 全成功時だけ既存DriverArchiveInput。失敗時は空
	 * @return 全実byteとrecord結合成功0、元HRESULTまたは拒否HRESULT
	 * @note 内容署名・Windows適合・導入は別の共通検査で行います
	 * WiXの場合は元バイトとハッシュの結合だけを返し、従来形式のINF指定は生成しません
	 */
	[[nodiscard]] NativeError bindInspectionInput(
		const OfficialPreparationTask &task, IndexLookupContext current,
		std::uint64_t nowUtcSeconds, const OfficialAcquisitionSession &session,
		const OfficialDownloadWorkspace &workspace, const OfficialAcquiredFileEvidence &evidence,
		IndexedDriverArchiveHint &hint, DriverArchiveInput &input) const ;

private:
	/**
	 * @brief 元取得の保護ファイルと署名レコードから検査入力を作ります
	 * @param[in] task 同じ発行済み元taskです
	 * @param[in] current 同じスキャンのcontextです
	 * @param[in] nowUtcSeconds 元期限を確認する時点です
	 * @param[in] session 封印の元issuerです
	 * @param[in] workspace 元保護ファイルの領域です
	 * @param[in] evidence 保持済み取得封印です
	 * @param[out] hint 元索引とレコード・配布物の固定値です
	 * @param[out] input 同じ保護ファイルの検査入力です
	 * @param[in] observeHost 端末条件をこの呼出しで再観測する場合trueです
	 * @return 全照合成功0、元拒否はHRESULTです
	 * @note falseで借りた入力は、後段の明示再観測まで候補発行・変更へ使いません
	 * WiXは元の公式ページ照合を要求し、observeHostがtrueの場合に元ホストと端末を再観測します
	 */
	[[nodiscard]] NativeError bindInspectionInputImpl(
		const OfficialPreparationTask &task, IndexLookupContext current,
		std::uint64_t nowUtcSeconds, const OfficialAcquisitionSession &session,
		const OfficialDownloadWorkspace &workspace, const OfficialAcquiredFileEvidence &evidence,
		IndexedDriverArchiveHint &hint, DriverArchiveInput &input, bool observeHost) const ;
	enum class AuthorityProfile ;	// 後段で定義する既固定profileです
	/** @brief 同contextの最初のhost拒否だけを保持するprivate値です */
	struct HostRejection {
		/// 三IDを完全一致で照合します
		IndexLookupContext	context ;
		/// 後続成功で消さない原観測とローカル判定です
		IndexHostGateResult decision ;
	} ;
	/**
	 * @brief 全元binding検証後だけ呼ぶhost再観測です
	 * @param[in] current 元scanの全contextです
	 * @return 既拒否/変化/失敗は拒否し、callbackの原診断を保持します
	 * @note 同workerの論理const取消しだけで、原snapshot/observer/issuerを置換しません
	 */
	[[nodiscard]] NativeError reobserveHost( IndexLookupContext current) const ;
	/**
	 * @brief 元contextへ最初の拒否を不可逆に保存します
	 * @param[in] current 完全contextです
	 * @param[in] decision 原native値と別のローカル拒否です
	 * @return 保存した元拒否です。確保不能でも全取得を閉じます
	 * @note 拒否三fieldと同所有の取得能力だけを取り消し、thread安全性を追加しません
	 */
	[[nodiscard]] NativeError rejectHost( IndexLookupContext			current,
										 const IndexHostGateResult &decision) const noexcept ;
	/**
	 * @brief 内部固定profileで同じfullhost開始を行います
	 * @param[in] lookup 原lookupです
	 * @param[in] current 全contextです
	 * @param[in] host 同scan原観測です
	 * @param[in] observer 明示再観測です
	 * @param[in] nowUtc 原期限UTCです
	 * @param[in] profile 既product/fixture区分です
	 * @return 全開始成立0、他は拒否です
	 */
	[[nodiscard]] NativeError beginHostImpl( std::shared_ptr<const SignedIndexRecordLookup> lookup,
											IndexLookupContext current, IndexScanHostSnapshot host,
											WindowsHostPlatformObserver				observer,
											std::optional<std::chrono::sys_seconds> nowUtc,
											AuthorityProfile profile) noexcept ;
	/**
	 * @brief 同lookupの配布tupleを比較します。原期限検証は呼出側でも省きません
	 * @param[in] task 新しい明示対象です
	 * @param[in] sourceTask 元TRANSFER対象です
	 * @return 原配布tupleが完全一致した場合だけtrueです
	 */
	[[nodiscard]] bool		  matchesRetainedBody( const OfficialPreparationTask &task,
												  const OfficialPreparationTask &sourceTask) const ;
	/**
	 * @brief 新LOCAL taskのscopeへ同owned fileを結合します
	 * @param[in] task 新しい明示承認taskです
	 * @param[in] sourceTask 元所有を説明する過去TRANSFER taskです
	 * @param[in] current 元scan contextです
	 * @param[in] nowUtcSeconds 信頼UTC秒です
	 * @param[in] session 元file sealのissuerです
	 * @param[in] workspace 元保護領域です
	 * @param[in] evidence 元fileの不変sealです。現在の読取許可ではありません
	 * @param[in] localInspection 当該LOCAL claimの照合票です
	 * @param[out] hint 新recordの原selectorです
	 * @param[out] input 元ownerからの非所有byte入力です
	 * @param[in] observeHost 再利用元と再利用先のホストをこの呼出しで確認する場合trueです
	 * @return 原A/B期限・所有・全tuple成立0です。通信/旧grant再消費は行いません
	 */
	[[nodiscard]] NativeError bindRetainedInspectionInput(
		const OfficialPreparationTask &task, const OfficialPreparationTask &sourceTask,
		IndexLookupContext current, std::uint64_t nowUtcSeconds,
		const OfficialAcquisitionSession &session, const OfficialDownloadWorkspace &workspace,
		const OfficialAcquiredFileEvidence	  &evidence,
		const OfficialLocalInspectionEvidence &localInspection, IndexedDriverArchiveHint &hint,
		DriverArchiveInput &input, bool observeHost = true) const ;
	/** @brief 製品policyと固定内部fixture policyを分離します */
	enum class AuthorityProfile {
		/// 通常は固定配布の独立取得集合、local受入は独立optionの固定集合です
		PRODUCT,
		/// 隔離RAM署名fixtureだけの固定fixture-main／revision1です
		INTERNAL_RAM_FIXTURE
	} ;
	/** @brief 承認済みのWiX検査taskに結ぶ公式ページの確認時刻です */
	struct WixPageVerification {
		/// 元機器、元レコードと取得範囲を結合した実taskです
		OfficialPreparationTask	 task ;
		/// 公式ページと元アンカーの照合が完了した信頼UTCです
		std::chrono::sys_seconds verifiedAtUtc ;
	} ;
	/** @brief 一回の記述と実claimを元関係位置へ結合します */
	struct PreparedBinding {
		/// 元lookupの関係位置
		std::size_t							   relationIndex{} ;
		/// Workerが記述した全対象snapshot
		OfficialPreparationTarget			   target ;
		/// 記述時の共通予約予算
		OfficialPreparationLimits			   limits ;
		/// 実claim後だけ存在するtoken。同recordの再発行を拒否します
		std::optional<OfficialPreparationTask> claimedTask ;
		/// 元taskから発行した同issuer内のexact grant ID。未発行は0です
		std::uint64_t						   grantId{} ;
		/// 同完全payload根拠と全取得policyへ結合した原関係位置。既存lookup最大32768枠内です
		std::vector<std::size_t>			   relationIndices ;
		/// 新LOCAL taskから検査した場合だけtrueです。grant発行と排他です
		bool								   localInspectionClaimed{} ;
		/// 再確認対象の規約を取得前に照合した元操作です。未照合は0です
		OperationId							   recheckedTermsOperation{} ;
		/// 同時に照合済みの元計画IDです
		std::uint64_t						   recheckedTermsPlan{} ;
		/// WiXの公式アンカーを同じ検査専用taskで確認した場合だけ保持します
		std::optional<WixPageVerification>	   wixPageVerification ;
	} ;
	/** @brief 原recordへ結合した有限全文のRAM所有値です */
	struct TermsSnapshot {
		/// 本文を認証した同じ元レコードの位置です
		std::size_t	 recordIndex{} ;
		/// 正確な全文とrevisionです。永続化しません
		std::wstring text ;
		/// 原公開revisionまたは全文の算出revisionです
		std::wstring revision ;
	} ;
	/**
	 * @brief 内部固定profileを使って同じ開始検査を行います
	 * @param[in] lookup 保存済み元lookup
	 * @param[in] current 現context
	 * @param[in] targetOs 既知OS分類
	 * @param[in] nowUtc 信頼UTC
	 * @param[in] profile 外部設定ではない内部固定policy区分
	 * @param[in] hostAware fullhost入口だけがServer enumを開始へ渡します
	 * @return 全開始検査成功0、それ以外は拒否HRESULT
	 */
	[[nodiscard]] NativeError beginImpl( std::shared_ptr<const SignedIndexRecordLookup> lookup,
										IndexLookupContext current, IndexTargetOs targetOs,
										std::optional<std::chrono::sys_seconds> nowUtc,
										AuthorityProfile profile, bool hostAware = false) noexcept ;
	/** @brief 同じ索引関係を使用する目的です */
	enum class RecordValidation {
		/// 認証済み元レコードと所有者を結びます
		OWNERSHIP,
		/// 取得前に表示する条件と規約本文を検査します
		PREPARATION,
		/// 本体の転送・保持バイトの利用・導入を検査します
		ACQUISITION
	} ;
	/**
	 * @brief 元tuple・descriptor・期限・通常driver条件を再照合します
	 * @param[in] relationIndex 元関係位置
	 * @param[in] current 現context
	 * @param[in] nowUtc 信頼UTC
	 * @param[out] reason 失敗時の具体的理由。成功時は空
	 * @param[in] purpose 現在の検証目的です。確認計画は本体の取得権限を発行しません
	 * @return 全条件成立0、それ以外は拒否または保留HRESULT
	 */
	[[nodiscard]] NativeError validateRecord(
		std::size_t relationIndex, IndexLookupContext current,
		std::optional<std::chrono::sys_seconds> nowUtc, std::string &reason,
		RecordValidation purpose = RecordValidation::ACQUISITION) const ;
	/**
	 * @brief 私有共有bindingの全原recordと期限を再確認します
	 * @param[in] binding 同issuerが記述した未変更の取得binding
	 * @param[in] current 元scan context
	 * @param[in] nowUtc 信頼UTC
	 * @param[out] reason 最初の拒否理由
	 * @param[in] purpose 条件表示又は取得権限を検査する用途です
	 * @return 全原関係成立0、それ以外は元HRESULTです
	 */
	[[nodiscard]] NativeError validateBinding(
		const PreparedBinding &binding, IndexLookupContext current,
		std::optional<std::chrono::sys_seconds> nowUtc, std::string &reason,
		RecordValidation purpose = RecordValidation::ACQUISITION) const ;
	/**
	 * @brief 規約を画面用に保存するか、同じ承認済み本文に対して新しい応答を検査します
	 * @param[in] relationIndex 現スキャンの元関係位置です
	 * @param[in] current 現操作の元contextです
	 * @param[in] utc 送信と検査前後に使う信頼UTCです
	 * @param[in,out] client 元公式URLだけを取得する共通HTTPです
	 * @param[in] cancellation 同処理の停止照会です
	 * @param[in] recheck trueはZIPまたは二段リンク規約の取得前検査です。既表示の本文と改訂を変更しません
	 * @return 同じ原証拠と規約の照合が成立した場合0です
	 */
	[[nodiscard]] NativeError readTermsTextImpl(
		std::size_t relationIndex, IndexLookupContext current,
		const std::function<std::optional<std::chrono::sys_seconds>()> &utc,
		OfficialHttpClient &client, const HttpCancellationCallback &cancellation, bool recheck) ;
	/**
	 * @brief 承認済み操作で再確認が必要な規約の形式を判定する
	 * @param[in] terms 同じ署名記述子の元規約
	 * @return ZIP内の明示規約または二段リンク用の場合true
	 */
	[[nodiscard]] static bool requiresApprovedTermsRecheck(
		const IndexAcquisitionTerms &terms) noexcept ;
	/**
	 * @brief 所有中の承認済み操作へ規約の再確認を結びます
	 * @param[in,out] preparation 元承認状態を所有するsessionです。新しい承認は発行しません
	 * @param[in] task 実active taskです
	 * @param[in] current 現スキャンの全contextです
	 * @param[in] utc 前後の期限を検査する信頼時計です
	 * @param[in,out] client 同じ元公式URLを再確認する共通HTTPです
	 * @param[in] cancellation 停止又は回線条件の失効を検査します
	 * @return 元規約の再確認に成功した場合0です
	 */
	[[nodiscard]] NativeError recheckApprovedTerms(
		OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
		IndexLookupContext												current,
		const std::function<std::optional<std::chrono::sys_seconds>()> &utc,
		OfficialHttpClient &client, const HttpCancellationCallback &cancellation) ;
	/**
	 * @brief 承認済みのWiX検査taskへ現在の公式ページと元アンカーの照合を結びます
	 * @param[in] preparation 実active taskを所有するsessionです
	 * @param[in] task 一台だけに結合した検査専用の承認済みtaskです
	 * @param[in] current 元スキャンの全contextです
	 * @param[in] utc 送信前、送信中、受信後に原期限と時計逆行を検査する信頼時計です
	 * @param[in,out] client 同じ元公式ページを有限HTTPSで取得する共通HTTPです
	 * @param[in] cancellation 回線、共有待機又は取消しによる停止を確認します
	 * @return 同じ公式ページの実アンカーを確認した場合0です。拒否時はHRESULTです
	 * @note 原観測ハッシュを変更せず、規約同意や導入許可を発行しません
	 */
	[[nodiscard]] NativeError verifyWixInspectionPage(
		OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
		IndexLookupContext												current,
		const std::function<std::optional<std::chrono::sys_seconds>()> &utc,
		OfficialHttpClient &client, const HttpCancellationCallback &cancellation) ;
	/**
	 * @brief 機種別の原レコードを同スキャンの初回型番と現在の端末観測で確認します
	 * @param[in] record 元関係を照合した後の同署名レコードです
	 * @param[in] current その関係の元スキャンcontextです
	 * @return 機種別条件なし又は初回と現在の一致で0、変化・不明で当該関係の拒否です
	 */
	[[nodiscard]] NativeError reobservePlatformMachine( const IndexDistributionRecord &record,
													   IndexLookupContext current) const ;
	/**
	 * @brief 元承認の機種、完全Hardware ID又は必須群を現在の属性から再確認する
	 * @param[in] record 同じ取得対象の元署名レコードです
	 * @param[in] target 元承認の変更不可な取得対象です
	 * @param[in] current 同じ操作・スキャン・インベントリです
	 * @return 一致又は端末条件なしは0、変化や観測不能は元の拒否です
	 * @note 本体送信・検査の入口が、承認と元レコードを照合した後に使います
	 */
	[[nodiscard]] NativeError reobservePreparedDevice( const IndexDistributionRecord	  &record,
													  const OfficialPreparationTarget &target,
													  IndexLookupContext current) const ;
	friend struct signed_index_acquisition_detail::Access ;
	friend class RecordScopedDownloadGrant ;
	friend class SignedIndexCandidateBindingSession ;
	friend class SignedIndexScanSession ;
	/// 生存能力を表す独立issuer。Grantは弱参照だけを保持します
	std::shared_ptr<const std::byte>			   issuer_ ;
	/// Issuerと独立した新規取得開始可否。閉鎖後は再開せず新scanを必要とします
	std::shared_ptr<bool>						   acquisitionOpen_ ;
	/// 同scanの非公開構築lookupと原保存snapshot
	std::shared_ptr<const SignedIndexRecordLookup> lookup_ ;
	/// 全発行対象の同worker context
	IndexLookupContext							   context_ ;
	/// 同scanの初回hostです。invalidateで解放します
	std::optional<IndexScanHostSnapshot>		   host_ ;
	/// 同workerの明示observerです。空を補完しません
	WindowsHostPlatformObserver					   hostObserver_ ;
	/// 機種条件付き行に必要な同workerの観測関数です。空は再確認不能です
	std::function<IndexPlatformMachineIdentity()>  platformMachineObserver_ ;
	/// 同じスキャンの端末を一台ずつ再観測する所有Providerをworker内で借用します
	const DriverStoreProvider					  *platformDeviceStore_{} ;
	/// 初回対応判定です。原API値を所有します
	IndexHostGateResult							   initialHostDecision_ ;
	/// 同contextの初回snapshotはinvalidate/rebeginでも置換しません
	std::vector<IndexScanHostSnapshot>			   initialHosts_ ;
	/// full contextごとの最初の拒否です。invalidate/rebeginで消しません
	mutable std::vector<HostRejection>			   rejectedHosts_ ;
	/// 拒否保存の確保不能でも元拒否を失わない固定領域です
	mutable std::optional<HostRejection>		   emergencyHostRejection_ ;
	/// 拒否記録の確保不能後は新しい権限を作りません
	mutable bool								   hostRejectionStorageFailed_{} ;
	/// 現workerが確認した対象OS分類
	IndexTargetOs								   targetOs_{IndexTargetOs::WINDOWS_11} ;
	/// 最大256件の記述と一回claimの元binding
	std::vector<PreparedBinding>				   bindings_ ;
	/// 最大256本文かつplan全文上限以内の原RAM snapshotです
	std::vector<TermsSnapshot>					   terms_ ;
	/// 同issuer内で単調増加するgrant ID
	std::uint64_t								   nextGrantId_{1U} ;
} ;
} // namespace drivercrate
