//------------------------------------------------------------------------------
/**
 * @file metadata_ui_fixture.h
 * @brief 専用Win32画面試験の非通信Provider契約。
 * @version 01.16.00
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  実device・network・復旧操作を持たないUI fixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  通常scanの協調取消し待機fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  真署名・実byte・完全HTTPによる通常索引UI入力を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  実INF閉包と完全policy一致/欠損の有限入力を宣言。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/10/12  規約GETの固定headerとCookie禁止の観測値を保持。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  元二recordの出典・公開revision差を独立入力へ固定。
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  元固定28条件の必要構成byte入力を宣言。
 * Ver.01.07.00 Shunji Ogawa  2026/10/13  元31条件と固定19選択節/import条件の契約を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/13  元50入力を保持するWin32 service38条件を宣言。
 * Ver.01.08.01 Shunji Ogawa  2026/10/13  元88を維持して不正binary位置三条件を宣言。
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  元91と新Win32必要形式24条件の入力範囲を明示。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  元117入力と新媒体24条件の完全byte範囲を明示。
 * Ver.01.11.00 Shunji Ogawa  2026/10/13  媒体root-onlyと選択節依存の有限回帰入力を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/13  固定root-onlyと15選択依存入力の範囲を説明。
 * Ver.01.13.00 Shunji Ogawa  2026/10/14  通常取得commandの共通HTMLと第二payload拒否を固定。
 * Ver.01.13.01 Shunji Ogawa  2026/10/15  同workerのgrant直前に限る同期HTTP観測を説明。
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  追加INFなしの選択Needs条件の入力範囲を明示。
 * Ver.01.15.00 Shunji Ogawa  2026/10/15  33INF正例とarchive128/129境界の完全閉包入力を分離。
 * Ver.01.16.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * </pre>
 *
 * @note 製品EXEへ組み込まず、内部UI試験だけで使用する。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/provider_worker.h"
#include "platform/provider_worker_index_internal.h"

#include <atomic>
#include <array>
#include <cstdint>
#include <memory>
#include <semaphore>
#include <functional>
#include <string>

namespace drivercrate::test {

/** @brief 画面へ返す合成終端。実Providerや回線条件を表さない。 */
enum class MetadataUiScenario {
	/// 三現在行と一record・二deviceの情報行を返す。
	INFORMATION,
	/// 適格二deviceへ問い合わせたがrecordがない。
	NO_INFORMATION,
	/// 表示probe対象がない。
	NOT_APPLICABLE,
	/// 選択providerの合成検索失敗。
	FAILED,
	/// 選択providerの合成metadata形式拒否。
	REJECTED,
} ;

/** @brief UI threadとworkerの間で共有する非機密counterと有限待機信号。 */
struct MetadataUiState {
	/// 次の一操作へ注入する結果。
	std::atomic<MetadataUiScenario> scenario{MetadataUiScenario::INFORMATION} ;
	/// 通常scanを要求した回数。情報検索から自動発行されてはならない。
	std::atomic_uint32_t			normalCalls{} ;
	/// 通常scanが同じoperationの取消しを観測した回数。
	std::atomic_uint32_t			normalCancelled{} ;
	/// 専用scan要求回数。
	std::atomic_uint32_t			metadataCalls{} ;
	/// 選択された公式fake callback回数。
	std::atomic_uint32_t			officialCalls{} ;
	/// 復旧service呼出し回数。常に0を期待する。
	std::atomic_uint32_t			restoreCalls{} ;
	/// 通常scan後だけに期待する準備plan照会。情報検索では0。
	std::atomic_uint32_t			planCalls{} ;
	/// 取得準備・plan・導入の誤呼出し回数。
	std::atomic_uint32_t			forbiddenCalls{} ;
	/// 同期pointへ入った状態。取消し待ちの画面を確認する。
	std::atomic_bool				waiting{} ;
	/// 次の公式callbackだけを明示解除まで待機させる。
	std::atomic_bool				holdNext{} ;
	/// 次の通常scanだけを取消し照会または明示解除まで待機させる。
	std::atomic_bool				holdNextNormal{} ;
	/// UIがworkerの有限待機を解除する。
	std::binary_semaphore			release{0} ;
	/// Fixture待機が5秒で期限切れになった回数。
	std::atomic_uint32_t			waitTimeouts{} ;
} ;

/**
 * @brief 非通信Providerだけを生成するfactoryを返す。
 * @param[in] state Worker終了まで両threadが共有する状態。
 * @return 実Providerへfallbackしない生成関数。
 */
ProviderFactory		metadataUiProviderFactory( std::shared_ptr<MetadataUiState> state) ;

/**
 * @brief Windows復旧APIを使用しないservice factoryを返す。
 * @param[in] state 誤呼出しcounterの共有先。
 * @return 常に合成失敗を返すserviceの生成関数。
 */
RestorePointFactory metadataUiRestoreFactory( std::shared_ptr<MetadataUiState> state) ;

/** @brief 同operation終端後に読む完全fake HTTPの非機密観測です。 */
struct SignedIndexUiHttpObservation {
	/// Grant限定GETの実fake送信回数。
	std::uint32_t sends{} ;
	/// Fake HTTP handle生成数。
	std::uint32_t opens{} ;
	/// 同handle解放数。
	std::uint32_t closes{} ;
	/// Proxy・HTTPS・credential非送信・有限timeoutを全callで確認した状態。
	bool		  safe{} ;
	/// 規約GETでCookie送受信を無効化した実回数。
	std::uint32_t cookieDisabled{} ;
	/// 規約GETで固定cache再検証headerを設定した実回数。
	std::uint32_t cacheControlHeaders{} ;
} ;
/** @brief 真署名隔離storeと実原ZIPを同worker寿命へ保持する内部UI入力です。 */
struct SignedIndexUiInput {
	/// Refresh呼出し数/load数/初回empty/実commitを同worker終端後だけ観測します。
	std::function<std::array<std::uint32_t, 4U>()> observeRefresh ;
	/// 境界入力の実ZIP列挙で数えたINF数です。通常入力は未計測の0です。
	std::uint32_t								   originalArchiveInfCount{} ;
	/// 同実ZIPで非空INFと同名CAT/SYSが存在する基本閉包数です。内容合格数ではありません。
	std::uint32_t								   originalArchiveBasicClosureCount{} ;
	/// 元署名・UTC・完全HTTPを所有するcallback。外部成功statusを入力しません。
	provider_worker_index_detail::Services		   services ;
	/// 非空INF/SYS/人工CATの元ZIP。実抽出／hashへ渡します。
	std::string									   zip ;
	/// 署名recordへ結ぶ元payloadです。標準INF用の原ZIPとは別に保持します。
	std::string									   payload ;
	/// 同worker終端後のHTTP呼出し観測。原IDやURLを返しません。
	std::function<SignedIndexUiHttpObservation()>  observeHttp ;
} ;
/** @brief Code前の有限caseへ固定する元形式・規約・具体的条件です。 */
struct SignedIndexUiOptions {
	/// P5だけが空の隔離storeへの実commitをworker refresh callbackまで遅延します。
	bool								 deferredRefresh{} ;
	/// 基本INF閉包数の明示指定です。0は従来入力、境界試験だけ128または129を指定します。
	std::uint32_t						 archiveInfCount{} ;
	/// 元C01～C169と追加memberなしC178～C180の依存byte条件です。0は従来入力です。
	std::uint32_t						 requiredComponentCase{} ;
	/// 元payload形式です。未知installerの展開は行いません。
	IndexPayloadFormat					 format{IndexPayloadFormat::ZIP} ;
	/// 正確な全文と出典を要求する元規約です。
	bool								 termsRequired{} ;
	/// 原page・選択文書・全文・改訂・payloadを共通HTML profileへ結ぶ条件です。
	bool								 htmlTerms{} ;
	/// 原規約hashと異なる同長HTTP byteだけを返す拒否条件です。
	bool								 corruptTerms{} ;
	/// 元payload hashと異なる同長HTTP byteだけを返す拒否条件です。
	bool								 corruptPayload{} ;
	/// 二つの独立targetの第二payloadだけを同長hash差へ固定します。
	bool								 corruptSecondPayload{} ;
	/// 元recordの具体的条件です。未指定は明示空集合です。
	std::optional<IndexPrerequisiteKind> prerequisite ;
	/// 対応するOS確認以外の未知LOCAL_CHECKを保持する条件です。
	bool								 unknownLocal{} ;
	/// 予定範囲を未確認として保持するinstaller拒否条件です。
	bool								 wrongScope{} ;
	/// 二recordの第二source subjectだけを別の署名元source IDへ固定します。
	bool								 secondTermsSubject{} ;
	/// 二recordの第二公開terms revisionだけをOriginal 2.0へ固定します。
	bool								 secondTermsRevision{} ;
} ;
/** @brief 実CNG原byte署名から実commit/reloadした一または二record入力を作ります。
 * @param[in] partial 異なる二deviceの二recordを生成する場合trueです。
 * @param[in] shared 二recordの完全取得descriptorを一致させる場合trueです。
 * @param[in] multiInf 二つの独立した基本INF/CAT/member閉包を含める場合trueです。
 * @param[in] capacityBoundary 旧32件期待を超える33完全閉包の正常入力を生成する場合trueです。
 * @param[in] unknownDependency 元INFへ未確認の具体的外部依存を含める場合trueです。
 * @param[in] unknownPayloadEvidence 原recordのfull digest/size申告をUNKNOWNに保つ場合trueです。
 * @param[in] options 事前固定した形式・規約全文・具体的条件です。
 * @return 実認証を通した隔離storeと完全低位HTTP。生成失敗は例外です。
 * @throws std::runtime_error 元署名・schema・保護storeまたは有限fixtureの生成が失敗した場合。
 * @throws std::bad_alloc 所有する入力またはcallbackの確保が失敗した場合。
 * @note 秘密鍵はRAMだけに保持し、製品trust・実network・実inventoryを使いません。
 * CallbackはstoreとHTTP fixtureをworker停止まで共有所有します。observeHttpは元終端eventの
 * 取得またはworker停止の同期完了後、または同workerのgrant直前の同期観測中だけ呼びます。
 * HTTP callと並行しない条件で、同じfixtureの実安全option/header数を返します。
 */
[[nodiscard]] SignedIndexUiInput makeSignedIndexUiInput( bool partial, bool shared = false,
														bool multiInf				 = false,
														bool capacityBoundary		 = false,
														bool unknownDependency		 = false,
														bool unknownPayloadEvidence	 = false,
														SignedIndexUiOptions options = {}) ;

} // namespace drivercrate::test
