//------------------------------------------------------------------------------
/**
 * @file local_collector_http_tests.h
 * @brief 有限DNS・制御付き公式GETの非通信試験入口です。
 * @version 01.28.00
 * @date 2026/09/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  有限DNS・共通HTTP制御接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  所有workerからv3保存までの非通信試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  新射影予約と偽HTTPの本文受入入口を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/01  未応答次世代予約の独立非通信試験入口を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/01  部分開始の独立保存復旧試験入口を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/01  日次切替の全保存prefix・再中断・拒否試験を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/01  末尾完了の固定prefix・再停止・拒否試験を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/01  正常300世代と301開始拒否の専用入口を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/01  本番299操作と未受領枠の専用非通信入口を追加。
 * Ver.01.08.01 Shunji Ogawa  2026/10/01  timeout試験を二世代の短い基礎接続へ分離。
 * Ver.01.09.00 Shunji Ogawa  2026/10/01  合成300操作の独立境界選択を追加。
 * Ver.01.09.01 Shunji Ogawa  2026/10/01  既定16要求と上限専用四要求の検査範囲を区別。
 * Ver.01.10.00 Shunji Ogawa  2026/10/01  新requestのCACHE増加・未受領二枠復旧入口を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/01  大量新requestの独立段階測定を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/01  全完了容量境界と通常起動の独立選択を追加。
 * Ver.01.13.00 Shunji Ogawa  2026/10/02  全完了raw封印の独立非通信入口を追加。
 * Ver.01.14.00 Shunji Ogawa  2026/10/02  同親historyのv3保存・個別根拠検査入口を追加。
 * Ver.01.15.00 Shunji Ogawa  2026/10/02  現区間の一致／同時借用検査入口を追加。
 * Ver.01.16.00 Shunji Ogawa  2026/10/02  実根拠切替準備の非保存検査入口を追加。
 * Ver.01.17.00 Shunji Ogawa  2026/10/02  HTTP実所有閉鎖の独立検査入口を追加。
 * Ver.01.18.00 Shunji Ogawa  2026/10/02  同親保持・保存role先払いの非保存試験を追加。
 * Ver.01.19.00 Shunji Ogawa  2026/10/02  切替準備実保存と同一hold再開の独立試験を追加。
 * Ver.01.20.00 Shunji Ogawa  2026/10/02  新子69role保存と同一hold再開の独立試験を追加。
 * Ver.01.21.00 Shunji Ogawa  2026/10/02  専用初期ROOTのcarry・実保存試験を追加。
 * Ver.01.22.00 Shunji Ogawa  2026/10/02  元head保持・親head実保存の独立試験を追加。
 * Ver.01.23.00 Shunji Ogawa  2026/10/02  元実保存byteの回復decoder独立試験を追加。
 * Ver.01.24.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.25.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * Ver.01.26.00 Shunji Ogawa  2026/10/03  初回最終head読取りcodecの独立非通信入口を追加。
 * Ver.01.27.00 Shunji Ogawa  2026/10/03  実handle初回readerの独立非通信入口を追加。
 * Ver.01.28.00 Shunji Ogawa  2026/10/26  公開hash/指紋訂正だけの限定選択を追加。
 * </pre>
 *
 * @note 通信APIをfakeへ置換し、公式parserと一時保護台帳を検証します。実通信・導入は実行しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "test_framework.h"
#include <filesystem>
#include <functional>
namespace drivercrate {
struct CollectorProjectedCampaignDefinition ;
}
namespace drivercrate::test {
/** @brief 実保存初回readyの非作成reader・寿命・再入と直接raw改変を検査します。
 * @param[in,out] context 新枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID領域の生成関数です。
 * @param[in] definitionFactory 元二sourceのfake公開入力です。
 * @note 旧payloadの全検査・R01～R15全受入・監督／HTTP再開は測定しません。
 */
void runCollectorSegmentReadContextTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 実保存frameの初回readyとcarry／checkpoint結合を非通信検査します。
 * @param[in,out] context 新独立枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID領域の保護fixture生成元です。
 * @param[in] definitionFactory 二sourceの架空公開入力です。
 * @note 実handle readerの能力発行、最大実規模、通常CLI／HTTP再開は検査しません。
 */
void runCollectorSegmentInitialReadCodecTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 実保存byteと回復decoderの四状態・改変拒否を非通信検証します。
 * @param[in,out] context 新枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID祖先の保護fixture生成関数です。
 * @param[in] definitionFactory 元二sourceのfake公開入力です。
 * @note 実handle再発行・再起動回復・通常CLIの合格ではありません。
 */
void runCollectorSegmentRecoveryCodecTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;

/** @brief 全能力解放後の保護実file回復と親head不足suffixを検査します。
 * @param[in,out] context 決定的な非通信assertion集計です。
 * @param[in] rootFactory 自作GUID領域だけの生成元です。
 * @param[in] definitionFactory 元二sourceの架空公開入力です。
 */
void runCollectorSegmentRecoveryStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief ROOT未保存の全連続prefix回復・不足保存と改変拒否を非通信検査します。
 * @param[in,out] context 新独立枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID領域だけの生成元です。
 * @param[in] definitionFactory 元二sourceの架空公開入力です。
 * @note 実OS再起動・電源断・通常収集とdirectory作成穴の修復は検査しません。
 */
void runCollectorSegmentPreparationRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 元head保持記録と二親head保存・停止再開を非通信検証します。
 * @param[in,out] context 新枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID祖先を含む保護領域生成関数です。
 * @param[in] definitionFactory 元二sourceのfake公開入力です。
 * @note 同じ生存予約限定です。再起動回復・通常reader／HTTPは検査しません。
 */
void runCollectorParentHeadStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 実66像の非変更carryと専用初期ROOT実保存・改変拒否を検証します。
 * @param[in,out] context 独立新枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID祖先を含む保護領域生成関数です。
 * @param[in] definitionFactory 元二sourceのfake公開入力です。
 * @note 親head反映・再起動回復・通常reader／HTTP接続は検査しません。
 */
void runCollectorInitialRootStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 私有新子の全69保存地点と同一hold再開を非通信検証します。
 * @param[in,out] context 新枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID領域の生成関数です。
 * @param[in] definitionFactory 元二sourceの架空入力です。
 * @note 新history ROOT／親head切替・再起動回復は測定しません。
 */
void runCollectorNewSegmentStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 固定切替準備の実保存窓・改変拒否と同一hold再開を非通信検査します。
 * @param[in,out] context 新枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID領域の生成関数です。
 * @param[in] definitionFactory 元二sourceの架空入力です。
 * @note 新子／ROOT／親head切替・再起動回復は測定しません。
 */
void runCollectorSegmentPreparationStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 同親handle寿命と固定保存role容量を独立非通信検査します。
 * @param[in,out] context 新枠だけのassertion集計です。
 * @param[in] rootFactory 自作GUID祖先を含む領域生成関数です。
 * @param[in] definitionFactory 元二sourceの架空公開入力です。
 * @note 新子作成・実保存／回復・実HTTPは測定しません。
 */
void runCollectorSegmentStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 実pool／permit／thread寿命と排他的HTTP停止を非通信検査します。
 * @param[in,out] context 独立枠のassertion集計。
 * @param[in] rootFactory 自作保護領域の生成関数。
 * @param[in] definitionFactory 元二sourceのfake公開定義。
 */
void runCollectorHttpQuiescenceTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 新requestの通常受領と非再送中断によるCACHE4→8→10を検査します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] rootFactory 試験専用の保護store生成関数。
 * @param[in] definitionFactory 元二sourceの公開定義生成関数。
 * @param[in] capacityGrowth 初回四件から合成新requestの段階測定だけを行う場合true。
 * @param[in] startupBoundary 四件単位の厳密境界と通常起動を別枠で測る場合true。capacityGrowthも必須です。
 * @note 偽HTTP8受領と未受領2中断。CACHE300件・64 MiB境界・実通信の受入ではありません。
 */
void runCollectorCacheGrowthTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory,
	bool capacityGrowth = false, bool startupBoundary = false) ;
/** @brief 本番16 request・二世代と未受領二枠の非再送回復を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作保護storeの生成関数。
 * @param[in] definitionFactory 元二sourceの公開定義。
 * @param[in] capacityBoundary 合成299操作＋本番未受領一枠の専用境界を実行する場合true。
 * @note 既定は16要求の偽HTTP17受領と二中断。上限枠は四要求と末尾新一要求の合成履歴です。
 * 実日次運用やCACHE300件の受入ではありません。
 */
void runCollectorOperationHistoryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory,
	bool														 capacityBoundary = false) ;
/** @brief 異なる300世代の全完了像と301番目の保存前拒否を非通信検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作保護storeの生成関数。
 * @param[in] definitionFactory 元二sourceの公開定義。
 * @note DEFERRED合成履歴であり、操作／CACHE300件の受入ではありません。
 */
void runCollectorGenerationBoundaryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 末尾世代完了の実五保存窓・再停止・改変拒否を非通信検証します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作保護storeの生成関数。
 * @param[in] definitionFactory 元二sourceの公開定義。
 */
void runCollectorFinishRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 全完了履歴からの日次切替を実保存checkpointと非通信改変で検証します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作保護storeの生成関数。
 * @param[in] definitionFactory 元二sourceの公開定義。
 */
void runCollectorDayRollRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 次世代の二開始prefix・保存中断・拒否を専用非通信枠で検証します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 試験専用保護storeの生成関数。
 * @param[in] definitionFactory 初回成功を作る元二sourceの定義関数。
 */
void runCollectorPartialStartRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 次世代未応答の明示中断・保存窓・旧成功保持を非通信検証します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作保護storeの生成関数。
 * @param[in] definitionFactory 元二source定義の生成関数。
 */
void runCollectorNextRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 新射影予約・二source本文・拒否と一回性を偽HTTPで検証します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 独立保護storeの生成関数。
 * @param[in] definitionFactory 元公開manifestの生成関数。
 * @param[in] fingerprintOnly true時は公開hash/codec/faultと通常record同値だけを再確認します。
 */
void runCollectorProjectedHttpTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory,
	bool														 fingerprintOnly = false) ;
/** @brief 全完了raw由来の封印・改変／借用競合・最終再照合を非通信検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作保護rootの生成関数。
 * @param[in] definitionFactory 元二sourceの架空公開入力。
 */
void runCollectorCompletedInventoryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 同親historyで既存v3保存／完了readerと共有readerを個別に検査します。
 * @param[in,out] context 独立新枠のassertion集計。
 * @param[in] rootFactory 自身の通常祖先を含む領域生成関数。
 * @param[in] definitionFactory 元二sourceのfake公開入力。
 * @note 共有値一致や結合sealは検査・発行しません。
 */
void runCollectorHistoryLayoutV3Tests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 同親共有値／CACHE由来の一致と区間sealを独立非通信検査します。
 * @param[in,out] context 新枠だけのassertion集計。
 * @param[in] rootFactory 自作GUID祖先を含む領域生成関数。
 * @param[in] definitionFactory 元二sourceのfake公開入力。
 * @note 一完了世代の現区間だけです。旧区間参照／実worker join／通信は検査しません。
 */
void runCollectorSegmentInventoryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 実同親根拠の非保存draft・全元像・改変拒否を独立検査します。
 * @param[in,out] context 新枠だけのassertion集計。
 * @param[in] rootFactory 自作GUID領域の生成関数。
 * @param[in] definitionFactory 元二sourceのfake公開入力。
 * @note 実workerの停止所有証明・switch保存／回復は測定しません。
 */
void runCollectorSegmentPreparationTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory) ;
/** @brief 本番の予約・共通GETを完全fake依存で検証します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作GUID rootを生成し呼出し側が回収する同期関数。
 */
void runCollectorControlledHttpTests( TestContext								  &context,
									 const std::function<std::filesystem::path()> &rootFactory) ;
/** @brief Raw GETからworker終了・v3保存まで同じ経路を非通信検証します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作GUID rootの同期生成関数。
 */
void runCollectorControlledExecutorHttpTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory) ;
}
