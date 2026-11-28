//------------------------------------------------------------------------------
/**
 * @file signed_index_manifest_tests.h
 * @brief RAM内RSA署名によるmanifest認証試験を宣言します
 * @version 01.21.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  同RAM helperを使うasset byteの独立試験groupを追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  署名済み配布recordの独立native groupを追加
 * Ver.01.03.00 Shunji Ogawa  2026/10/11  隔離diskの保護head保存試験groupを追加
 * Ver.01.04.00 Shunji Ogawa  2026/10/11  保存snapshotの有限read-only resolver groupを追加
 * Ver.01.05.00 Shunji Ogawa  2026/10/19  実DPAPI旧headの不変移動回帰を追加
 * Ver.01.06.00 Shunji Ogawa  2026/10/23 実producer原manifest/GZipの認証と通常候補接続を宣言
 * Ver.01.06.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理
 * Ver.01.07.00 Shunji Ogawa  2026/10/24  同集合の未照合native一recordを保持するfixtureを追加
 * Ver.01.08.00 Shunji Ogawa  2026/10/24  原Intel六入力の明示historical archive試験を追加
 * Ver.01.09.00 Shunji Ogawa  2026/10/26 新metadata生成索引の原byteを通常reader/候補adapterへ接続
 * Ver.01.09.01 Shunji Ogawa  2026/10/26 宣言と定義の引数名を揃えDoxygen契約を整合
 * Ver.01.10.00 Shunji Ogawa  2026/11/06 Windows管理driver DATAの限定通常経路試験を宣言
 * Ver.01.11.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合
 * Ver.01.11.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.11.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.11.03 Shunji Ogawa  2026/11/12  外側tupleの取得予約と開始拒否の原理由を接続
 * Ver.01.12.00 Shunji Ogawa  2026/11/16  storage通常選択と完全native表の正負・原結果を検証
 * Ver.01.13.00 Shunji Ogawa  2026/11/17  所有workspace限定のMTD file I/Oを個別に選択
 * Ver.01.14.00 Shunji Ogawa  2026/11/17  MTD通常操作と旧通常controlの限定入口を宣言
 * Ver.01.15.00 Shunji Ogawa  2026/11/19  正規Client26200条件の限定consumer入口を宣言
 * Ver.01.16.00 Shunji Ogawa  2026/11/19  24H2最低26100の独立回帰と旧条件を接続
 * Ver.01.17.00 Shunji Ogawa  2026/11/19  保存原取得を使う追加索引の独立検証を宣言
 * Ver.01.18.00 Shunji Ogawa  2026/11/19  保存AWS原索引の通常取得計画試験を宣言
 * Ver.01.19.00 Shunji Ogawa  2026/11/19  独自クラスの元署名recordを使う通常worker試験を宣言
 * Ver.01.20.00 Shunji Ogawa  2026/11/22  私有ZIP規約の保存原本を使う通常取得試験を宣言
 * Ver.01.21.00 Shunji Ogawa  2026/11/27  付随INF付きDisplay更新の個別回帰試験を追加
 * </pre>
 *
 * @note Test target専用です。秘密鍵をexport・保存・log出力せず、実deviceや通信を使いません
 */
//------------------------------------------------------------------------------
#pragma once
#include <cstddef>
#include <filesystem>

namespace drivercrate::test {
class TestContext ;

//------------------------------------------------------------------------------
/**
 * @brief 人工署名索引からWindows-only driver DATAの通常選択/保護導入経路を検査します
 * @param[in,out] context 有限assertion集計先です
 * @note 実CAB/実CAT検査Aと分ける人工fixture Bです。HTTP、復旧、NewDevは完全fakeです
 */
//------------------------------------------------------------------------------
void runWindowsManagedDriverPackageFixtureTests( TestContext &context) ;

//------------------------------------------------------------------------------
/**
 * @brief 付随INFの通常導入と別配置や同バージョンの拒否を検証する
 * @param[in,out] context 正例と個別拒否の検査結果を保持します
 * @note 人工署名索引と隔離fileを使い、実際のドライバーを変更しません
 */
//------------------------------------------------------------------------------
void runDisplayCopyInfBindingTests( TestContext &context) ;

//------------------------------------------------------------------------------
/**
 * @brief 実CNG署名・JSON・base64・期限・世代の正例と拒否を固定時刻で検査します
 * @param[in,out] context 共通unit assertion集計先
 */
//------------------------------------------------------------------------------
void runSignedIndexManifestTests( TestContext &context) ;

//------------------------------------------------------------------------------
/**
 * @brief 前段の実CNG認証から実GZip assetのsize／hash／期限／展開上限を検査します
 * @param[in,out] context 共通unit assertion集計先
 * @note 実128MiB境界の人工原byteを使い、record schemaや実deviceのcoverageを測りません
 */
//------------------------------------------------------------------------------
void runSignedIndexAssetBytesTests( TestContext &context) ;

//------------------------------------------------------------------------------
/**
 * @brief 同RAM helperで厳格配布schema・原hash・UNKNOWN・有限上限を検査します
 * @param[in,out] context 共通unit assertion集計先
 * @note 架空の公開IDだけを使用し、公式性・端末適合・導入の実績を作りません
 */
//------------------------------------------------------------------------------
void runSignedIndexRecordsTests( TestContext &context) ;

//------------------------------------------------------------------------------
/**
 * @brief 保存済み取得から作った対照assetをRAM署名し、旧本文と追加欄の保持を確認します
 * @param[in,out] context 共通試験集計です
 * @param[in] legacyGzipPath 追加欄を持たない既存GZip対照です
 * @param[in] manifestPath 追加欄付きassetの未署名manifestです
 * @param[in] gzipPath 元レコードを持つ追加欄付きGZipです
 * @note 製品trust、永続鍵、通信、実導入を扱いません
 */
//------------------------------------------------------------------------------
void runSignedIndexSupplementFixtureTests( TestContext				  &context,
										  const std::filesystem::path &legacyGzipPath,
										  const std::filesystem::path &manifestPath,
										  const std::filesystem::path &gzipPath) ;

//------------------------------------------------------------------------------
/**
 * @brief 保存AWS原索引の通常取得計画とNitro確認を隔離して検査します
 * @param[in,out] context 共通試験集計です
 * @param[in] manifestPath 保存済みの原manifestです
 * @param[in] gzipPath 原レコードを含む保存済み圧縮索引です
 * @param[in] archivePath 検査済みの保存ZIPです
 * @note RAM試験鍵と低位fakeだけを使用します
 */
//------------------------------------------------------------------------------
void runSavedAwsConsumerPlanTests( TestContext &context, const std::filesystem::path &manifestPath,
								  const std::filesystem::path &gzipPath,
								  const std::filesystem::path &archivePath) ;

//------------------------------------------------------------------------------
/**
 * @brief 保存した私有候補をRAM署名し、通常の規約同意と保護ZIPの検査へ渡します
 * @param[in,out] context 共通試験集計です
 * @param[in] manifestPath 私有索引の未署名manifestです
 * @param[in] gzipPath 原候補の追加欄を持つ圧縮索引です
 * @param[in] archivePath 検査済みの元ZIPです
 * @param[in] pagePath 保存した公式配布ページです
 * @param[in] termsPath 保存した原規約文書です
 */
//------------------------------------------------------------------------------
void runSavedArchiveTermsConsumerTests( TestContext				   &context,
									   const std::filesystem::path &manifestPath,
									   const std::filesystem::path &gzipPath,
									   const std::filesystem::path &archivePath,
									   const std::filesystem::path &pagePath,
									   const std::filesystem::path &termsPath) ;

//------------------------------------------------------------------------------
/**
 * @brief 同RAM鍵と実隔離diskで保護原子head・世代・期限・障害を検査します
 * @param[in,out] context 共通unit assertion集計先
 * @note 製品store、network、実端末適合、実導入、process再起動は実行しません
 */
//------------------------------------------------------------------------------
void runSignedIndexStoreTests( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief 実署名/DPAPIの隔離rootで用途別trust・世代下限・未知root拒否を検査します
 * @param[in,out] context 共通unit assertion集計先です
 * @note 固定ProgramData/実鍵/実通信へアクセスしません
 */
//------------------------------------------------------------------------------
void runSignedIndexStoreDomainTests( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief 実署名・gzip・schema・隔離commit／reloadから公開ID照合seamを検査します
 * @param[in,out] context 共通unit assertion集計先
 * @note Fake resolverを使用し、実端末適合・通常worker／UI・取得導入へ接続しません
 */
//------------------------------------------------------------------------------
void runSignedIndexRecordLookupTests( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief 実producerの同一manifest/GZip原byteをRAM認証し通常照合へ渡します
 * @param[in,out] context 共通assertion集計先です
 * @param[in] manifestPath 原producerが保存した未署名manifestです
 * @param[in] gzipPath 同producerの原GZipです
 * @param[in] package 同runを生成した自己所有packageです
 * @param[in] nativeMerge trueだけ固定Intel一原recordを未照合のまま四record集合へ保持します
 * @param[in] metadataBound trueだけ新metadata一recordとpackage引数の人工terms原bodyを検査します
 * @note 秘密鍵はRAM限定です。製品trustへ登録せず、実導入/通信を行いません
 */
//------------------------------------------------------------------------------
void runDistributionApplicationFixtureTests( TestContext					&context,
											const std::filesystem::path &manifestPath,
											const std::filesystem::path &gzipPath,
											const std::filesystem::path &package,
											bool nativeMerge = false, bool metadataBound = false) ;
//------------------------------------------------------------------------------
/**
 * @brief 原Intel record/期限/実archiveを通常appへ明示historical replayします
 * @param[in,out] context 元assertion集計先です
 * @param[in] manifestPath 現producerで六原入力を元publication秒へ投影したmanifestです
 * @param[in] gzipPath 同producerの全22IDを持つ原GZip、負例3だけはID欠損copyです
 * @param[in] archivePath 元40477087Bのarchiveです。別byte/hashを拒否します
 * @param[in] termsPath 元173557BのHTTP規約documentです
 * @param[in] scenario 0正常、1誤byte、2同意欠落、3全ID tuple欠損です
 * @note RAM鍵/隔離storeとhistorical fake時計だけを使い、実現在UTCの失効拒否も確認します。Windows標準署名APIは実行し、証明書読取通信は未観測です。実
 *       device/導入/driver HTTPは0です
 */
//------------------------------------------------------------------------------
void runNativeIntelArchiveFixtureTests( TestContext				   &context,
									   const std::filesystem::path &manifestPath,
									   const std::filesystem::path &gzipPath,
									   const std::filesystem::path &archivePath,
									   const std::filesystem::path &termsPath, unsigned scenario) ;
//------------------------------------------------------------------------------
/**
 * @brief 独立byte条件内の65536/65537 recordを共通値codecで確認します
 * @param[in,out] context 本suiteの集計先です
 * @note 認証receiptや内容成功は発行しません
 */
//------------------------------------------------------------------------------
void runIndexCapacityRecordCountTests( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief native producer原fileをRAM署名/隔離store/通常scan/planへ接続します
 * @param[in,out] context 共通集計先です
 * @param[in] directory 私有native producerの保存先です
 */
//------------------------------------------------------------------------------
void runIndexCapacityProducedConsumerTests( TestContext				   &context,
										   const std::filesystem::path &directory) ;

//------------------------------------------------------------------------------
/**
 * @brief 旧368原byteを保持し全ID/record容量とnative matcherを有限確認します
 * @param[in,out] context 共通assertion集計先です
 * @param[in] baselineIndex 764基準から作った私有base368/index.jsonです
 * @param[in] requestedInputs 0は旧上限超/境界matrix、正値はその全公開ID数です
 * @param[in] large trueは4096nodeの完全低位fakeを使います
 * @param[in] realClock trueだけ実時間/メモリ性能を受入分母にします
 * @param[in] tailUnknown trueだけ全入力枠消費後に0-ID UNKNOWNを追加します
 * @note 実鍵/store/inventory/通信/導入を使用せずRAM署名の隔離storeだけです
 */
//------------------------------------------------------------------------------
void runIndexCapacityTests( TestContext &context, const std::filesystem::path &baselineIndex,
						   std::size_t requestedInputs, bool large, bool realClock,
						   bool tailUnknown) ;
//------------------------------------------------------------------------------
/**
 * @brief positive/UNKNOWN/native projectionの保持32768/32769を確認します
 * @param[in,out] context 共通集計先です
 */
//------------------------------------------------------------------------------
void runIndexCapacityRetainedTests( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief 真署名outer sizeから実UI共有承認/予算guardと匿名拒否へ有限接続します
 * @param[in,out] context assertion集計先です
 * @note 隔離RAM署名/保存と既fakeだけを使い、実HTTP/driver/restoreを呼びません
 */
//------------------------------------------------------------------------------
void runSignedIndexKnownSizeApprovalTests( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief 真署名storage索引を通常選択と完全native fakeの候補資格へ接続します
 * @param[in,out] context 隔離した有限assertionの集計先です
 * @param[in] mtdFileOnly 新規所有workspaceのMTD file I/Oだけを選ぶ場合trueです
 * @param[in] mtdOperationOnly MTDの通常操作一件だけを選ぶ場合trueです
 * @note BOOT0/SYSTEM1/DEMAND3の元INFを使い、実通信・実導入・復元作成を行いません
 */
//------------------------------------------------------------------------------
void runSignedIndexStorageQualificationTests( TestContext &context, bool mtdFileOnly = false,
											 bool mtdOperationOnly = false) ;
//------------------------------------------------------------------------------
/**
 * @brief 従来のPorts通常署名candidateを同じfake指定導入経路で確認します
 * @param[in,out] context 隔離した有限assertionの集計先です
 * @note 実HTTP、実device導入、実復元の作成を行いません
 */
//------------------------------------------------------------------------------
void runSignedIndexNormalBindingControl( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief 元署名recordと人工配布物から独自クラスの通常導入を検査します
 * @param[in,out] context 候補発行と明示選択後の元Windows API回数を検証する集計先です
 * @note 非永続鍵、隔離storeとFake HTTP・SetupAPI・NewDev・復元を使用します
 */
//------------------------------------------------------------------------------
void runSignedIndexDeclarativeClassBindingTests( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief 正規Client最低build条件の通常scan・計画・取得とhost拒否を限定実行します
 * @param[in,out] context 独立literal条件と実owner経路のassertion集計先です
 * @param[in] minimumBuild 既26200又は追加26100の固定分母です
 * @param[in] prechange 旧sourceの26100項目拒否だけを別に確認する場合trueです
 * @note RAM署名・人工archive・完全native/HTTP fakeだけを使い、実導入を行いません
 */
//------------------------------------------------------------------------------
void runClientMinimumBuildConsumerTests( TestContext &context, unsigned minimumBuild = 26200U,
										bool prechange = false) ;
} // namespace drivercrate::test
