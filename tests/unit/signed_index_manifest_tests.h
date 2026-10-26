//------------------------------------------------------------------------------
/**
 * @file signed_index_manifest_tests.h
 * @brief RAM内RSA署名によるmanifest認証試験を宣言します。
 * @version 01.09.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  Native署名と固定時刻の拒否試験を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  同RAM helperを使うasset byteの独立試験groupを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  署名済み配布recordの独立native groupを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/11  隔離diskの保護head保存試験groupを追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/11  保存snapshotの有限read-only resolver groupを追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/19  実DPAPI旧headの不変移動回帰を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/23 実producer原manifest/GZipの認証と通常候補接続を宣言。
 * Ver.01.06.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理。
 * Ver.01.07.00 Shunji Ogawa  2026/10/24  同集合の未照合native一recordを保持するfixtureを追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/24  原Intel六入力の明示historical archive試験を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/26 新metadata生成索引の原byteを通常reader/候補adapterへ接続。
 * Ver.01.09.01 Shunji Ogawa  2026/10/26 宣言と定義の引数名を揃えDoxygen契約を整合。
 * </pre>
 *
 * @note Test target専用です。秘密鍵をexport・保存・log出力せず、実deviceや通信を使いません。
 */
//------------------------------------------------------------------------------
#pragma once
#include <filesystem>

namespace drivercrate::test {
class TestContext ;

/** @brief 実CNG署名・JSON・base64・期限・世代の正例と拒否を固定時刻で検査します。
 * @param[in,out] context 共通unit assertion集計先。
 */
void runSignedIndexManifestTests( TestContext &context) ;

/** @brief 前段の実CNG認証から実GZip assetのsize／hash／期限／展開上限を検査します。
 * @param[in,out] context 共通unit assertion集計先。
 * @note 実128MiB境界の人工原byteを使い、record schemaや実deviceのcoverageを測りません。
 */
void runSignedIndexAssetBytesTests( TestContext &context) ;

/** @brief 同RAM helperで厳格配布schema・原hash・UNKNOWN・有限上限を検査します。
 * @param[in,out] context 共通unit assertion集計先。
 * @note 架空の公開IDだけを使用し、公式性・端末適合・導入の実績を作りません。
 */
void runSignedIndexRecordsTests( TestContext &context) ;

/** @brief 同RAM鍵と実隔離diskで保護原子head・世代・期限・障害を検査します。
 * @param[in,out] context 共通unit assertion集計先。
 * @note 製品store、network、実端末適合、実導入、process再起動は実行しません。
 */
void runSignedIndexStoreTests( TestContext &context) ;
/** @brief 実署名/DPAPIの隔離rootで用途別trust・世代下限・未知root拒否を検査します。
 * @param[in,out] context 共通unit assertion集計先です。
 * @note 固定ProgramData/実鍵/実通信へアクセスしません。
 */
void runSignedIndexStoreDomainTests( TestContext &context) ;
/** @brief 実署名・gzip・schema・隔離commit／reloadから公開ID照合seamを検査します。
 * @param[in,out] context 共通unit assertion集計先。
 * @note Fake resolverを使用し、実端末適合・通常worker／UI・取得導入へ接続しません。
 */
void runSignedIndexRecordLookupTests( TestContext &context) ;
/** @brief 実producerの同一manifest/GZip原byteをRAM認証し通常照合へ渡します。
 * @param[in,out] context 共通assertion集計先です。
 * @param[in] manifestPath 原producerが保存した未署名manifestです。
 * @param[in] gzipPath 同producerの原GZipです。
 * @param[in] package 同runを生成した自己所有packageです。
 * @param[in] nativeMerge trueだけ固定Intel一原recordを未照合のまま四record集合へ保持します。
 * @param[in] metadataBound trueだけ新metadata一recordとpackage引数の人工terms原bodyを検査します。
 * @note 秘密鍵はRAM限定です。製品trustへ登録せず、実導入/通信を行いません。
 */
void runDistributionApplicationFixtureTests( TestContext					&context,
											const std::filesystem::path &manifestPath,
											const std::filesystem::path &gzipPath,
											const std::filesystem::path &package,
											bool nativeMerge = false, bool metadataBound = false) ;
/** @brief 原Intel record/期限/実archiveを通常appへ明示historical replayします。
 * @param[in,out] context 元assertion集計先です。
 * @param[in] manifestPath 現producerで六原入力を元publication秒へ投影したmanifestです。
 * @param[in] gzipPath 同producerの全22IDを持つ原GZip、負例3だけはID欠損copyです。
 * @param[in] archivePath 元40477087Bのarchiveです。別byte/hashを拒否します。
 * @param[in] termsPath 元173557BのHTTP規約documentです。
 * @param[in] scenario 0正常、1誤byte、2同意欠落、3全ID tuple欠損です。
 * @note RAM鍵/隔離storeとhistorical fake時計だけを使い、実現在UTCの失効拒否も確認します。
 * Windows標準署名APIは実行し、証明書読取通信は未観測です。実device/導入/driver HTTPは0です。
 */
void runNativeIntelArchiveFixtureTests( TestContext				   &context,
									   const std::filesystem::path &manifestPath,
									   const std::filesystem::path &gzipPath,
									   const std::filesystem::path &archivePath,
									   const std::filesystem::path &termsPath, unsigned scenario) ;
} // namespace drivercrate::test
