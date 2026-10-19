//------------------------------------------------------------------------------
/**
 * @file signed_index_manifest_tests.h
 * @brief RAM内RSA署名によるmanifest認証試験を宣言します。
 * @version 01.04.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  Native署名と固定時刻の拒否試験を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  同RAM helperを使うasset byteの独立試験groupを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  署名済み配布recordの独立native groupを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/11  隔離diskの保護head保存試験groupを追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/11  保存snapshotの有限read-only resolver groupを追加。
 * </pre>
 *
 * @note Test target専用です。秘密鍵をexport・保存・log出力せず、実deviceや通信を使いません。
 */
//------------------------------------------------------------------------------
#pragma once

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
/** @brief 実署名・gzip・schema・隔離commit／reloadから公開ID照合seamを検査します。
 * @param[in,out] context 共通unit assertion集計先。
 * @note Fake resolverを使用し、実端末適合・通常worker／UI・取得導入へ接続しません。
 */
void runSignedIndexRecordLookupTests( TestContext &context) ;
} // namespace drivercrate::test
