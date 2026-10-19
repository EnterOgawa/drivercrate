//------------------------------------------------------------------------------
/**
 * @file official_file_verifier.h
 * @brief 公式配布file共通検証定義。
 * @version 01.05.00
 * @date 2026/09/23
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  XML署名publisher検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  SHA-256と共通のstream処理によるSHA-512計算を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/25  収集metadata専用の8 MiB hash上限を分離。
 * Ver.01.04.00 Shunji Ogawa  2026/10/06  原container専用の128 MiB hash入口を分離。
 * Ver.01.05.00 Shunji Ogawa  2026/10/17 明示cached-onlyの共通Authenticode入口を追加。
 * </pre>
 *
 * @note 公式catalogとpayloadのsize、SHA-256、Authenticode publisherを共通のfail-closed規則で検証します。URLや端末識別情報は保持し
 *       ません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

/**
 * @brief 親metadataが宣言した公式fileのsizeとSHA-256条件を表す。
 */
struct OfficialFileMetadataPolicy {
	/// 完全一致を要求するbyte数。未指定時は検査しない。
	std::optional<std::uint64_t> expectedSize ;
	/// 64桁ASCII hex。空の場合はhash検査を行わない。
	std::wstring_view			 expectedSha256 ;
} ;

/**
 * @brief File全体のSHA-256を小文字ASCII hexへ変換する。
 * EOFまでの全byteをCNG SHA-256へ順序通り入力する。
 * @param[in] path 読み取るfileの絶対path。
 * @param[out] sha256 成功時の64桁小文字SHA-256。失敗時は空。
 * @return 成功時は0、fileまたはCNG処理失敗時はHRESULT bit pattern。 成功時は0、fileまたはCNG失敗時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError computeFileSha256( std::wstring_view path, std::wstring &sha256) ;

/**
 * @brief 最大1 MiBの原byte列からSHA-256を計算します。
 * @param[in] bytes 空でない有限入力。BOM等を正規化しません。
 * @param[out] sha256 成功時の小文字64桁hex。失敗時は空。
 * @return 成功0、入力不正またはCNG失敗時はHRESULT。
 */
[[nodiscard]] NativeError computeBytesSha256( std::string_view bytes, std::wstring &sha256) ;

/** @brief 収集した最大8 MiBの原metadata本文を同じCNG処理でhashします。
 * @param[in] bytes 1 byte以上8 MiB以下のsession内本文。
 * @param[out] sha256 成功時の小文字SHA-256、失敗時は空です。
 * @return 成功0、上限拒否またはCNG失敗のHRESULT。
 * @note 既存computeBytesSha256の1 MiB上限は変更しません。
 */
[[nodiscard]] NativeError computeCollectorMetadataSha256( std::string_view bytes,
														 std::wstring	 &sha256) ;
/** @brief 原container memoryの最大128 MiBを既存CNG処理でhashする。
 * @param[in] bytes 空でない有限原byte。呼出し中に不変とする。
 * @param[out] sha256 成功時の小文字64桁SHA-256、失敗時は空。
 * @return 完了0、上限拒否またはCNG／allocation失敗のHRESULT。
 * @note 従来の1 MiB／8 MiB入口は変更せず、用途別の抽出上限を代替しない。
 */
[[nodiscard]] NativeError computeDriverContainerSha256( std::string_view bytes,
													   std::wstring	   &sha256) ;

/**
 * @brief File全体のSHA-512を有限bufferで計算します。
 * @param[in] path 読み取るfileの絶対path。
 * @param[out] sha512 成功時の128桁小文字hex。失敗時は空。
 * @return 成功0、file／CNG／allocation失敗時はHRESULT。
 * @note 公開hashの照合用であり、署名や導入許可を表しません。
 */
[[nodiscard]] NativeError computeFileSha512( std::wstring_view path, std::wstring &sha512) ;

/**
 * @brief 公式fileのsizeとSHA-256を親metadataの宣言へ完全一致させる。
 * 公式fileのsizeとSHA-256をmetadata宣言へ一致させる。
 * Sizeを先に確認し、不一致fileのhash計算を行わない。
 * @param[in] path 検証するfileの絶対path。
 * @param[in] policy 一つ以上のsizeまたはSHA-256条件。
 * @return 全指定条件一致時は0、不正条件または不一致時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError verifyOfficialFileMetadata( std::wstring_view				   path,
													 const OfficialFileMetadataPolicy &policy) ;

/**
 * @brief FileのAuthenticode chainと許可publisher完全一致を検証する。
 * Windows trust policy成功後にembedded signerを完全一致する。
 * @param[in] path 検証するfileの絶対path。
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可するpublisher表示名群。
 * @return Chain、revocation、publisher一致時は0、失敗時はtrust HRESULT。 Chain、revocation、publisher一致時は0、失敗時は
 *         HRESULT。
 */
[[nodiscard]] NativeError verifyAuthenticodePublisher(
	std::wstring_view path, std::span<const std::wstring_view> acceptedPublishers) ;

/**
 * @brief 通信せずcache内のchainと失効情報だけで共通Authenticodeを検証します。
 * @param[in] path 検証中に呼出側が実handleで変更・置換を防いだ絶対path。
 * @param[in] acceptedPublishers 許可するembedded certificateの完全publisher名群。
 * @return 成功0、cache不足・失効・chain・publisher不一致は元trust HRESULT。
 * @note 通常入口のpolicyは変えず、online fallbackやcatalog-only signer推測は行いません。
 */
[[nodiscard]] NativeError verifyAuthenticodePublisherCachedOnly(
	std::wstring_view path, std::span<const std::wstring_view> acceptedPublishers) ;

/**
 * @brief 署名catalogが全member fileの現在内容を収録していることを検証する。
 * 署名catalogと全member fileを検証する。
 * 現在OSのstrong-sign policyとSHA-256を全memberへ適用し、一件でも不一致ならpackage全体を受理しない。
 * @param[in] catalogPath 検証するCAT fileの絶対path。
 * @param[in] memberPaths Catalog memberとして検証する通常fileの絶対path群。 Catalogへ収録されるべき通常file群。
 * @return 全memberのhashとcatalog trustが有効なら0、最初の失敗はtrust HRESULT。 全memberのhashとcatalog trustが有効なら0、失敗
 *         時はHRESULT。
 * @note SHA-256と現在OSのstrong-sign policyを使用し、blocking処理はworkerで実行する。
 */
[[nodiscard]] NativeError verifyOfficialCatalogMembers( std::wstring_view			 catalogPath,
													   std::span<const std::wstring> memberPaths) ;

/**
 * @brief XML Digital Signatureと埋込みcertificateのpublisherを検証する。
 * XML Digital Signatureとpublisherを検証する。
 * Certificate公開鍵と文書全体の単一referenceを結び付け、CryptXML extensionを使用しない。
 * @param[in] path 検証するUTF-8 XML fileの絶対path。 検証するUTF-8 XML file絶対path。
 * @param[in] maximumBytes 読取りを許可するXML byte数上限。 XML read上限byte数。
 * @param[in] validationFiletime 署名済み時刻を表す1601年起点100ns単位値。 署名済みSigningTime。
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可publisher表示名群。
 * @return 文書全体の署名、code-signing chain、publisher一致時は0。 XML署名、chain、publisherが全て有効なら0。
 * @note 単一enveloped reference、RSA-SHA256、SHA-256、標準C14Nだけを許可する。
 */
[[nodiscard]] NativeError verifyXmlSignaturePublisher(
	std::wstring_view path, std::uint64_t maximumBytes, std::uint64_t validationFiletime,
	std::span<const std::wstring_view> acceptedPublishers) ;

/**
 * @brief Metadata条件とAuthenticode publisherを一つの順序で検証する。
 * Metadata条件とAuthenticode publisherを順番に検証する。
 * 不一致payloadへWinTrust処理を行わず、全条件をfail-closedにする。
 * @param[in] path 検証するfileの絶対path。
 * @param[in] metadataPolicy 親metadataが宣言したsize／SHA-256条件。 親metadataのsize／SHA-256条件。
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可するpublisher表示名群。
 * @return 全検証成功時は0、最初に失敗した検証のHRESULT bit pattern。 全検証成功時は0、最初の失敗時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError verifyOfficialFile( std::wstring_view					path,
											 const OfficialFileMetadataPolicy  &metadataPolicy,
											 std::span<const std::wstring_view> acceptedPublishers) ;

} // namespace drivercrate
