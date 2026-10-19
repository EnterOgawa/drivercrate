//------------------------------------------------------------------------------
/**
 * @file local_index_signing.h
 * @brief 明示操作だけのローカル索引署名と非秘密の結果を定義します。
 * @version 01.03.00
 * @date 2026/10/13
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/13  非export保護鍵と原byte署名の明示入口を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/14  実assetと取得revision1の用途別署名検査を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/15  別固定配布鍵と公開pinだけのmetadata検証を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/16  配布取得用途の公開検証と明示署名を分離。
 * Ver.01.03.00 Shunji Ogawa  2026/10/17  公開byteだけの配布取得履歴検証を追加。
 * </pre>
 *
 * @note 開発collector側専用です。秘密byteを返さず、network・導入・自動鍵更新はありません。
 * @see docs/adr/0337-local-index-signing-and-build-pins.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/signed_index_manifest.h"
#include "platform/signed_index_records.h"
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief CNGのfull-control maskの既知重複表現だけを認める純粋内部境界です。 */
namespace local_index_signing_detail {
/** @brief GENERIC_ALLまたは完全file全権限を未知bitなしで比較します。
 * @param[in] mask 非秘密の実ACE access maskです。
 * @return 全権限の既知表現だけtrueです。Read-only、未知bit、0はfalseです。
 */
[[nodiscard]] bool fullControlMask( std::uint32_t mask) noexcept ;
}

/** @brief 公開byteと実保護検査だけの非秘密receiptです。署名権限を移譲しません。 */
struct LocalIndexPublicKey {
	/// 完全な411byteのRSA3072公開blob。秘密fieldはありません。
	std::vector<std::uint8_t> publicBlob ;
	/// 公開blob全byteの小文字SHA-256です。
	std::string				  fingerprint ;
	/// Fingerprint前32桁へ結合するlocal専用IDです。
	std::string				  keyId ;
	/// この呼出しで新規鍵をfinalizeした場合だけtrueです。
	bool					  created{} ;
	/// 実bit長、非export、signing-only、owner/DACLの全確認後だけtrueです。
	bool					  protectionVerified{} ;
} ;

/** @brief 元OS codeと非秘密出力を保持し、途中の作成事実を失わない結果です。 */
struct LocalIndexSigningResult {
	/// 成功時0。CNG code、Win32 errorまたはHRESULTをそのまま保持します。
	NativeError								 error{} ;
	/// 保護入力拒否の固定検査段階番号です。SID/descriptor/秘密情報を含みません。
	std::uint32_t							 checkStage{} ;
	/// 固定検査に付随する非秘密の属性値です。SID/descriptorを返しません。
	std::uint32_t							 observedValue{} ;
	/// 新規finalizeの事実。後段が失敗してもtrueを保持します。
	bool									 created{} ;
	/// 保護確認成功時だけ存在する公開receiptです。
	std::optional<LocalIndexPublicKey>		 publicKey ;
	/// 原manifest署名と既存codecの全確認後だけ存在する外側byteです。
	std::string								 envelope ;
	/// 既存codecによる署名後の拒否理由です。未実行ではnulloptです。
	std::optional<SignedIndexManifestStatus> manifestStatus ;
	/// 用途別の実GZip拒否理由です。未実行ではnulloptです。
	std::optional<IndexAssetBytesStatus>	 assetStatus ;
	/// 用途別の原v2 record拒否理由です。未実行ではnulloptです。
	std::optional<IndexRecordsStatus>		 recordsStatus ;
} ;

/**
 * @brief 固定current-user鍵を実照会し、明示createの場合だけ欠損鍵を作ります。
 * @param[in] createIfMissing 明示create操作だけtrueです。通常inspectはfalseです。
 * @return 実保護確認後だけpublic receipt。不適合既存鍵は変更・削除しません。
 * @note 同期CNG/OS処理です。秘密export、machine key、特権調整を行いません。
 */
[[nodiscard]] LocalIndexSigningResult inspectLocalIndexSigningKey( bool createIfMissing) noexcept ;

/**
 * @brief 固定既存鍵で原manifest byteを署名し、既存native codecで再認証します。
 * @param[in] manifestBytes 最大64KiBの原UTF-8。再serializationしません。
 * @param[in] expectedFingerprint 明示固定した公開blob全SHA-256の小文字64桁です。
 * @param[in] nowUtc 確認した現在UTC。期限検査なしでは出力しません。
 * @return 成功時だけ原byteを含むenvelope。失敗時envelope空で元codeを保持します。
 * @note 鍵作成、trust登録、取得/導入許可、保存やnetworkは行いません。
 */
[[nodiscard]] LocalIndexSigningResult signLocalIndexManifest(
	std::string_view manifestBytes, std::string_view expectedFingerprint,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/**
 * @brief 同manifestと実GZipの全取得recordを用途別に再検査して署名出力を返します。
 * @param[in] manifestBytes 最大64KiBの原UTF-8 manifestです。再整形しません。
 * @param[in] gzipBytes 同manifestへ結合する有限な原GZipです。
 * @param[in] expectedFingerprint 固定した公開blob全SHA-256です。
 * @param[in] nowUtc 確認済みの現在UTCです。
 * @return 全codecとrevision1/公開INF/内容申告の成立時だけenvelopeです。拒否時は空です。
 * @note 開発producer専用です。実公式性/内容を新たに証明せず、鍵作成/取得/導入を行いません。
 */
[[nodiscard]] LocalIndexSigningResult signLocalAcquisitionIndex(
	std::string_view manifestBytes, std::span<const std::byte> gzipBytes,
	std::string_view expectedFingerprint, std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/** @brief Acceptanceと共有しない固定CurrentUser配布鍵だけを照会または明示作成します。
 * @param[in] createIfMissing 明示create操作だけtrueです。
 * @return 同じ非export/owner/DACL検査を通った公開receiptだけです。
 * @note 任意container指定とAcceptance fallbackはありません。
 */
[[nodiscard]] LocalIndexSigningResult inspectDistributionIndexSigningKey(
	bool createIfMissing) noexcept ;

/** @brief 配布専用固定鍵で署名し、同assetのmetadata-only schemaまで検査します。
 * @param[in] manifestBytes 再整形しない原manifestです。
 * @param[in] gzipBytes 同manifestに結合した原GZipです。
 * @param[in] expectedFingerprint ローカルで固定した公開blobの全SHA-256です。
 * @param[in] nowUtc 現在UTCです。欠損を受理しません。
 * @return 全検査成功時だけenvelopeです。
 */
[[nodiscard]] LocalIndexSigningResult signDistributionIndex(
	std::string_view manifestBytes, std::span<const std::byte> gzipBytes,
	std::string_view expectedFingerprint, std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/** @brief 鍵storeを開かず、ローカル公開pinと既存native codecで配布byteを検証します。
 * @param[in] envelopeBytes 署名された原envelopeです。
 * @param[in] gzipBytes 同manifestの原GZipです。
 * @param[in] publicBlob ローカルに固定したRSA3072公開blobです。
 * @param[in] expectedFingerprint 公開blob全byteの小文字SHA-256です。
 * @param[in] nowUtc 現在UTCです。
 * @param[in] requirePublicationTime 旧current高水位専用として署名発行秒との一致を要求する場合だけtrueです。
 * @return 原署名/期限/hash/GZip/metadata-only schemaの全成功時だけenvelopeです。
 * @note Remote鍵をtrustへ追加せず、署名秘密鍵の存在も照会しません。
 */
[[nodiscard]] LocalIndexSigningResult verifyDistributionIndex(
	std::string_view envelopeBytes, std::span<const std::byte> gzipBytes,
	std::span<const std::uint8_t> publicBlob, std::string_view expectedFingerprint,
	std::optional<std::chrono::sys_seconds> nowUtc, bool requirePublicationTime = false) noexcept ;

/** @brief 公開byteだけで全recordの配布取得用途と原署名を検証します。
 * @param[in] envelopeBytes 正規化しない原envelopeです。
 * @param[in] gzipBytes 同manifestへ結合した原GZipです。
 * @param[in] publicBlob 明示固定した411byteのRSA3072公開blobです。
 * @param[in] expectedFingerprint 公開blob全byteの小文字SHA-256です。
 * @param[in] nowUtc 現在の確認済みUTC。欠損では出力しません。
 * @return 全codecと全取得申告が成立した場合だけ原envelope。拒否では空です。
 * @note 鍵storeを照会せず、実公式性/CAT再検査/端末適用性/grantを証明しません。
 */
[[nodiscard]] LocalIndexSigningResult verifyDistributionAcquisitionIndex(
	std::string_view envelopeBytes, std::span<const std::byte> gzipBytes,
	std::span<const std::uint8_t> publicBlob, std::string_view expectedFingerprint,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/** @brief 公開byteだけで配布取得索引が署名発行時点で成立していたことを検査します。
 * @param[in] envelopeBytes 正規化しない原envelopeです。最大96KiBです。
 * @param[in] gzipBytes 同manifestへ結合した原GZipです。最大32MiBです。
 * @param[in] publicBlob 明示固定した411byteのRSA3072公開blobです。
 * @param[in] expectedFingerprint 公開blob全byteの小文字SHA-256です。
 * @param[in] publishedAtUtc 原manifestから読み取った発行UTC秒です。署名後の値と完全一致を要求します。
 * @param[in] nowUtc 確認済み現在UTCです。欠損または未来の発行秒を拒否します。
 * @return 発行時の全codec/用途検査成功時だけ原envelopeと非保護公開receiptです。拒否時は空です。
 * @note 入力は呼出し中だけ借用します。独立入力では同時呼出し可能で、永続I/Oを行いません。
 * 現在の失効は許可しますが、現行取得許可、grant、署名権限、高水位や保護storeを発行・更新しません。
 * 秘密鍵/KSPを照会せず、metadata-onlyを取得履歴へ昇格しません。
 */
[[nodiscard]] LocalIndexSigningResult verifyDistributionAcquisitionIndexHistory(
	std::string_view envelopeBytes, std::span<const std::byte> gzipBytes,
	std::span<const std::uint8_t> publicBlob, std::string_view expectedFingerprint,
	std::optional<std::chrono::sys_seconds> publishedAtUtc,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/** @brief 既存固定配布containerだけで署名し、全recordの取得用途検査後だけ返します。
 * @param[in] manifestBytes 最大64KiBの原manifestです。再整形しません。
 * @param[in] gzipBytes 同manifestへ結合した原GZipです。
 * @param[in] expectedFingerprint 事前固定した公開blob全SHA-256です。
 * @param[in] nowUtc 現在の確認済みUTCです。
 * @return 保護検査/署名/全codec/全用途成功時だけenvelopeです。
 * @note 鍵作成/Acceptance fallback/秘密export/取得grantはありません。申告の署名であり実内容の再検査ではありません。
 */
[[nodiscard]] LocalIndexSigningResult signDistributionAcquisitionIndex(
	std::string_view manifestBytes, std::span<const std::byte> gzipBytes,
	std::string_view expectedFingerprint, std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

} // namespace drivercrate
