//------------------------------------------------------------------------------
/**
 * @file signed_index_codec_internal.h
 * @brief 署名wrapperと未署名候補が共有する値codecを定義します
 * @version 01.10.01
 * @date 2026/10/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/19  圧縮元byteに結合した追加欄を保持
 * Ver.01.02.00 Shunji Ogawa  2026/11/19  追加欄と既存候補の取得用途を共通検査
 * Ver.01.03.00 Shunji Ogawa  2026/11/19  追加欄の運搬とレコードを候補準備と共通化
 * Ver.01.04.00 Shunji Ogawa  2026/11/19  圧縮前の保留候補を同じレコード検査に接続
 * Ver.01.05.00 Shunji Ogawa  2026/11/22  収集専用の公式Models証拠の原文と型を定義
 * Ver.01.06.00 Shunji Ogawa  2026/11/22  公式Modelsの専用欄を従来の追加欄と分離
 * Ver.01.07.00 Shunji Ogawa  2026/11/22  専用欄の取得条件を元証拠付きレコードに限定
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  収集した専用欄の局所値検査を追加
 * Ver.01.09.00 Shunji Ogawa  2026/11/22  専用候補の局所読戻しに同じ値検査を使用
 * Ver.01.10.00 Shunji Ogawa  2026/11/25  本文と私有追加欄の共通検査を宣言
 * Ver.01.10.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 * @note 値の検査だけです。認証receipt、信頼鍵、通信能力を作りません
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/official_driver_package.h"
#include "platform/signed_index_records.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::signed_index_detail {

/** @brief Manifest値codecの未認証結果です */
struct DecodedIndexManifest {
	/// 既存codecの元拒否だけです。値成功時はnulloptで、認証成功区分を作りません
	std::optional<SignedIndexManifestStatus> failure{SignedIndexManifestStatus::INVALID_MANIFEST} ;
	/// CNGまたは確保の元診断です
	NativeError								 error{} ;
	/// 全値検査成功時だけ所有する未認証DTOです
	std::optional<IndexManifestData>		 data ;
} ;

/** @brief 実GZipの検査・展開値です */
struct DecodedIndexAssetData {
	/// 全境界検査を終えた原展開byteです
	std::vector<std::byte> expanded ;
	/// 展開原byteだけの実hashです
	IndexManifestSha256	   expandedSha256{} ;
	/// 圧縮率と絶対上限の最小値です
	std::uint64_t		   maximumExpandedBytes{} ;
	/// 元圧縮byteに含まれる従来のDC欄です。存在だけでは認証を意味しません
	std::vector<std::byte> supplementFrame ;
	/// 元圧縮byteに含まれる公式ModelsのDM欄です。存在だけでは認証を意味しません
	std::vector<std::byte> scopedModelsFrame ;
} ;

/** @brief Asset値codecの未認証結果です */
struct DecodedIndexAsset {
	/// 既存codecの元区分です
	IndexAssetBytesStatus				 status{IndexAssetBytesStatus::GZIP_REJECTED} ;
	/// 共通CNG/GZip APIの元診断です
	NativeError							 error{} ;
	/// 全検査成功時だけ所有する未認証byteです
	std::optional<DecodedIndexAssetData> data ;
} ;

/** @brief 全recordとqualityの未認証所有値です */
struct DecodedIndexRecordsData {
	/// 全参照検査を終えたsource集合です
	std::vector<IndexRecordSource>		 sources ;
	/// 全hash/schema検査を終えたrecord集合です
	std::vector<IndexDistributionRecord> records ;
	/// Manifestと照合した実件数です
	IndexManifestQuality				 quality ;
} ;

/** @brief Record値codecの未認証結果です */
struct DecodedIndexRecords {
	/// 既存codecの元区分です
	IndexRecordsStatus					   status{IndexRecordsStatus::INVALID_INDEX} ;
	/// 元APIまたは確保診断です
	NativeError							   error{} ;
	/// 全検査成功時だけ所有する未認証値です
	std::optional<DecodedIndexRecordsData> data ;
} ;

/** @brief 一つの配布物・INF・明示OSについて保存する収集専用の原証拠 */
struct CollectorScopedModelsEvidence {
	/// 読取り前にハッシュを照合した原UTF-8
	std::string						originalBytes ;
	/// 収集結果が指す原UTF-8の実SHA-256
	IndexManifestSha256				evidenceSha256{} ;
	/// 取得・内容検査で確認した外側配布物のSHA-256と長さ
	IndexManifestSha256				archiveSha256{} ;
	/// 外側の配布物について検査したバイト数
	std::uint64_t					archiveBytes{} ;
	/// 一段内包物の完全相対位置。外側が直接INFを含む場合は空
	std::string						nestedArchiveIdentity ;
	/// 内包物または外側から選択した元INFの完全相対位置
	std::string						infIdentity ;
	/// 元INFが指定した同じ階層のCATの完全相対位置とSHA-256
	std::string						catalogIdentity ;
	/// 元INFと同じ階層で検査したCATの実SHA-256
	IndexManifestSha256				catalogSha256{} ;
	/// 同元INFのClassGUIDの元表記
	std::string						classGuid ;
	/// 公式Catalog詳細本文の実バイト数
	std::uint64_t					catalogDetailsBytes{} ;
	/// 同じ原応答のURL・ハッシュ・時刻と全公式対象。候補添字は持たない
	IndexCatalogHardwareScope		catalog ;
	/// 元INFのハッシュ・明示OS・対象のない節を含む全選択節と元位置
	OfficialInfScopedModelsEvidence models ;
} ;

/** @brief 私有の元証拠を構造検査した結果。署名索引のレコードではない */
struct DecodedCollectorScopedModelsEvidence {
	/// 原値不正・上限・完全読取りを区別する共通診断
	IndexRecordsStatus							 status{IndexRecordsStatus::INVALID_EVIDENCE} ;
	/// 元APIまたは割当て失敗の値
	NativeError									 error{} ;
	/// 完全な読取りに成功した場合だけ保持する値
	std::optional<CollectorScopedModelsEvidence> data ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 既存manifest意味codecを認証型の作成なしで実行します
 * @param[in] bytes 最大64KiBの原UTF-8です
 * @param[in] expectedKeyId 署名側または候補channelで固定したkey IDです
 * @param[in] nowUtc 確認済みUTCです。欠損は拒否します
 * @return 同じschema/期限/asset検査の値結果です。署名検証は行いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] DecodedIndexManifest decodeIndexManifestData(
	std::string_view bytes, std::string_view expectedKeyId,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 実GZip byteを同じhash/容量/圧縮率/CRC規則で検査します
 * @param[in] manifest 呼出側が意味検査済みの値です。認証の有無を表しません
 * @param[in] compressed 最大32MiBの実byteです
 * @param[in] nowUtc 確認済みUTCです
 * @return 未認証の展開値だけを所有する結果です
 */
//------------------------------------------------------------------------------
[[nodiscard]] DecodedIndexAsset decodeIndexAssetData(
	const IndexManifestData &manifest, std::span<const std::byte> compressed,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ検査済み圧縮byteに含まれる追加欄を有限枠で展開します
 * @param[in] manifest 圧縮全byteと一致したmanifest値です
 * @param[in] frame 同じGZipから検出した予約追加欄です。欠損時は空です
 * @param[in] baseExpandedBytes 同じGZipの旧本文展開サイズです
 * @param[in] baseExpandedSha256 同じGZipの旧本文展開hashです
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 追加欄の元期限と検査成功時の展開byteです。署名・公開の権限は発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexAssetSupplementResult decodeIndexSupplementFrame(
	const IndexManifestData &manifest, std::span<const std::byte> frame,
	std::size_t baseExpandedBytes, const IndexManifestSha256 &baseExpandedSha256,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 同じassetのDM領域を本文・世代・期限へ結合して展開します
 * @param[in] manifest 原圧縮を照合した元manifestです
 * @param[in] frame 原圧縮から分離したDMです
 * @param[in] baseExpandedBytes 同じassetの本文展開バイト数です
 * @param[in] baseExpandedSha256 同じ本文の展開ハッシュです
 * @param[in] nowUtc 原内外期限の評価時刻です
 * @return 全検査成立時だけ専用領域の展開バイトを所有します
 * @note 照合値だけを扱い、署名や取得許可を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexAssetSupplementResult decodeIndexScopedModelsFrame(
	const IndexManifestData &manifest, std::span<const std::byte> frame,
	std::size_t baseExpandedBytes, const IndexManifestSha256 &baseExpandedSha256,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 展開byteの原record/schema/参照/qualityを共通codecで検査します
 * @param[in] manifest 同じ原manifestの検査済み値です
 * @param[in] expanded 同じasset値codecの展開byteです
 * @param[in] nowUtc 確認済みUTCです
 * @return 未認証の全値結果です。署名receiptは構築しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] DecodedIndexRecords decodeIndexRecordsData(
	const IndexManifestData &manifest, std::span<const std::byte> expanded,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 追加欄の元証拠、期限、旧本文との合計枠を共通に検査します
 * @param[in] manifest 同じassetに結合したmanifest値です
 * @param[in] baseSources 同じassetの旧本文を構造検査した取得元集合です
 * @param[in] baseRecords 同じassetの旧本文を構造検査したレコード集合です
 * @param[in] transport 同じassetの追加欄の運搬検査結果です
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 取得権限を含まない追加レコードの検査結果です
 * @pre Windows最低buildの根拠を含む追加欄は呼出しworkerのMTAで検査します
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexSupplementRecordsResult decodeIndexSupplementRecordsData(
	const IndexManifestData &manifest, std::span<const IndexRecordSource> baseSources,
	std::span<const IndexDistributionRecord> baseRecords,
	const IndexAssetSupplementResult		&transport,
	std::optional<std::chrono::sys_seconds>	 nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief DMの元証拠・期限・重複と同じ本文の合計枠を照合します
 * @param[in] manifest 元assetに結合済みのmanifestです
 * @param[in] baseSources 同asset本文の検査済み取得元です
 * @param[in] baseRecords 同asset本文の検査済み元レコードです
 * @param[in] transport 同assetのDM運搬検査結果です
 * @param[in] nowUtc 元期限を比較する時点です
 * @return 専用レコードと全参照の成立結果です。署名・取得・公開権限は返しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexSupplementRecordsResult decodeIndexScopedModelsRecordsData(
	const IndexManifestData &manifest, std::span<const IndexRecordSource> baseSources,
	std::span<const IndexDistributionRecord> baseRecords,
	const IndexAssetSupplementResult		&transport,
	std::optional<std::chrono::sys_seconds>	 nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 元投影の全行を圧縮前に追加欄の文法と期限で検査します
 * @param[in] utf8 局所世代1の展開原byteです
 * @param[in] expiry 各行の元期限から得た最短期限です
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 全行の値検査です。圧縮・署名・世代の受理は行いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] DecodedIndexRecords decodePendingCollectorSupplement(
	std::span<const std::byte> utf8, std::chrono::sys_seconds expiry,
	std::chrono::sys_seconds nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 通常収集で生成した専用欄の原レコードと証拠を局所の値として検査します
 * @param[in] utf8 局所世代1の専用欄の圧縮前原バイトです
 * @param[in] expiry 元レコードの同じ原期限です
 * @param[in] nowUtc 検査するUTCです。履歴の再読込みでは元内容検査時刻です
 * @return 完全な構造と元証拠の検査結果です。署名済み索引と公開権限は返しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] DecodedIndexRecords decodePendingCollectorScopedModels(
	std::span<const std::byte> utf8, std::chrono::sys_seconds expiry,
	std::chrono::sys_seconds nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 収集専用のModels証拠の元UTF-8と全対象の一意な元位置を検査する
 * @param[in] utf8 収集結果と一緒に保存した最大512 KiBの原UTF-8
 * @param[in] expectedSha256 同じ収集結果が保持する原UTF-8のSHA-256
 * @return 元バイトの完全一致と構造読取り成功時だけ型付き値を返す
 * @note 署名、元INFの再読取り、候補作成、公開と導入の許可は別途検査する
 */
//------------------------------------------------------------------------------
[[nodiscard]] DecodedCollectorScopedModelsEvidence decodeCollectorScopedModelsEvidence(
	std::string_view utf8, const IndexManifestSha256 &expectedSha256) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 検査済みレコードの元ID又はModels節名に追加欄が必要か判定します
 * @param[in] record 共通codecで構造・元証拠を検査したレコードです
 * @return 元表記が旧文法の範囲を超える場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool indexRecordNeedsSupplement( const IndexDistributionRecord &record) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 通常収集が準備する追加欄付き候補の全行の用途、配置、元期限を検査します
 * @param[in] manifest 同じ実圧縮まで値検査した未署名manifestです
 * @param[in] asset 同manifestの圧縮を値検査した結果です
 * @param[in] base 同assetの旧本文を構造検査した値です。0件を許容します
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 追加レコードの検査値です。失敗時は中間行を返しません
 * @pre Windows最低buildの根拠を含む追加欄は呼出しworkerのMTAで検査します
 * @note 認証、公開又は導入の許可を生成しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexSupplementRecordsResult validateNativeSupplementCandidateData(
	const IndexManifestData &manifest, const DecodedIndexAssetData &asset,
	const DecodedIndexRecordsData &base, std::chrono::sys_seconds nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 確認済みの私有追加欄の運搬結果を同じ索引本文と照合します
 * @param[in] manifest 同じ本文の圧縮と原発行時刻に結ぶmanifestです
 * @param[in] base 同manifestで検査済みの本文です
 * @param[in] transport 原ハッシュ・元期限・展開上限を検査した追加欄です
 * @param[in] nowUtc 両方の元期限を検査する時点です
 * @return 両領域の共通条件が成立した場合に限り、追加レコードを返します
 * @note 署名・公開・導入の許可は発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexSupplementRecordsResult validateNativeSupplementValues(
	const IndexManifestData &manifest, const DecodedIndexRecordsData &base,
	const IndexAssetSupplementResult &transport, std::chrono::sys_seconds nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 型検査済みレコードが既存の内容検査済み取得候補の条件を満たすか確認します
 * @param[in] record 元の取得記述と証拠を持つレコードです
 * @param[in] nowUtc 確認済み現在UTCです
 * @param[in] scopedModels 専用欄で元証拠に結合したv6も検査する場合trueです
 * @return 必須fieldと個別期限が成立した場合trueです。取得許可は発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isInspectedIndexAcquisition( const IndexDistributionRecord &record,
											   std::chrono::sys_seconds		  nowUtc,
											   bool scopedModels = false) noexcept ;
} // namespace drivercrate::signed_index_detail
