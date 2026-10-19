//------------------------------------------------------------------------------
/**
 * @file official_download_delegation.h
 * @brief 公式配布recordに限定するdownload委譲の非機密値型を定義します。
 * @version 01.03.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record証拠とgrant状態の非機密型を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  消費後も終端結果を保持する状態軸を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  認識済み外部expiryの有無をgrantへ保持。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * </pre>
 *
 * @note 本値型はURL、host、path、query、credentialを保持しません。Worker内の秘密URL所有型と
 *       組み合わせるまでnetwork取得権限を表さず、UI、log、cacheへの秘密値伝播を防ぎます。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace drivercrate {

//------------------------------------------------------------------------------
// Record限定download委譲型定義。
//------------------------------------------------------------------------------

/**
 * @brief URLの可変部分を除いた型付き配布recordのSHA-256識別値を表します。
 * @note 全zeroは未設定値です。計算対象と有効性はADR 0152および後続のrecord検証器が決定します。
 */
struct OfficialStableRecordFingerprint {
	/// Stable fieldを正規形へ直列化して計算した32 byte SHA-256。
	std::array<std::byte, 32U> bytes{} ;
} ;

/**
 * @brief 検証済み公式起点から一つの型付き配布recordを得た非機密証拠を表します。
 * @note `rootEvidence`を複製してもnetwork権限は増えず、秘密URLは本型へ格納できません。
 */
struct OfficialDistributionRecordEvidence {
	/// Recordを得た組み込み公式起点のopaque取得証拠。
	OfficialSourceEvidence			rootEvidence ;
	/// 同じscan session内で一意な0ではないrecord証拠ID。
	std::uint64_t					recordEvidenceId{} ;
	/// 型付きrecord parserの単調revision。0は未解析です。
	std::uint32_t					parserRevision{} ;
	/// 秘密URLを除く安定fieldのSHA-256。
	OfficialStableRecordFingerprint stableFingerprint ;
	/// Recordが宣言したpayload行数。1以上32以下だけを後続検証器が受理します。
	std::uint32_t					payloadCount{} ;
	/// Record本文と起点証拠を結合したUTC秒。0は未確定です。
	std::uint64_t					resolvedUtcSeconds{} ;
} ;

/**
 * @brief Record限定download grantで許可するHTTP methodを表します。
 */
enum class OfficialDownloadGrantMethod {
	/// 応答本文を検査用workspaceへ保存するGETだけを許可します。
	GET,
} ;

/**
 * @brief 一つのrecord限定download grantの有限状態を表します。
 * @note `ACQUIRED_FOR_INSPECTION`は内容、適用性または導入可能性の合格を意味しません。
 */
enum class OfficialDownloadGrantState {
	/// Record解決またはgrant発行を開始していません。
	NOT_REQUESTED,
	/// 公式起点、schemaまたはstable fieldを検証できませんでした。
	RECORD_REJECTED,
	/// 一つのrecord payloadだけに有効な未使用grantを発行しました。
	GRANT_ISSUED,
	/// 取得開始前に安全余裕を含む期限を満たさなくなりました。
	GRANT_EXPIRED,
	/// 宛先、method、redirectまたはnetwork境界を拒否しました。
	TARGET_REJECTED,
	/// 再解決したrecordのstable fieldまたはEULAが変化しました。
	RECORD_CHANGED,
	/// Grantをclaimして検査用取得を実行しています。
	ACQUIRING,
	/// 取得物を保護workspaceへ固定しましたが内容検査は未完了です。
	ACQUIRED_FOR_INSPECTION,
	/// 利用者または終了処理が取得を取消しました。
	CANCELLED,
	/// NetworkまたはWindows API処理が失敗しました。
	FAILED,
	/// 一回使用grantを終端結果へ確定し、再使用を拒否します。
	CONSUMED,
} ;

/**
 * @brief URLを公開せず、一つのgrantが結合するrecordとpayloadを表します。
 * @note URL digest、host、path、queryおよびworkspace file名も保持しないため、本値だけでは取得できません。
 */
enum class OfficialDownloadGrantOrigin {
	/// 検証したlive公式起点本文から得たrecordである。
	LIVE_OFFICIAL_NETWORK,
	/// 固定policyが認めた監視PCの署名取得attestationである。
	SIGNED_INDEX_COLLECTOR_ATTESTATION
} ;

/** @brief 非機密metadataの由来は権限ではなく、私有封印で別に検証します。 */
struct RecordScopedDownloadGrantMetadata {
	/// Live起点と署名索引attestationを混同しない由来。
	OfficialDownloadGrantOrigin		origin{OfficialDownloadGrantOrigin::LIVE_OFFICIAL_NETWORK} ;
	/// Grantを所有する0ではないscan session ID。
	ScanSessionId					scanSessionId{} ;
	/// 同じscan session内で単調増加する0ではないgrant ID。
	std::uint64_t					grantId{} ;
	/// Grant発行元のrecord証拠ID。
	std::uint64_t					recordEvidenceId{} ;
	/// Provider registryのstable ID。
	std::wstring					providerId ;
	/// 組み込み公式取得元policyのstable ID。
	std::wstring					policyId ;
	/// Recordを得たlandingまたはmetadata resourceのstable ID。
	std::wstring					rootResourceId ;
	/// 発行時に固定したstable record SHA-256。
	OfficialStableRecordFingerprint recordFingerprint ;
	/// Record内の0起点payload行番号。`payloadCount`未満だけを後続検証器が受理します。
	std::uint32_t					payloadOrdinal{} ;
	/// Grantが許可する唯一のHTTP method。
	OfficialDownloadGrantMethod		method{OfficialDownloadGrantMethod::GET} ;
	/// 現在の有限状態。
	OfficialDownloadGrantState		state{OfficialDownloadGrantState::NOT_REQUESTED} ;
	/// `CONSUMED`時に保持する取得試行の終端結果。未消費では`NOT_REQUESTED`です。
	OfficialDownloadGrantState		outcome{OfficialDownloadGrantState::NOT_REQUESTED} ;
	/// 拒否または失敗のHRESULT bit pattern。成功状態では0です。
	NativeError						error{} ;
	/// Grant発行UTC秒。未発行では0です。
	std::uint64_t					issuedUtcSeconds{} ;
	/// 安全余裕を反映した取得開始期限UTC秒。未発行では0です。
	std::uint64_t					expiresUtcSeconds{} ;
	/// Provider parserが認識済みの外部expiryを明示した場合trueです。
	bool							externalExpiryPresent{} ;
	/// 取得を許可する有限byte上限。未発行では0です。
	std::uint64_t					maximumBytes{} ;
	/// 期限切れ前に公式起点へ戻った回数。0または1だけを後続検証器が受理します。
	std::uint32_t					reresolutionCount{} ;
} ;

} // namespace drivercrate
