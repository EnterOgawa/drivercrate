//------------------------------------------------------------------------------
/**
 * @file official_download_grant.h
 * @brief 型付き公式配布recordの検証と短命download grantを定義します。
 * @version 01.10.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record検証と一回使用grant契約を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Claim済みURLのHTTP request所有権移動を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  各HTTP hop開始前の期限再検証を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/20  公式driver分類をrecord fingerprintへ追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/23  公開SHA-512の任意検証値と独立した結果を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/23  非実行取得専用型と明示有限profileを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  収集専用候補とURL非保持metadata射影を分離。
 * Ver.01.07.00 Shunji Ogawa  2026/09/28  射影fieldの独立説明とmetadata文字境界を明記。
 * Ver.01.08.00 Shunji Ogawa  2026/09/29  収集recordの失敗専用CNG境界probeを分離。
 * Ver.01.09.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.10.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * </pre>
 *
 * @note Provider worker threadだけで直列使用します。Recordは検査用取得の入口であり、内容、適用性、
 *       推奨または導入可能性を保証しません。完全URLは秘密所有型の外へ保存しません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_download_delegation.h"
#include "platform/secret_official_url.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
class SignedIndexAcquisitionAdapter ;
class SignedIndexRecordLookup ;
class OfficialPreparationSession ;
struct OfficialPreparationTask ;
struct IndexLookupContext ;

//------------------------------------------------------------------------------
// 型付き配布record定義。
//------------------------------------------------------------------------------

/**
 * @brief 配布recordが明示するWindows architectureを表します。
 */
enum class OfficialDistributionArchitecture {
	/// DriverCrateが対象とするWindows x64です。
	WINDOWS_X64,
} ;

/**
 * @brief 配布record内の一payloadを後続処理へ渡す方式を表します。
 */
enum class OfficialDistributionPayloadKind {
	/// ADR 0151の共通INF package検査へ渡すarchiveです。
	STANDARD_INF_PACKAGE,
	/// 公式installer監査へ渡す実行形式です。取得だけでは実行を許可しません。
	OFFICIAL_INSTALLER,
	/// Parserは識別したものの現在の検査方式では扱えません。
	UNSUPPORTED,
	/// 未検査ZIP／EXEの取得専用です。内容検査・installer実行へ渡しません。
	DOWNLOAD_ONLY_FILE,
} ;

/** @brief 非実行取得に明示する固定容量profileです。 */
enum class OfficialDownloadOnlyProfile : std::uint64_t {
	/// 取得専用を許可しない既定状態です。
	DISABLED = 0U,
	/// 128 MiBまでの取得専用です。
	STANDARD_128_MIB = 128ULL * 1024ULL * 1024ULL,
	/// 512 MiBまでの取得専用です。
	EXTENDED_512_MIB = 512ULL * 1024ULL * 1024ULL,
	/// 2 GiBまでの取得専用です。全量をmemoryへ保持しません。
	LARGE_2_GIB = 2ULL * 1024ULL * 1024ULL * 1024ULL,
} ;

/** @brief 取得専用payloadが宣言した形式です。実byte検査ではありません。 */
enum class OfficialDownloadOnlyFormat {
	/// 未対応形式またはmetadata不整合です。
	UNKNOWN,
	/// ZIP配布です。内容検査は未実施です。
	ZIP,
	/// Windows EXE配布です。PE・署名検査と実行は未実施です。
	WINDOWS_EXE,
} ;

/**
 * @brief 配布recordが示すdownload前利用条件を表します。
 */
enum class OfficialDistributionTerms {
	/// Provider契約でdownload前の明示同意が不要と確認済みです。
	CONFIRMED_NO_CONSENT,
	/// 固定したrevisionと全文への明示同意が必要です。
	ACCEPTANCE_REQUIRED,
} ;

/**
 * @brief 型付き配布recordが明示した一つのpayload操作を所有します。
 * @note URLはstable fingerprintへ含めず、`SecretOfficialUrl`だけが所有します。
 */
struct OfficialDistributionPayloadRecord {
	/// 組み込みsource policy内のpayload resource ID。
	std::wstring					resourceId ;
	/// Record内の0起点順序。Vector内indexとの一致を要求します。
	std::uint32_t					payloadOrdinal{} ;
	/// 後続の内容検査方式。
	OfficialDistributionPayloadKind kind{OfficialDistributionPayloadKind::UNSUPPORTED} ;
	/// 公式recordが表示するbasename。保存先pathへ直接使用しません。
	std::wstring					fileDisplayName ;
	/// 公式recordが明示したexact byte数。欠落時は未指定です。
	std::optional<std::uint64_t>	publishedSizeBytes ;
	/// 公式recordが明示したSHA-256。欠落時は空です。
	std::wstring					publishedSha256 ;
	/// 公式recordが明示したSHA-512。欠落時は空です。
	std::wstring					publishedSha512 ;
	/// 公式recordまたはProvider契約が明示した署名publisher。欠落時は空です。
	std::wstring					publisher ;
	/// Provider parserが選択した期待応答content type。
	std::wstring					expectedContentType ;
	/// このpayloadに許可する有限受信上限byte数。
	std::uint64_t					maximumBytes{} ;
	/// 認識済み署名URL方式が明示したUTC expiry秒。通常URLでは未指定です。
	std::optional<std::uint64_t>	externalExpiryUtcSeconds ;
	/// Provider worker内だけで所有するrecord直結URL。
	SecretOfficialUrl				targetUrl ;
} ;

/**
 * @brief 明示された三つの非実行取得profileをbyte上限へ解決します。
 * @param[in] profile 呼出元が明示したprofile。
 * @return 既知profileの上限。無効・未知の場合0。
 */
[[nodiscard]] std::uint64_t officialDownloadOnlyMaximumBytes(
	OfficialDownloadOnlyProfile profile) noexcept ;
/**
 * @brief 取得専用payloadの有限profile・公開hash・形式metadataを検証します。
 * @param[in] payload URLを参照せず判定するpayload。
 * @return 条件を満たす宣言形式。不整合時UNKNOWN。実byteを検査した値ではありません。
 */
[[nodiscard]] OfficialDownloadOnlyFormat officialDownloadOnlyFormat(
	const OfficialDistributionPayloadRecord &payload) noexcept ;
/**
 * @brief Parentが明示したprofileへ標準ZIPまたは公式EXEの取得方式を変更します。
 * @param[in,out] payload 成功時だけkindとmaximumBytesを変更するpayload。
 * @param[in] profile 明示的な有限取得上限。
 * @return 形式・公開hash・exact sizeが整合する場合true。失敗時は入力不変。
 * @note 公式根拠・EULA同意を発行しません。変更後は共通record検証とbinding固定が必須です。
 */
[[nodiscard]] bool setOfficialDownloadOnlyProfile( OfficialDistributionPayloadRecord &payload,
												  OfficialDownloadOnlyProfile profile) noexcept ;

/**
 * @brief 一つの公式起点応答から型付きparserが構築する有限配布recordを所有します。
 * @note 本型は秘密URLを含むため、UI、log、cache、crash reportへ複写または永続化しません。
 */
struct OfficialDistributionRecord {
	/// Record本文を得た組み込み公式起点の取得証拠。
	OfficialSourceEvidence			 rootEvidence ;
	/// 同じscan session内で一意な0ではないrecord証拠ID。
	std::uint64_t					 recordEvidenceId{} ;
	/// Provider別の組み込みparser stable ID。
	std::wstring					 parserId ;
	/// Parser契約の単調revision。0は未解析です。
	std::uint32_t					 parserRevision{} ;
	/// 組み込みrootからrecordへ到達した型付きroute ID。
	std::wstring					 recordRoute ;
	/// 公式sourceが明示したstable record key。
	std::wstring					 recordKey ;
	/// 公式sourceが明示した公開製品系列。
	std::wstring					 productFamily ;
	/// 公式sourceが明示したdriver分類。分類を持たないsourceでは空です。
	std::wstring					 driverCategory ;
	/// 公式sourceが明示した対象Windows releaseまたはbranch。
	std::wstring					 operatingSystem ;
	/// Recordが明示した対象architecture。
	OfficialDistributionArchitecture architecture{OfficialDistributionArchitecture::WINDOWS_X64} ;
	/// 公式sourceが明示したpackage版。欠落時は空です。
	std::wstring					 packageVersion ;
	/// 公式sourceが明示した公開日。欠落時は空です。
	std::wstring					 publishedDate ;
	/// Download前利用条件の区分。
	OfficialDistributionTerms		 terms{OfficialDistributionTerms::ACCEPTANCE_REQUIRED} ;
	/// 同意対象の改訂識別子。同意不要の場合は空です。
	std::wstring					 eulaRevision ;
	/// 同意対象のplain text全文。同意不要の場合は空です。
	std::wstring					 eulaText ;
	/// Recordが明示した依存識別子。順序を保持し、推測で追加しません。
	std::vector<std::wstring>		 dependencies ;
	/// Recordが明示した1件以上32件以下のpayload操作。
	std::vector<OfficialDistributionPayloadRecord> payloads ;
	/// Record本文とroot evidenceを結合したUTC秒。
	std::uint64_t								   resolvedUtcSeconds{} ;
} ;

/**
 * @brief 制御付きGETの同一本文から作る収集専用の一時候補です。
 * @note 通常のsource evidenceを持たず、grantへ変換できません。URL／EULA全文はworker内だけに保持します。
 */
struct OfficialCollectorRecordCandidate {
	/// 同一本文内の0ではない候補ID。取得権限の証拠IDではありません。
	std::uint64_t					 recordEvidenceId{} ;
	/// 公式parserのstable ID。
	std::wstring					 parserId ;
	/// Parser契約のrevision。
	std::uint32_t					 parserRevision{} ;
	/// 公式本文内の有限route。
	std::wstring					 recordRoute ;
	/// 公式本文が明示したrecord key。
	std::wstring					 recordKey ;
	/// 公開製品系列。
	std::wstring					 productFamily ;
	/// Driver分類。
	std::wstring					 driverCategory ;
	/// 対象Windows。
	std::wstring					 operatingSystem ;
	/// 対象architecture。
	OfficialDistributionArchitecture architecture{OfficialDistributionArchitecture::WINDOWS_X64} ;
	/// 公開package版。
	std::wstring					 packageVersion ;
	/// 公開日。
	std::wstring					 publishedDate ;
	/// Download前条件。
	OfficialDistributionTerms		 terms{OfficialDistributionTerms::ACCEPTANCE_REQUIRED} ;
	/// EULA revision。
	std::wstring					 eulaRevision ;
	/// Worker内限定のEULA全文。
	std::wstring					 eulaText ;
	/// 公式の依存識別子。
	std::vector<std::wstring>		 dependencies ;
	/// Worker内限定の秘密URLを所有するpayload群。
	std::vector<OfficialDistributionPayloadRecord> payloads ;
	/// 同一本文の検証時刻以降の解決UTC秒。
	std::uint64_t								   resolvedUtcSeconds{} ;
} ;

/** @brief 親へ渡せるURL非保持payload metadataです。 */
struct OfficialCollectorPayloadProjection {
	/// Policy内resource ID。
	std::wstring					resourceId ;
	/// 元record内のordinal。
	std::uint32_t					payloadOrdinal{} ;
	/// 非実行の観測方式。
	OfficialDistributionPayloadKind kind{OfficialDistributionPayloadKind::UNSUPPORTED} ;
	/// 公開表示basename。
	std::wstring					fileDisplayName ;
	/// 公開exact byte数。
	std::optional<std::uint64_t>	publishedSizeBytes ;
	/// 公開SHA-256。
	std::wstring					publishedSha256 ;
	/// 公開SHA-512。
	std::wstring					publishedSha512 ;
	/// 宣言publisher。
	std::wstring					publisher ;
	/// 宣言content type。
	std::wstring					expectedContentType ;
} ;

/** @brief 取得権限・秘密URL・EULA本文を含まない収集専用record射影です。 */
struct OfficialCollectorRecordProjection {
	/// 既存canonicalと同じ値を200本文内で計算した不透明な観測指紋。
	OfficialStableRecordFingerprint	 stableFingerprint ;
	/// 公式parserのstable ID。
	std::wstring					 parserId ;
	/// 配布parser契約のrevision。製品照合ruleとは独立です。
	std::uint32_t					 parserRevision{} ;
	/// 公式本文内の有限route。
	std::wstring					 recordRoute ;
	/// 公式本文が明示したrecord key。
	std::wstring					 recordKey ;
	/// 公開製品系列。
	std::wstring					 productFamily ;
	/// 公式sourceのdriver分類。未掲載の場合は空です。
	std::wstring					 driverCategory ;
	/// 公式sourceが明示した対象Windows。
	std::wstring					 operatingSystem ;
	/// 対象architecture。
	OfficialDistributionArchitecture architecture{OfficialDistributionArchitecture::WINDOWS_X64} ;
	/// 公開package版。
	std::wstring					 packageVersion ;
	/// 公開日。
	std::wstring					 publishedDate ;
	/// Download前条件区分。
	OfficialDistributionTerms		 terms{OfficialDistributionTerms::ACCEPTANCE_REQUIRED} ;
	/// 公開EULA revision。EULA本文は含みません。
	std::wstring					 eulaRevision ;
	/// 公開依存識別子。
	std::vector<std::wstring>		 dependencies ;
	/// URLを持たない公開payload metadata。
	std::vector<OfficialCollectorPayloadProjection> payloads ;
} ;

/**
 * @brief 同一の検証済み200本文から作った候補を検証し、収集専用射影へ変換します。
 * @param[in] candidate Worker内だけの候補。通常evidenceを合成してはなりません。
 * @param[in] policyId 制御付きGETの検証済みsource policy ID。
 * @param[in] resourceId 同GETの検証済みlanding／metadata resource ID。
 * @param[in] bodyValidatedUtcSeconds 同GET本文の検証UTC秒。
 * @param[out] projection 成功時だけURL非保持の所有値を設定します。
 * @return 全fieldとpolicy結合、有限射影、SHA-256計算が成立した場合0。
 * @note 呼出元はbody／policy／resourceの同一GET結合を保証します。本関数は取得証明もgrantも発行しません。
 * @note metadata専用に制御文字・不正Unicode・path／query／端末ID形状とUTF-8 byte上限を検査します。
 * 日付とMIMEに限りfield別のslash文法を認めます。通常record検証の文字列契約は変更しません。
 */
[[nodiscard]] NativeError projectOfficialCollectorRecord(
	const OfficialCollectorRecordCandidate &candidate, std::wstring_view policyId,
	std::wstring_view resourceId, std::uint64_t bodyValidatedUtcSeconds,
	OfficialCollectorRecordProjection &projection) noexcept ;

/** @brief CNG Hash直前に元NTSTATUS失敗だけを注入します。成功時は実hashを実行します。 */
using OfficialCollectorHashProbe = std::function<std::int32_t()> ;

/** @brief 共通record検証へ失敗専用probeを明示する開発入口です。
 * @param[in] candidate 同じGETからのworker限定候補。
 * @param[in] policyId 同GETの組み込みpolicy。
 * @param[in] resourceId 同GETのmetadata用途。
 * @param[in] bodyValidatedUtcSeconds 同GET本文の検証時刻。
 * @param[out] projection 全成功時だけ公開値。失敗時は空。
 * @param[in] probe CNG開始後、Hash直前の非秘密通知。空なら通常動作です。
 * @return 通常検証結果または注入NTSTATUSから変換した元HRESULT。
 * @note Probeへ本文・正規形・digestを渡さず、成功値の注入や再hashを認めません。
 */
[[nodiscard]] NativeError projectOfficialCollectorRecordWithHashProbe(
	const OfficialCollectorRecordCandidate &candidate, std::wstring_view policyId,
	std::wstring_view resourceId, std::uint64_t bodyValidatedUtcSeconds,
	OfficialCollectorRecordProjection &projection,
	const OfficialCollectorHashProbe  &probe) noexcept ;

/**
 * @brief 型付きrecordを有限検証し、URL非保持の証拠とstable fingerprintを作ります。
 * @param[in] record Provider workerが一つの検証済みroot応答から構築したrecord。
 * @param[out] evidence 成功時だけrecord証拠を設定します。失敗時は既定値へ戻します。
 * @return 全field、root evidence、payload集合とSHA-256計算の成功時は0、それ以外はHRESULT bit pattern。
 * @note URLは存在と文字数だけを確認し、fingerprintへ含めません。HTTPS宛先検証はHTTP境界で行います。
 */
[[nodiscard]] NativeError validateOfficialDistributionRecord(
	const OfficialDistributionRecord   &record,
	OfficialDistributionRecordEvidence &evidence) noexcept ;

//------------------------------------------------------------------------------
// Record限定grant定義。
//------------------------------------------------------------------------------

/**
 * @brief HTTP／取得境界へ一時的に貸し出すgrant payload viewを表します。
 * @note `targetUrl`はgrantが`ACQUIRING`の間だけ非空です。全viewはgrantより長く保持しません。
 */
struct RecordScopedDownloadGrantPayloadView {
	/// 呼出し中だけ参照する完全URL。保存、表示、記録してはなりません。
	std::wstring_view				targetUrl ;
	/// 組み込みsource policy内のpayload resource ID。
	std::wstring_view				resourceId ;
	/// 後続の内容検査方式。
	OfficialDistributionPayloadKind kind{OfficialDistributionPayloadKind::UNSUPPORTED} ;
	/// 公式表示basename。保存先pathへ直接使用しません。
	std::wstring_view				fileDisplayName ;
	/// 公式recordのexact byte数。欠落時は未指定です。
	std::optional<std::uint64_t>	publishedSizeBytes ;
	/// 公式recordのSHA-256。欠落時は空です。
	std::wstring_view				publishedSha256 ;
	/// 公式recordのSHA-512。欠落時は空です。
	std::wstring_view				publishedSha512 ;
	/// 署名publisher。欠落時は空です。
	std::wstring_view				publisher ;
	/// 期待応答content type。
	std::wstring_view				expectedContentType ;
	/// 有限受信上限byte数。
	std::uint64_t					maximumBytes{} ;
} ;

/**
 * @brief 一つのrecord payloadへ15分以内・一回だけの取得権限を所有します。
 * @note 完全URLは本object内だけで所有し、全終端経路と上書き時に消去します。
 */
class RecordScopedDownloadGrant final {
public:
	/**
	 * @brief 未発行のgrant objectを作成します。
	 * @post `metadata().state`は`NOT_REQUESTED`です。
	 */
	RecordScopedDownloadGrant() noexcept = default ;

	/**
	 * @brief 秘密URLとsession内target fingerprintを消去します。
	 */
	~RecordScopedDownloadGrant() noexcept ;

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	RecordScopedDownloadGrant( const RecordScopedDownloadGrant &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	RecordScopedDownloadGrant &operator=( const RecordScopedDownloadGrant &) = delete ;

	/**
	 * @brief Grant metadataと秘密URLの所有権を移動します。
	 * @param[in,out] other 未発行状態へ戻る移動元。
	 * @post `other.metadata().state`は`NOT_REQUESTED`です。
	 */
	RecordScopedDownloadGrant( RecordScopedDownloadGrant &&other) noexcept ;

	/**
	 * @brief 現在の秘密URLを消去し、別grantの所有権を移動します。
	 * @param[in,out] other 未発行状態へ戻る移動元。自己代入も許可します。
	 * @return このobjectへの参照。
	 * @post 自己代入でない場合、`other.metadata().state`は`NOT_REQUESTED`です。
	 */
	RecordScopedDownloadGrant &operator=( RecordScopedDownloadGrant &&other) noexcept ;

	/**
	 * @brief 検証済みrecordの一payloadを消費し、短命grantを発行します。
	 * @param[in,out] record 成功時だけ対象payloadの秘密URL所有権を失う型付きrecord。
	 * @param[in] evidence 同じrecordから作成したURL非保持証拠。
	 * @param[in] payloadOrdinal 発行対象の0起点payload行番号。
	 * @param[in] grantId 同じscan session内で一意な0ではないgrant ID。
	 * @param[in] issuedUtcSeconds 発行時点のUTC秒。
	 * @param[in] reresolutionCount 組み込みrootから再解決した回数。初回0、再解決後1です。
	 * @return 発行成功時は0、不正record、証拠不一致、期限不足または再発行はHRESULT bit pattern。
	 * @pre このobjectは一度も発行していないこと。
	 * @post 成功時は`GRANT_ISSUED`、失敗時は秘密URLを取得せず`NOT_REQUESTED`を維持します。
	 */
	[[nodiscard]] NativeError  issue( OfficialDistributionRecord				  &record,
									 const OfficialDistributionRecordEvidence &evidence,
									 std::uint32_t payloadOrdinal, std::uint64_t grantId,
									 std::uint64_t issuedUtcSeconds,
									 std::uint32_t reresolutionCount) ;

	/**
	 * @brief Sessionとgrant ID、30秒の期限余裕を照合して一回だけ取得開始をclaimします。
	 * @param[in] scanSessionId 現在のworker scan session ID。
	 * @param[in] grantId 呼出し側が保持するopaque grant ID。
	 * @param[in] nowUtcSeconds Request開始直前のUTC秒。
	 * @return Claim成功時は0、stale、期限切れまたは再使用時はHRESULT bit pattern。
	 * @post 成功時は`ACQUIRING`です。期限切れ時は秘密URLを消去して`CONSUMED`へ移ります。
	 */
	[[nodiscard]] NativeError  claim( ScanSessionId scanSessionId, std::uint64_t grantId,
									 std::uint64_t nowUtcSeconds) noexcept ;

	/**
	 * @brief Claim前の拒否または取消しを終端結果として一回だけ確定します。
	 * @param[in] outcome `GRANT_EXPIRED`、`TARGET_REJECTED`、`RECORD_CHANGED`、`CANCELLED`または`FAILED`。
	 * @param[in] error 0ではない具体的なHRESULT bit pattern。
	 * @return 終端確定成功時は0、不正状態・結果・診断値はHRESULT bit pattern。
	 * @post 成功時は秘密URLを消去し、stateを`CONSUMED`、outcomeを指定値へ設定します。
	 */
	[[nodiscard]] NativeError  finishBeforeAcquisition( OfficialDownloadGrantState outcome,
													   NativeError				  error) noexcept ;

	/**
	 * @brief 取得開始後の成功、拒否、取消しまたは失敗を一回だけ確定します。
	 * @param[in] outcome `ACQUIRED_FOR_INSPECTION`、`GRANT_EXPIRED`、`TARGET_REJECTED`、`CANCELLED`または`FAILED`。
	 * @param[in] error 成功結果では0、その他では0ではないHRESULT bit pattern。
	 * @return 終端確定成功時は0、不正状態・結果・診断値はHRESULT bit pattern。
	 * @post 成功時は秘密URLを消去し、stateを`CONSUMED`、outcomeを指定値へ設定します。
	 */
	[[nodiscard]] NativeError  finishAcquisition( OfficialDownloadGrantState outcome,
												 NativeError				error) noexcept ;

	/**
	 * @brief URLを含まない現在のgrant metadataを参照します。
	 * @return Object lifetime中有効な非所有参照。
	 */
	[[nodiscard]] const RecordScopedDownloadGrantMetadata &metadata() const noexcept ;

	/**
	 * @brief Claim済みgrantのpayloadをHTTP／取得境界へ貸し出します。
	 * @return `ACQUIRING`の間だけ秘密URLを含むview。それ以外はURLが空のviewです。
	 * @warning 戻り値と各viewを本objectの次の操作より長く保持してはなりません。
	 */
	[[nodiscard]] RecordScopedDownloadGrantPayloadView	   payloadView() const noexcept ;

	/**
	 * @brief Claim済みの秘密URL所有権を一回のHTTP requestへ移します。
	 * @return `ACQUIRING`中でURLが未移動ならその所有値。それ以外は空です。
	 * @post 成功時はgrant内のURLが空になり、stateは`ACQUIRING`を維持します。
	 * @warning 戻り値はworker内の専用HTTP requestだけが所有してください。
	 */
	[[nodiscard]] SecretOfficialUrl						   takeTargetUrlForHttp() noexcept ;

	/**
	 * @brief Claim済みgrantがrequest開始の30秒余裕を保つか再検証します。
	 * @param[in] nowUtcSeconds 当該requestまたはredirect開始直前のUTC秒。
	 * @return 開始可能なら0、状態不整合・時計異常・期限不足はHRESULT bit pattern。
	 * @note 開始済みstreamの成功可否は本関数で再評価しません。
	 */
	[[nodiscard]] NativeError							   validateRequestStartDeadline(
									 std::uint64_t nowUtcSeconds) const noexcept ;

	/**
	 * @brief 再解決した秘密URLが消費済みgrantと同じtargetか比較します。
	 * @param[in] candidate 再解決recordが所有する完全URL。
	 * @param[out] sameTarget 成功時に同じURLならtrue、異なるURLならfalse。
	 * @return 比較成功時は0、状態不整合・空URL・hash失敗はHRESULT bit pattern。
	 * @warning URLとfingerprintを返さず、再解決worker内だけで使用してください。
	 */
	[[nodiscard]] NativeError compareConsumedTarget( std::wstring_view candidate,
													bool			 &sameTarget) const noexcept ;
	/** @brief 署名索引grantの失効leaseと同scanの非公開元lookupを照合します。
	 * @param[in] scanSessionId 現取得session。
	 * @return 元封印とissuerが生存し同scanの場合0。それ以外は拒否HRESULT。
	 */
	[[nodiscard]] NativeError validateSignedIndexAuthority(
		ScanSessionId scanSessionId) const noexcept ;
	/** @brief 封印した署名索引routeのexact URL順を再照合します。
	 * @param[in] exactTarget 現HTTP hopのURL。本呼出し中だけ借用します。
	 * @param[in] hop 0起点のhop位置。
	 * @param[in] finalResponse HTTP 200に達した場合だけtrue。
	 * @return 生存権限・URL完全一致・終端位置が成立した場合0。
	 */
	[[nodiscard]] NativeError validateSignedIndexHop( std::wstring_view exactTarget,
													 std::uint32_t	   hop,
													 bool finalResponse) const noexcept ;

private:
	friend class SignedIndexAcquisitionAdapter ;
	friend class OfficialAcquisitionSession ;
	/** @brief 非公開adapterが実taskとsnapshotを再確認して同じgrantを発行します。
	 * @param[in,out] adapter 失効可能な元issuer。
	 * @param[in] preparation 実claimを保持するsession。
	 * @param[in] task 同じ未完了task。
	 * @param[in] current 現worker context。
	 * @param[in] nowUtcSeconds 発行UTC秒。
	 * @return 全sealed bindingの成立時0。未発行の入力だけを受理します。
	 */
	[[nodiscard]] NativeError	   issueSignedIndex( SignedIndexAcquisitionAdapter &adapter,
													OfficialPreparationSession	  &preparation,
													const OfficialPreparationTask &task,
													IndexLookupContext			   current,
													std::uint64_t				   nowUtcSeconds) ;
	/// Snapshotの共有所有とは独立した元adapterの弱い失効lease。
	std::weak_ptr<const std::byte> signedIndexIssuer_ ;
	/// 元workerの取得閉鎖状態。消費済み成功根拠だけを閉鎖後に参照できます。
	std::weak_ptr<const bool>	   signedIndexAcquisitionOpen_ ;
	/// 非公開構築の同scan関係と原snapshotを保持する封印。生存能力には使いません。
	std::shared_ptr<const SignedIndexRecordLookup> signedIndexLookup_ ;
	/// 封印した関係の0起点位置。公開tupleは受理しません。
	std::size_t									   signedIndexRelationIndex_{} ;
	/// 認証済み一payloadのexact URL順。終端で消去します。
	std::vector<SecretOfficialUrl>				   signedIndexRoute_ ;
	/**
	 * @brief 終端結果を検証済みとして保持し、秘密URLを消去します。
	 * @param[in] outcome 保持する終端結果。
	 * @param[in] error 結果と整合する診断値。
	 * @post Stateは`CONSUMED`です。
	 */
	void consume( OfficialDownloadGrantState outcome, NativeError error) noexcept ;

	/**
	 * @brief 移動元の全所有値を引き取り、移動元を未発行へ戻します。
	 * @param[in,out] other 所有権を失う移動元。
	 */
	void moveFrom( RecordScopedDownloadGrant &other) noexcept ;

	/// URL非保持のgrant bindingと状態。
	RecordScopedDownloadGrantMetadata metadata_ ;
	/// HTTP／取得境界へ渡すまでworker内で所有する秘密URL。
	SecretOfficialUrl				  targetUrl_ ;
	/// 組み込みsource policy内のpayload resource ID。
	std::wstring					  resourceId_ ;
	/// 後続の内容検査方式。
	OfficialDistributionPayloadKind	  kind_{OfficialDistributionPayloadKind::UNSUPPORTED} ;
	/// 公式recordが表示するbasename。
	std::wstring					  fileDisplayName_ ;
	/// 公式recordが明示したexact byte数。
	std::optional<std::uint64_t>	  publishedSizeBytes_ ;
	/// 公式recordが明示したSHA-256。
	std::wstring					  publishedSha256_ ;
	/// Grant発行時に固定した任意SHA-512。
	std::wstring					  publishedSha512_ ;
	/// 公式recordまたはProvider契約が明示した署名publisher。
	std::wstring					  publisher_ ;
	/// Provider parserが選択した期待応答content type。
	std::wstring					  expectedContentType_ ;
	/// 同じ拒否URLへの再発行を防ぐscan session内だけのSHA-256。
	OfficialStableRecordFingerprint	  targetFingerprint_ ;
	/// Target fingerprintを正常に計算して保持する場合true。
	bool							  targetFingerprintPresent_{} ;
} ;

} // namespace drivercrate
