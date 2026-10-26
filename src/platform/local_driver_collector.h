//------------------------------------------------------------------------------
/**
 * @file local_driver_collector.h
 * @brief 開発用の公式metadata継続収集と非公開checkpointの契約を定義します。
 * @version 01.11.00
 * @date 2026/09/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/24  非AIの有限metadata収集入口を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/25  台帳権限の検証と元errorの保持を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/25  v2 run識別子と時計・HTTP試験契約を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/25  v3のmetadata再検証と本文・射影結合を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/25  未昇格回収・source待機・空と減少の保留を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  明示収集evidenceの200原byte返却を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  日次receiptと保護本文・due前検査を追加。
 * Ver.01.06.01  Shunji Ogawa  2026/10/16  既定比較の引数と一致条件の契約を明記。
 * Ver.01.07.00  Shunji Ogawa  2026/10/17  原日次予約の非変更照合と明示用途を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/25  同runの明示本体取得と非置換保存sinkを追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/25  呼出し内だけの最初の拒否段階を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/25  明示取得失敗の完全200本文を別診断へ分離。
 * Ver.01.11.00 Shunji Ogawa  2026/10/26 全公開hash・metadata期待値と共通承認readerを追加。
 * </pre>
 *
 * @note 明示日次取得だけが検査用本体へ接続し、driver導入および通常製品scanは行いません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

struct OfficialHttpTransport ;
class OfficialAcquisitionSession ;
class OfficialDownloadWorkspace ;
class IOfficialNetworkCostReader ;
struct OfficialAcquisitionResult ;

/** @brief 同じ日次runだけへ明示する許諾と一file予算です。公式authorityを保持しません。 */
struct LocalCollectorPayloadRequest {
	/// 原release全byteへ明示した許諾同意。既定は未同意です。
	bool						 termsAccepted{} ;
	/// 同意した原parserの許諾revision。完全一致を要求します。
	std::wstring				 termsRevision ;
	/// 同意した抽出全文UTF-8の小文字SHA-256。PAGE全体hashとは別です。
	std::wstring				 termsTextSha256 ;
	/// 承認した原releaseの公表SHA-256。新200との完全一致を要求します。
	std::wstring				 publishedSha256 ;
	/// 承認した公表SHA-512。掲載された全算法を新200と実byteへ照合します。
	std::wstring				 publishedSha512 ;
	/// 承認した公式配布URL。権限ではなく新recordとの完全一致条件です。
	std::wstring				 payloadUrl ;
	/// 承認した配布file名。旧版の同意bindingを別fileへ流用しません。
	std::wstring				 fileName ;
	/// 承認したpackage版。導入適用性の判定には使用しません。
	std::wstring				 packageVersion ;
	/// 公表exact size。欠損は未知、0や上限超過は拒否します。
	std::optional<std::uint64_t> publishedSizeBytes ;
	/// 今回一fileの最大受信byte。公表exact sizeには変換しません。1～128MiBです。
	std::uint64_t				 maximumBytes{} ;
	/// 同意の絶対UTC期限。未知/失効/24h超の同意は取得を開始しません。
	std::uint64_t				 consentNotAfter{} ;
	/// 保護callerが同封印証拠/原byteを再検査し新archiveへatomic非置換commitします。
	std::function<std::int32_t( const OfficialAcquisitionSession &,
							   const OfficialDownloadWorkspace &,
							   const OfficialAcquisitionResult &)>
		commitArchive ;
} ;

/** @brief 保存解析v1/v2の全掲載hashとpayload/terms期待値だけを読みます。
 * @param[in] raw 明示pinを確認済みの有限UTF-8原JSON。呼出し中だけ借用します。
 * @param[out] request 成功時はmetadata期待値だけ、失敗時は空です。同意/予算/authorityは発行しません。
 * @return schema・全algorithm・任意exact size・許諾全文hashが整合する場合trueです。
 */
[[nodiscard]] bool decodeLocalCollectorPayloadApproval( std::string_view				 raw,
													   LocalCollectorPayloadRequest &request) ;

/** @brief 一つの公開製品・公式sourceに対する有限metadata収集条件です。 */
struct LocalCollectorTarget {
	/// 登録済み公式sourceの有限識別子。
	std::wstring source ;
	/// 公開製品model。Intel固定pageでは空です。
	std::wstring publicModel ;
	/// 公式pageに明示するWindows x64条件。
	std::wstring operatingSystem ;
	/// ASUS公式page内の分類。Intel固定pageでは空です。
	std::wstring category ;
	/// 上記四fieldのcanonical byteから計算した秘密非保持key。
	std::wstring keySha256 ;
} ;

/** @brief 許可fieldだけを持つ一件の公式record射影です。 */
struct LocalCollectorRecord {
	/// 既存公式record validatorから得たstable指紋。
	std::wstring	   fingerprint ;
	/// Driver配布行の表示名。製品model適合根拠ではありません。
	std::wstring	   displayTitle ;
	/// 公式recordが示したdriver分類。
	std::wstring	   driverCategory ;
	/// 公式recordが示したWindows条件。
	std::wstring	   operatingSystem ;
	/// 公式recordが示したpackage版。
	std::wstring	   packageVersion ;
	/// 公式recordが示した公開日。
	std::wstring	   publishedDate ;
	/**
	 * @brief 同じ公開field群の差分だけを比較します。
	 * @param[in] other 比較先のsnapshot。変更しない。
	 * @return 全fieldが一致する場合true、それ以外はfalse。
	 */
	[[nodiscard]] bool operator==( const LocalCollectorRecord &other) const = default ;
} ;

/** @brief 日次run内の一targetの状態です。 */
enum class LocalCollectorTargetState {
	/// このrunで未試行のtarget。
	PENDING,
	/// 試行開始をcheckpointへ保存済みのtarget。
	IN_PROGRESS,
	/// 前回成功から公開recordに変更があったtarget。
	UPDATED,
	/// 公式再検証で前回成功と同じrecordを得たtarget。
	UNCHANGED,
	/// 完全な空結果を示す予約状態。現adapterでは未生成です。
	NO_RECORDS,
	/// 今回のmetadata取得または検証に失敗したtarget。
	FAILED,
	/// 空／減少または不明な待機期限を成功にしない保留。
	HELD,
	/// 実行時間または再確認間隔により延期したtarget。
	DEFERRED,
} ;

/** @brief 今回の公式adapter呼出しで最初に拒否した区間です。永続化しません。 */
enum class LocalCollectorFailureStage : std::uint32_t {
	/// 成功、今回未試行、またはこの呼出しでは拒否区間が未観測です。
	NONE = 0U,
	/// 固定request生成または公式session開始の拒否です。
	REQUEST_SESSION = 1U,
	/// 公式metadata取得APIの拒否です。
	METADATA = 2U,
	/// 304の再利用条件または新200の取得証拠の拒否です。
	EVIDENCE = 3U,
	/// 公式page解析または解析後の空entryの拒否です。
	PARSE = 4U,
	/// 解析結果から公式配布recordへの変換の拒否です。
	ADAPT = 5U,
	/// 公式record集合または許可された公開fieldの拒否です。
	RECORD_VALIDATION = 6U,
	/// 同recordの明示本体取得またはarchive保存の拒否です。
	PAYLOAD = 7U,
} ;

/** @brief metadata checkpointと同呼出しだけの明示本体取得結果です。 */
struct LocalCollectorTargetResult {
	/// 固定manifestに対応するkey。
	std::wstring					  keySha256 ;
	/// 今回の組み込み公式source。
	std::wstring					  source ;
	/// 公式pageに渡した公開model。
	std::wstring					  publicModel ;
	/// 明示されたWindows x64条件。
	std::wstring					  operatingSystem ;
	/// 公式driver分類。
	std::wstring					  category ;
	/// 今回の確定または作業中状態。
	LocalCollectorTargetState		  state{LocalCollectorTargetState::PENDING} ;
	/// 直近の成功検証時刻。失敗で更新しません。
	std::uint64_t					  lastSuccessfulValidationAt{} ;
	/// 今回の試行時刻。未試行は0です。
	std::uint64_t					  lastAttemptAt{} ;
	/// 元HRESULT bit pattern。成功・未試行は0です。
	std::uint32_t					  error{} ;
	/// 最後に成功した200本文の受信確認時刻。304で変更しません。
	std::uint64_t					  lastFetchedAt{} ;
	/// 今回のHTTP status。HTTP応答以前の失敗・未試行は0。
	std::uint32_t					  lastHttpStatus{} ;
	/// URLを保存しないtarget・契約・固定requestの結合。
	std::wstring					  requestBindingSha256 ;
	/// 最後に成功した200本文の原byte SHA-256。
	std::wstring					  bodySha256 ;
	/// 保存record群とrequest・本文のcanonical結合。
	std::wstring					  projectionSha256 ;
	/// 有限ASCII subsetのETag。条件付き再確認不可なら空。
	std::wstring					  entityTag ;
	/// Targetの次回試行可能UTC秒。0は追加待機なし。
	std::uint64_t					  nextAttemptAt{} ;
	/// NONE、RETRY_AFTER、EMPTY_RESPONSE、RECORD_DECREASEの固定保留理由。
	std::wstring					  holdReason{L"NONE"} ;
	/// 今回解析で得たrecord数。旧保存record数と区別します。
	std::uint32_t					  observedRecordCount{} ;
	/// 前回成功を含む秘密非保持record群。
	std::vector<LocalCollectorRecord> records ;
	/// 明示evidence modeだけの新200原byte。永続checkpoint・通常UI・logへ渡しません。
	std::string						  rawMetadataBytes ;
	/// 日次modeで保護checkpointへ保存する元200の原byte。通常UI・logへ渡しません。
	std::string						  retainedMetadataBytes ;
	/// 明示日次本体取得が失敗した同呼出しの完全200原byte。永続化・成功利用しません。
	std::string						  failedMetadataBytesThisInvocation ;
	/// 同じ失敗原byteのHTTP取得時SHA-256。旧成功bodySha256と分離し永続化しません。
	std::wstring					  failedBodySha256ThisInvocation ;
	/// 今回の呼出しで公式adapterを試行した場合true。永続化しません。
	bool							  attemptedThisInvocation{} ;
	/// 今回の最初の拒否区間。成功/未試行/再開時はNONEで、checkpointへ保存しません。
	LocalCollectorFailureStage		  failureStageThisInvocation{LocalCollectorFailureStage::NONE} ;
	/// 同呼出しの新200から本体を取得し新archiveへcommitした場合だけtrue。永続化しません。
	bool							  payloadAcquiredThisInvocation{} ;
} ;

/** @brief 一日、一manifestの有限収集結果です。 */
struct LocalCollectorRun {
	/// 台帳の権限・I/Oの元Win32 error。不正状態は13、試験中断は995、成功は0。
	std::uint32_t							stateError{} ;
	/// 対象manifestの実byte SHA-256。
	std::wstring							manifestSha256 ;
	/// 実行binaryと固定収集設定の契約SHA-256。
	std::wstring							contractSha256 ;
	/// JSTのYYYYMMDD。run再開中は固定します。
	std::wstring							day ;
	/// 全targetがterminalになり、pointer確定可能な場合true。
	bool									complete{} ;
	/// 検証済みcheckpointを再利用・再開・commit回収した場合true。永続化しません。
	bool									reusedCheckpoint{} ;
	/// 以前のJST日に開始した未完了runを再開した場合true。永続化しません。
	bool									resumedEarlierDay{} ;
	/// 未昇格の完了runを通信なしでcommit回収した場合true。
	bool									recoveredCommit{} ;
	/// 日次preflightで未到来の最大UTC秒。未設定は0です。永続化しません。
	std::uint64_t							dailyNotBefore{} ;
	/// 当日run作成前のHOLD。未通信で、当日の再起動を固定しません。
	bool									dailyHeld{} ;
	/// 保護storeが単調に予約する運用世代。未通信・HOLDは0です。
	std::uint64_t							dailyGeneration{} ;
	/// 直前の日次receiptの実byte hash。最初の運用世代4では空です。
	std::wstring							dailyPreviousReceiptSha256 ;
	/// Manifest順序と同じtarget結果。
	std::vector<LocalCollectorTargetResult> targets ;
} ;

/** @brief 非通信fixtureで永続化後の途中終了を指定する有限位置です。 */
enum class LocalCollectorCheckpoint {
	/// 最初の未完了run保存後。
	RUN_STARTED,
	/// TargetをIN_PROGRESSとして保存した後、HTTPより前。
	TARGET_STARTED,
	/// 一targetのterminal状態を保存した後。
	TARGET_SAVED,
	/// 完了本文保存後、current pointer更新前。
	RUN_COMPLETED
} ;

/** @brief 非通信fixture専用の時計・HTTP差込みです。通常CLIからは指定できません。 */
struct LocalCollectorTestHooks {
	/// 固定UTC秒。未指定時はOS時計を使用します。
	std::function<std::uint64_t()>							   utcSeconds ;
	/// 固定JST日付。未指定時はOS時計を使用します。
	std::function<std::wstring()>							   jstDay ;
	/// 単調時間。未指定時はsteady_clockを使用します。
	std::function<std::chrono::steady_clock::time_point()>	   steadyNow ;
	/// 既存公式adapterに渡すfake HTTP transport。借用し、call中だけ有効です。
	const OfficialHttpTransport								  *httpTransport{} ;
	/// 明示本体取得のfixture専用回線cost。通常CLIではOS照会だけです。
	IOfficialNetworkCostReader								  *networkCostReader{} ;
	/// 永続化後にtrueを返した位置で中断します。第二引数はtarget番号、run位置ではtarget総数。
	std::function<bool( LocalCollectorCheckpoint, std::size_t)> stopAfterCheckpoint ;
} ;

/**
 * @brief 有限UTF-8 JSON manifestから既存公式sourceに限定したtargetを読み取ります。
 * @param[in] path 実在する通常file。256 KiB以下です。
 * @param[out] targets 成功時だけ1～32 targetを返します。
 * @param[out] sha256 成功時だけ実file SHA-256を返します。
 * @return 完全な形式・重複・公開値検証に成功した場合true。
 */
[[nodiscard]] bool loadLocalCollectorManifest( const std::filesystem::path		&path,
											  std::vector<LocalCollectorTarget> &targets,
											  std::wstring						&sha256) ;

/**
 * @brief 同じstate rootのmetadataを一回収集し、明示時だけ同recordの本体を取得します。
 * @param[in] stateRoot repositoryのwork/state配下の専用directory。
 * @param[in] targets 検証済みmanifestの固定target集合。
 * @param[in] manifestSha256 元manifestの実byte SHA-256。
 * @param[in] dryRun trueではnetwork／状態書込みをせず入力だけを確認します。
 * @param[out] run 成功時または部分失敗時の件数・状態だけを所有する結果。
 * @param[in] retainMetadata true時だけ新200原byteをrunへ返します。再利用・304・失敗から合成しません。
 * @param[in] dailyMode true時はIntel一対象の本文保護保存とrun作成前due検査を行います。
 * @param[in] payload 非nullなら日次新200から一回だけ取得/commitします。call中だけ借用します。
 * @return 全target完了時0、部分失敗時1、入力・状態破損時2、日次due前HOLD時3。
 */
[[nodiscard]] int  runLocalDriverCollector( const std::filesystem::path			   &stateRoot,
										   const std::vector<LocalCollectorTarget> &targets,
										   const std::wstring &manifestSha256, bool dryRun,
										   LocalCollectorRun &run, bool retainMetadata = false,
										   bool								   dailyMode = false,
										   const LocalCollectorPayloadRequest *payload	 = nullptr) ;

/** @brief 開発fixtureだけに時計とHTTPを差し込む同一収集coreです。
 * @param[in] stateRoot 現workspaceのwork/stateの専用保護root。
 * @param[in] targets 完全検証済みの固定target集合。
 * @param[in] manifestSha256 元manifestの実byte指紋。
 * @param[in] dryRun true時はnetwork／state書込みを開始しません。
 * @param[in] hooks 呼出し中だけ借用する非通信の時計／HTTP／停止制御。
 * @param[out] run 成功または部分失敗の所有結果。旧原本文を合成しません。
 * @param[in] retainMetadata true時だけ新200の原byteを返します。
 * @param[in] dailyMode 日次modeの本文保存・run作成前due検査を有効にします。
 * @param[in] payload 明示日次本体取得の同意/予算/保護commit。通常metadataではnullです。
 * @return 完了0、部分失敗1、入力／state拒否2、日次due前HOLD3。
 * @note 同一rootは実lockで直列化し、fixture注入を通常CLIへ公開しません。
 */
[[nodiscard]] int  runLocalDriverCollectorWithHooks(
	 const std::filesystem::path &stateRoot, const std::vector<LocalCollectorTarget> &targets,
	 const std::wstring &manifestSha256, bool dryRun, const LocalCollectorTestHooks &hooks,
	 LocalCollectorRun &run, bool retainMetadata = false, bool dailyMode = false,
	 const LocalCollectorPayloadRequest *payload = nullptr) ;

/** @brief 日次の実200・実304・未通信・HOLDを区別した有限receiptを生成します。
 * @param[in] run 同じ収集coreが返したIntel一対象の結果。参照を保持しません。
 * @param[out] bytes 成功時だけ最大1MiBのJSON。失敗時は空です。
 * @return 実観測なら本文/hash/射影を検証し、未通信・HOLD等との区別を保持できた場合true。
 * @note 通信・保存・署名・取得許可を発行せず、元fetch時刻を304で変更しません。
 */
[[nodiscard]] bool makeLocalCollectorDailyReceipt( const LocalCollectorRun &run, std::string &bytes) ;

/** @brief 同呼出しの完全200失敗本文を原receiptへ結ぶ私有診断JSONにします。
 * @param[in] run 明示日次本体取得の元失敗結果。保持・永続化しません。
 * @param[in] receiptBytes 同runから生成した原daily receipt全byte。最大1MiBです。
 * @param[in] collectorCode 元collector終了値。部分失敗1だけを受理します。
 * @param[out] bytes 成功時だけ最大3MiBの診断JSON。拒否時は空です。
 * @return 今回の完全200・失敗段階・最大2MiB原byte/hash・元receipt一致が成立した場合true。
 * @note 通信・保存・署名・取得権限を発行せず、成功checkpointや成功evidenceを変更しません。
 */
[[nodiscard]] bool makeLocalCollectorFailedPageDiagnostic( const LocalCollectorRun &run,
														  std::string_view		   receiptBytes,
														  int collectorCode, std::string &bytes) ;

/** @brief 原予約の現在入力照合と過去境界照合を区別します。 */
enum class LocalCollectorReservationMode {
	/// 現在契約と現在期限を要求する入力整合確認。
	FRESH_INPUT,
	/// 過去予約の境界factsだけ。現在取得・署名許可ではない。
	LEGACY_FENCE
} ;

/** @brief 原予約の最小公開factsです。本文・path・端末IDを保持しません。 */
struct LocalCollectorReservationFacts {
	/// 成功時だけの原head予約世代。失敗時は0。
	std::uint64_t generation{} ;
	/// 成功時だけの原receipt全byte SHA-256。
	std::wstring  receiptSha256 ;
	/// 固定拒否理由。成功時は空。
	std::wstring  reason ;
} ;

/** @brief 既存writer lock下で原receiptと全旧store・headを非変更照合します。
 * @param[in] stateRoot workspace work/state直下の既存保護root。
 * @param[in] manifestSha256 検証済みIntel一対象manifestの全byte hash。
 * @param[in] receiptBytes 保護readerが固定した原receipt全byte。最大1MiB、call中だけ借用。
 * @param[in] mode 明示用途。定義外値は拒否します。
 * @param[out] facts 成功時だけ世代/hash、失敗時は固定理由だけを返します。
 * @param[in] hooks 非通信fixture専用時計。通常CLIでは既定値を使用します。
 * @return 成功0、欠損・破損・競合・期限・契約不一致は元Win32 errorまたは13。
 * @note 既存lockを取得して同期読取します。新規作成・修復・採番・通信・grant発行は0です。
 *       同じrootのwriterとは排他します。例外を境界外へ渡しません。
 */
[[nodiscard]] std::uint32_t verifyLocalCollectorDailyReservation(
	const std::filesystem::path &stateRoot, const std::wstring &manifestSha256,
	std::string_view receiptBytes, LocalCollectorReservationMode mode,
	LocalCollectorReservationFacts &facts, const LocalCollectorTestHooks &hooks = {}) noexcept ;

} // namespace drivercrate
