//------------------------------------------------------------------------------
/**
 * @file local_collector_campaign.h
 * @brief 公開製品の共有metadata jobと全campaign共通予算を定義します。
 * @version 01.04.01
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  共有job・予算予約・中断回収を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  監督所有storeの単一借用入口を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  共通予算の非変更読込みと精算準備を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/27  復旧監督用の共通controlと固定精算を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  共有job keyの再照合入口を追加。
 * Ver.01.04.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 単一監督threadから使用します。通信・取得grant・導入を実行しません。
 * @see docs/adr/0214-multi-source-collector-campaign.md
 */
//------------------------------------------------------------------------------

#pragma once

#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class LocalCollectorStateStore ;

/** @brief v1とv2監督で共有する一要求の予算予約です。 */
struct CollectorBudgetReservation {
	/// 元campaignまたは日次generationの小文字SHA-256。
	std::wstring  campaign ;
	/// 元共有jobの小文字SHA-256。
	std::wstring  job ;
	/// 組み込みの有限待機group。
	std::wstring  group ;
	/// 予算を予約したUTC秒。予約日のJST日付へ固定します。
	std::uint64_t started{} ;
	/// 一応答の先払いbyte。1～8 MiBです。
	std::uint64_t maximum{} ;
	/// 課金byte。実受信が未知の場合はmaximumを維持します。
	std::uint64_t charged{} ;
	/// 0は未閉鎖、1は結果閉鎖、2は応答なし中断です。
	std::uint32_t phase{} ;
} ;

/** @brief 既存budget v1の保存意味を維持する非変更snapshotです。 */
struct CollectorBudgetSnapshot {
	/// 全予約を課金するJST日付。YYYYMMDDです。
	std::wstring							day ;
	/// 保存済みUTC秒の最高値。読み取っただけでは更新しません。
	std::uint64_t							lastUtc{} ;
	/// 固定保存順の最大1200予約。日次合計は1 GiB以下です。
	std::vector<CollectorBudgetReservation> reservations ;
} ;

/** @brief 元応答intentから固定した精算条件です。 */
struct CollectorBudgetSettlement {
	/// 元応答の完了UTC秒。予約開始時刻以降です。
	std::uint64_t finishedUtcSeconds{} ;
	/// 監督が元応答を受領したUTC秒。回収時刻に置き換えません。
	std::uint64_t acceptedUtcSeconds{} ;
	/// 実受信byteが判明している場合true。未知を0 byte観測にしません。
	bool		  bytesKnown{} ;
	/// 既知の実受信byte。未知時は0の表現ですが課金はmaximumです。
	std::uint64_t receivedBytes{} ;
	/// 応答なしの固定中断intentならtrue。実byteは未知に限定します。
	bool		  interrupted{} ;
} ;

/** @brief 保存を実行せずに準備した予算の更新前後本文です。 */
struct CollectorBudgetPreparedUpdate {
	/// 検査済み更新前canonical本文。
	std::string	 beforeBody ;
	/// 元応答の固定条件から作った更新後canonical本文。
	std::string	 afterBody ;
	/// 更新前本文の小文字SHA-256。
	std::wstring beforeSha256 ;
	/// 更新後本文の小文字SHA-256。
	std::wstring afterSha256 ;
} ;

/**
 * @brief 既存v1と共通のcanonical検査で有限予算本文を復号します。
 * @param[in] bytes 最大768 KiBのUTF-8本文。hash envelopeではありません。
 * @param[out] snapshot 成功時のtyped予算。拒否時は空です。
 * @return schema・phase・日付・合計・canonicalがすべて一致した場合true。
 */
[[nodiscard]] bool parseCollectorBudgetSnapshot( std::string_view		 bytes,
												CollectorBudgetSnapshot &snapshot) ;

/**
 * @brief typed予算を同じv1検査で確認してcanonical本文へ符号化します。
 * @param[in] snapshot 有限の予算。保存日・時計・予約の矛盾を拒否します。
 * @param[out] bytes 成功時のcanonical UTF-8本文。拒否時は空です。
 * @return 同じdecoderで再検証できた場合true。fileは変更しません。
 */
[[nodiscard]] bool encodeCollectorBudgetSnapshot( const CollectorBudgetSnapshot &snapshot,
												 std::string				   &bytes) ;

/** @brief 応答先行回収のために共有予算を変更せず借用します。 */
class LocalCollectorBudgetLedger final {
public:
	/** @brief 空の読込み部品を作成します。 */
	LocalCollectorBudgetLedger() ;
	/** @brief campaign借用を解放します。storeと保存fileは保持します。 */
	~LocalCollectorBudgetLedger() ;
	/**
	 * @brief 共有予算を読むcampaign借用の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorBudgetLedger( const LocalCollectorBudgetLedger &) = delete ;
	/**
	 * @brief 共有予算を読むcampaign借用を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorBudgetLedger &operator=( const LocalCollectorBudgetLedger &) = delete ;

	/**
	 * @brief 共有予算を読み、phase・日付・時計・markerを非変更で検査します。
	 * @param[in,out] store workspaceのwork/state内でwriter初期化済みのstore。
	 * @param[in] utcSeconds 現在の信頼するUTC秒。保存時計より前を拒否します。
	 * @return 成功0、拒否13、未初期化87、競合170または元I/O code。
	 * @pre Storeは本部品より長く存続し、同じ監督threadで使用します。
	 * @note 未登録の初回rootでは予算未存在を返せますがfileは作成しません。
	 * 他campaignの中断・日次切替・保存clockの更新を行いません。
	 */
	[[nodiscard]] DWORD			initializeBorrowed( LocalCollectorStateStore &store,
												   std::uint64_t			 utcSeconds) ;

	/** @brief 初期化時に検証済みの予算が存在したか確認します。
	 * @return 存在した場合true。未初期化・拒否後はfalseです。
	 */
	[[nodiscard]] bool			hasSnapshot() const noexcept ;

	/** @brief 読込み時点の検証済みsnapshotを返します。
	 * @return Object存続中の参照。hasSnapshotがfalseのとき利用しません。
	 */
	[[nodiscard]] const CollectorBudgetSnapshot &snapshot() const noexcept ;

	/**
	 * @brief 未閉鎖予約一件の固定精算本文を準備します。
	 * @param[in] campaign 元予約のcampaignまたはgeneration SHA-256。
	 * @param[in] job 元予約のjob SHA-256。
	 * @param[in] settlement 元応答または中断intentの固定観測。
	 * @param[out] prepared 成功時の更新前後本文。拒否時は空です。
	 * @return 成功0、拒否13または初期化時の元error。
	 * @note 保存・snapshotの変更は行いません。閉鎖予約の再準備を拒否します。
	 * 後続v2監督が応答結合と固定commitの適用順序を確認してから使用します。
	 */
	[[nodiscard]] DWORD prepareSettlement( std::wstring_view campaign, std::wstring_view job,
										  const CollectorBudgetSettlement &settlement,
										  CollectorBudgetPreparedUpdate	  &prepared) ;

	/** @brief 初回の拒否・I/O codeを保持して返します。
	 * @return 成功0、それ以外は元Win32 code。
	 */
	[[nodiscard]] DWORD lastError() const noexcept ;

private:
	/** @brief Store借用と非変更予算の単独所有状態です。 */
	struct State ;
	/// 単一監督threadで保持する状態。
	std::unique_ptr<State> state_ ;
} ;

/** @brief Callerが組み込むmetadata source契約です。manifestの許可ではありません。 */
struct CollectorCampaignSource {
	/// 組み込みsource policyの識別子。
	std::wstring  sourceId ;
	/// 当該sourceのmetadata用途識別子。
	std::wstring  resourceId ;
	/// 別categoryと待機を共有する組み込みgroup。
	std::wstring  rateLimitGroup ;
	/// 使用する固定parser revision。
	std::wstring  parserRevision ;
	/// 一応答のbyte上限。8 MiB以下です。
	std::uint64_t maximumResponseBytes{} ;
} ;

/** @brief 固定分母を構成する公開製品条件です。 */
struct CollectorCampaignTarget {
	/// 評価集合内の公開識別子。
	std::wstring id ;
	/// 公開メーカー名。
	std::wstring maker ;
	/// Revision等を保持した公開製品名。
	std::wstring model ;
	/// OEM_SYSTEM、MAINBOARD等の固定製品種別。
	std::wstring kind ;
	/// 必要なdriver目的。
	std::wstring purpose ;
} ;

/** @brief 同じ検証済みmetadata要求を複数製品へ共有するjobです。 */
struct CollectorCampaignJob {
	/// Source／resource／公開locator／page／parser契約のSHA-256。
	std::wstring			 key ;
	/// Manifestから予算を変更できない組み込みsource契約。
	CollectorCampaignSource	 source ;
	/// 公開modelや公開配布page ID。URLは含みません。
	std::wstring			 publicLocator ;
	/// 明示された公開page locale。
	std::wstring			 locale ;
	/// Sourceが実際に返した有限page番号。1～10です。
	std::uint32_t			 page{} ;
	/// 固定target集合へのindex。重複はありません。
	std::vector<std::size_t> targetIndices ;
} ;

/** @brief 評価planとは別schemaの、非通信で検証した有限実行条件です。 */
struct CollectorCampaignManifest {
	/// 利用者が区別する有限campaign名。
	std::wstring						 campaignId ;
	/// 固定評価planの実byte SHA-256。取得許可ではありません。
	std::wstring						 planSha256 ;
	/// 元manifest実byte SHA-256。
	std::wstring						 manifestSha256 ;
	/// 最大300公開製品の固定順序。
	std::vector<CollectorCampaignTarget> targets ;
	/// 最大300の重複除去したmetadata job。
	std::vector<CollectorCampaignJob>	 jobs ;
} ;

/** @brief Metadata jobの保存状態です。 */
enum class CollectorCampaignJobState {
	/// 未通信のjob。
	PENDING,
	/// 予算予約と開始を永続化したjob。
	RUNNING,
	/// Callerが有限metadata結果hashを渡した状態。公式製品照合ではありません。
	OBSERVED,
	/// Callerのmetadata取得・解析失敗。
	FAILED,
	/// Callerの要確認保留。
	HELD,
	/// 中断後に再送せず最大予約byteを維持したjob。
	INTERRUPTED
} ;

/** @brief 固定製品へのjob結果反映状態です。 */
enum class CollectorCampaignTargetState {
	/// 一つ以上のjobがまだ完了していません。
	PENDING,
	/// Jobが登録されていない製品です。
	UNSUPPORTED,
	/// 全jobがOBSERVEDですが、製品関係とdriver取得は未判定です。
	OBSERVED,
	/// 少なくとも一jobがFAILEDまたはINTERRUPTEDです。
	FAILED,
	/// 少なくとも一jobがHELDです。
	HELD
} ;

/** @brief 保存するjob observationの有限fieldです。 */
struct CollectorCampaignObservation {
	/// 保存jobの状態。
	CollectorCampaignJobState state{CollectorCampaignJobState::PENDING} ;
	/// 予約開始UTC秒。未開始は0です。
	std::uint64_t			  startedUtc{} ;
	/// 結果を受理したUTC秒。未完了は0です。
	std::uint64_t			  finishedUtc{} ;
	/// 実際に受信したbyte数。中断時は不明として0のままです。
	std::uint64_t			  receivedBytes{} ;
	/// HTTP status。応答前失敗は0です。
	std::uint32_t			  httpStatus{} ;
	/// 元の固定診断code。成功は0です。
	std::uint32_t			  error{} ;
	/// OBSERVED時の元本文SHA-256。
	std::wstring			  bodySha256 ;
	/// OBSERVED時の有限metadata射影SHA-256。
	std::wstring			  projectionSha256 ;
} ;

/** @brief 通信executorへ渡す予約済みjobの識別だけを保持します。 */
struct CollectorCampaignDispatch {
	/// Manifest内のjob index。
	std::size_t	  jobIndex{} ;
	/// 完了照合に必要なjob key。
	std::wstring  jobKey ;
	/// この一応答の予約byte上限。
	std::uint64_t maximumResponseBytes{} ;
	/// Executorが取消しに使用する日次wall期限のUTC秒。
	std::uint64_t deadlineUtc{} ;
} ;

/** @brief 監督が次に行える操作です。 */
enum class CollectorCampaignDispatchResult {
	/// 永続化済み予約をexecutorへ渡せます。
	READY,
	/// 同時数／同source／開始間隔待ちです。
	WAIT,
	/// 日次の要求数／byte／時間を使い切りました。
	BUDGET_EXHAUSTED,
	/// 全jobがterminalです。未対応targetの有無とは別です。
	COMPLETE,
	/// Stateまたは入力の拒否です。lastErrorを確認します。
	REJECTED
} ;

/** @brief Fixtureが二file保存窓へ中断を差し込む位置です。 */
enum class CollectorCampaignCheckpoint {
	/// Budget予約保存後、job開始保存前。
	BUDGET_RESERVED,
	/// Job結果保存後、budget予約閉鎖前。
	OBSERVATION_SAVED
} ;

/**
 * @brief 実行manifestを型・重複・有限上限で検証し、共有jobへ正規化します。
 * @param[in] bytes 最大256 KiBのUTF-8 JSON。評価plan schemaは拒否します。
 * @param[in] sources Callerが固定した最大20source・64resourceのmetadata契約。
 * @param[out] manifest 成功時だけ正規化した結果を返します。失敗時は空です。
 * @return 完全な入力検証とhash計算に成功した場合true。
 */
[[nodiscard]] bool parseCollectorCampaignManifest( std::string_view						   bytes,
												  std::span<const CollectorCampaignSource> sources,
												  CollectorCampaignManifest &manifest) ;

/** @brief 共有jobをmanifest parserと同じcanonical算法で再照合します。
 * @param[in] job 元の正規化済みjob。
 * @param[out] key 成功時の小文字SHA-256。失敗時は空。
 * @return 有限identityのhashを計算できた場合true。
 */
[[nodiscard]] bool makeCollectorCampaignJobKey( const CollectorCampaignJob &job, std::wstring &key) ;

/** @brief 全campaignに共通の日次予算と一campaignの保護状態を保持します。 */
class LocalCollectorCampaign final {
public:
	/** @brief 通信を持たない空の監督状態を作成します。 */
	LocalCollectorCampaign() ;
	/** @brief 所有storeを解放するか借用だけを解除します。保存fileは削除しません。 */
	~LocalCollectorCampaign() ;
	/**
	 * @brief 共通予算とcampaign保護状態の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorCampaign( const LocalCollectorCampaign &) = delete ;
	/**
	 * @brief 共通予算とcampaign保護状態を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorCampaign &operator=( const LocalCollectorCampaign &) = delete ;

	/**
	 * @brief 同じ保護rootで予算とcampaignを読み、未完了予約を回収します。
	 * @param[in] root Workspaceのwork/state配下の専用directory。
	 * @param[in] manifest 非通信parserで検証済みの固定条件。
	 * @param[in] contractSha256 実artifactと固定設定のSHA-256。
	 * @param[in] utcSeconds 信頼する時計のUTC秒。JST日付は内部で求めます。
	 * @param[in] stop Fixture専用中断callback。通常callerは空を渡します。
	 * @return 成功0、形式不正13、それ以外は元Win32 error。
	 */
	[[nodiscard]] DWORD		initialize( const std::filesystem::path	   &root,
									   const CollectorCampaignManifest &manifest,
									   std::wstring_view contractSha256, std::uint64_t utcSeconds,
									   std::function<bool( CollectorCampaignCheckpoint)> stop = {}) ;

	/**
     * @brief 監督所有の一つのwriterを借用し、既存v1予算と状態を初期化します。
     * @param[in,out] store work/state配下でwriter初期化済みのstore。
     * @param[in] manifest 検証済みv1の固定条件。
     * @param[in] contractSha256 実artifactと固定設定のSHA-256。
     * @param[in] utcSeconds 信頼するUTC秒。
     * @param[in] stop 非通信fixtureだけの中断callback。
     * @return 成功0、形式不正13、未初期化87、二重借用170またはI/O error。
     * @pre Storeはcoreより長く存続し、同じ監督threadだけで操作します。
     * @note core破棄はwriterを解放しません。他campaign予約のv1回収挙動は維持します。
     * 保存済み応答の先行回収が必要なlive v2へはまだ接続しません。
     */
	[[nodiscard]] DWORD		initializeBorrowed(
			LocalCollectorStateStore &store, const CollectorCampaignManifest &manifest,
			std::wstring_view contractSha256, std::uint64_t utcSeconds,
			std::function<bool( CollectorCampaignCheckpoint)> stop = {}) ;

	/**
	 * @brief 最初のdispatch可能jobを選び、HTTPより前に予算を永続化します。
	 * @param[in] utcSeconds 現在のUTC秒。巻戻しは拒否します。
	 * @param[out] dispatch READY時だけ有効な一job予約を返します。
	 * @return 開始可能・待機・予算不足・全完了・errorの区分。
	 */
	[[nodiscard]] CollectorCampaignDispatchResult reserve( std::uint64_t				 utcSeconds,
														  CollectorCampaignDispatch &dispatch) ;

	/**
	 * @brief 予約済みjobの結果を先に保存し、日次予約を実byteへ閉じます。
	 * @param[in] jobKey RUNNING jobのkey。別jobや重複完了を拒否します。
	 * @param[in] observation OBSERVED／FAILED／HELDの有限結果。
	 * @param[in] utcSeconds 完了を観測したUTC秒。
	 * @return 成功0、拒否13または元Win32 error。中断は995です。
	 */
	[[nodiscard]] DWORD							  finish( std::wstring_view					 jobKey,
														 const CollectorCampaignObservation &observation,
														 std::uint64_t						 utcSeconds) ;

	/**
	 * @brief 完了jobを最大32製品ずつ反映し、途中再開で重複加算しません。
	 * @param[out] applied 今回terminalへ移した製品数。最大32です。
	 * @return 保存成功0、拒否13または元Win32 error。
	 */
	[[nodiscard]] DWORD							  applyResults( std::size_t &applied) ;

	/** @brief 保存jobの現在観測を読みます。
	 * @return Object存続中だけ有効な読み取り専用参照。
	 */
	[[nodiscard]] const std::vector<CollectorCampaignObservation> &observations() const noexcept ;

	/** @brief 固定分母と同順序の製品状態を読みます。
	 * @return Object存続中だけ有効な読み取り専用参照。
	 */
	[[nodiscard]] const std::vector<CollectorCampaignTargetState> &targetStates() const noexcept ;

	/** @brief 最後の拒否またはI/O codeを返します。
	 * @return 成功0、それ以外は数値Win32 code。
	 */
	[[nodiscard]] DWORD											   lastError() const noexcept ;

private:
	/** @brief Writer lockと有限のtyped campaign／budget所有状態です。 */
	struct State ;
	/// initializeから終了まで単独所有する監督状態。
	std::unique_ptr<State> state_ ;
} ;

/** @brief 許可判断を保存せず、開始待ちの理由を返します。 */
enum class CollectorWaitDecision {
	/// 未開始intentがなく、二つの時計・待機を通過しています。
	READY,
	/// 期限または完了後二秒の間隔待ちです。
	WAIT,
	/// 自動解除しない要確認待機です。
	NEEDS_REVIEW,
	/// 先行開始intentがあり、応答回収を先に行う必要があります。
	RECOVERY_REQUIRED
} ;

/** @brief URLを持たない要求と元予約の結合です。 */
struct CollectorWaitRequest {
	/// 固定groupの公開識別子。
	std::wstring group ;
	/// 実HTTP契約のSHA-256。manifest／artifactを含めません。
	std::wstring requestKey ;
	/// 元予約の日次generation SHA-256。
	std::wstring generationKey ;
	/// 元共有job SHA-256。
	std::wstring jobKey ;
} ;

/** @brief 監督が検証した応答から待機へ必要な観測だけを渡します。 */
struct CollectorWaitObservation {
	/// Metadata結果全体の成功。200／304以外は拒否します。
	bool		  successful{} ;
	/// 検証済みHTTP status。応答前失敗は0です。
	std::uint32_t status{} ;
	/// Header検証後の絶対UTC millisecond。欠測は0です。
	std::uint64_t retryAfterUtcMillis{} ;
	/// 不正／重複Retry-After等の自動解除しない保留。
	bool		  needsReview{} ;
	/// Challengeが確認された場合のgroup保留。
	bool		  challenge{} ;
} ;

/** @brief 一つのgroupまたはrequestの待機と開始intentです。 */
struct CollectorWaitControl {
	/// 所属する組み込みgroup。
	std::wstring  group ;
	/// Requestの完全hash。group行では空です。
	std::wstring  request ;
	/// 保存観測のUTC millisecond最高値。
	std::uint64_t observed{} ;
	/// 絶対待機期限。0は期限なしです。
	std::uint64_t notBefore{} ;
	/// Groupの元応答完了UTC millisecond最高値。
	std::uint64_t completed{} ;
	/// 自動解除しない要確認条件。
	bool		  review{} ;
	/// 未回収開始intentの日次generation。
	std::wstring  generation ;
	/// 未回収開始intentのjob。
	std::wstring  job ;
	/// 開始UTC millisecond。完了後は0です。
	std::uint64_t started{} ;
} ;

/** @brief 既存control v1の共通非変更表現です。 */
struct CollectorWaitSnapshot {
	/// 保存台帳のUTC millisecond最高値。
	std::uint64_t								 lastUtc{} ;
	/// g-group／r-hashをkeyとする有限の制御集合。
	std::map<std::wstring, CollectorWaitControl> controls ;
} ;

/** @brief 共通control codecで保存本文を検証します。
 * @param[in] bytes v1 canonical本文。
 * @param[out] snapshot 成功時の型付き値。失敗時は空です。
 * @return 全検査成功時true。
 */
[[nodiscard]] bool			   parseCollectorWaitSnapshot( std::string_view		 bytes,
														  CollectorWaitSnapshot &snapshot) ;

/** @brief 共通control codecで型付き値を検査して符号化します。
 * @param[in] snapshot 最大20 group／300 requestの状態。
 * @param[out] bytes 成功時のcanonical本文。失敗時は空です。
 * @return 保存可能なときtrue。
 */
[[nodiscard]] bool			   encodeCollectorWaitSnapshot( const CollectorWaitSnapshot &snapshot,
														   std::string				   &bytes) ;

/** @brief 元応答時刻から待機の更新後値だけを作ります。
 * @param[in] before 共通codec検証済みの更新前台帳。
 * @param[in] request 元予約と同じ要求identity。
 * @param[in] observation 元応答の検証済み待機観測。
 * @param[in] started 元予約の開始UTC millisecond。
 * @param[in] finished 元応答の完了UTC millisecond。
 * @param[in] accepted 元応答の受領UTC millisecond。
 * @param[in] now 現在の検査UTC millisecond。
 * @param[in] missingStart 予約だけの中断に限り開始intent欠損を許可します。
 * @param[out] after 成功時の更新後値。保存は行いません。
 * @return 全時刻・元予約・開始intentが一致した場合true。
 */
[[nodiscard]] bool			   prepareCollectorWaitSettlement( const CollectorWaitSnapshot	 &before,
															  const CollectorWaitRequest	 &request,
															  const CollectorWaitObservation &observation,
															  std::uint64_t started, std::uint64_t finished,
															  std::uint64_t accepted, std::uint64_t now,
															  bool missingStart, CollectorWaitSnapshot &after) ;

/** @brief 借用storeへmanifest独立の待機と開始intentを保存します。 */
class LocalCollectorWaitLedger final {
public:
	/** @brief 未初期化の監督台帳を作成します。 */
	LocalCollectorWaitLedger() ;
	/** @brief 借用を解除します。storeと保存fileは保持します。 */
	~LocalCollectorWaitLedger() ;
	/**
	 * @brief 待機と開始intentを保存するstore借用の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorWaitLedger( const LocalCollectorWaitLedger &) = delete ;
	/**
	 * @brief 待機と開始intentを保存するstore借用を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorWaitLedger &operator=( const LocalCollectorWaitLedger &) = delete ;

	/**
     * @brief 最大320 controlとmarkerを同じwriterで検証します。
     * @param[in,out] store Writer初期化済みwork/state内store。台帳より長く存続します。
     * @param[in] utcMillis 信頼する現在UTC millisecond。2100年未満です。
     * @param[in] steadyMillis 同じprocessの単調時計millisecond。
     * @return 成功0、拒否13、未初期化87、二重借用170またはI/O error。
     * @note 通信・v2 generation・旧v4 enrollment・応答intent回収は実行しません。
     */
	[[nodiscard]] DWORD		  initialize( LocalCollectorStateStore &store, std::uint64_t utcMillis,
										 std::uint64_t steadyMillis) ;

	/**
     * @brief 旧source・新group／request待機と開始intentを照合します。
     * @param[in] request 組み込み要求と元予約の非機密identity。
     * @param[in] utcMillis 現在のUTC millisecond。
     * @param[in] steadyMillis 同じprocessの単調時計millisecond。
     * @param[out] decision 成功時の開始可否。失敗時はNEEDS_REVIEWです。
     * @return 状態を正常に評価した場合0。通信許可や予算予約を意味しません。
     * @note 新しく観測した旧source待機は新台帳へ最大値で保存します。旧fileは変更しません。
     */
	[[nodiscard]] DWORD		  check( const CollectorWaitRequest &request, std::uint64_t utcMillis,
									std::uint64_t steadyMillis, CollectorWaitDecision &decision) ;

	/**
     * @brief 開始可能な一要求のintentをHTTPより前に永続化します。
     * @param[in] request 永続予算予約へ結合する要求。
     * @param[in] utcMillis 現在のUTC millisecond。
     * @param[in] steadyMillis 単調時計millisecond。
     * @return 成功0、待機1237、拒否13またはI/O error。
     * @pre Callerは共通予算を先に永続予約します。成功だけでGETを許可しません。
     */
	[[nodiscard]] DWORD		  begin( const CollectorWaitRequest &request, std::uint64_t utcMillis,
									std::uint64_t steadyMillis) ;

	/**
     * @brief 一致する開始intentへ応答由来の待機を保存します。
     * @param[in] request 開始intentと同じ元予約。
     * @param[in] observation 監督が検証した非機密応答観測。
     * @param[in] utcMillis 完了UTC millisecond。
     * @param[in] steadyMillis 完了単調時計millisecond。
     * @return 永続化成功0、拒否13またはI/O error。
     * @pre 監督は応答intentを先に保存します。本APIはその保存を代行しません。
     */
	[[nodiscard]] DWORD		  finish( const CollectorWaitRequest		&request,
									 const CollectorWaitObservation &observation, std::uint64_t utcMillis,
									 std::uint64_t steadyMillis) ;

	/**
     * @brief 応答intentがないことを確認した開始要求へ24時間待機を設定します。
     * @param[in] request 保存開始intentと同じ元予約。
     * @param[in] utcMillis 回収UTC millisecond。
     * @param[in] steadyMillis 回収単調時計millisecond。
     * @return 永続化成功0、拒否13またはI/O error。
     * @pre 応答intentがある場合は先にその観測をfinishで回収します。
     */
	[[nodiscard]] DWORD		  recoverInterrupted( const CollectorWaitRequest &request,
												 std::uint64_t utcMillis, std::uint64_t steadyMillis) ;

	/** @brief 拒否後の新規操作を止めるerrorを読みます。
     * @return 成功0、元Win32 codeまたは形式拒否13。
     */
	[[nodiscard]] DWORD		  lastError() const noexcept ;

private:
	friend bool parseCollectorWaitSnapshot( std::string_view, CollectorWaitSnapshot &) ;
	friend bool encodeCollectorWaitSnapshot( const CollectorWaitSnapshot &, std::string &) ;
	/** @brief Store借用、有限control、二時計の単独監督状態です。 */
	struct State ;
	/// 単一監督threadだけが操作するstate。
	std::unique_ptr<State> state_ ;
} ;

} // namespace drivercrate
