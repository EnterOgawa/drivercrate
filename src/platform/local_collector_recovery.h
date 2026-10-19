//------------------------------------------------------------------------------
/**
 * @file local_collector_recovery.h
 * @brief 応答先行の固定commitとv2登録監督を定義します。
 * @version 01.27.01
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  固定応答・更新前後像による回収監督を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  保存容量の非変更判定を共用し境界検証へ接続。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  非変更readinessと元予約の有限deadlineを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/27  v3観測保存と制御予約の旧accept拒否を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  射影予約のmode識別を追加。新予約は未発行。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  v3登録・世代別再読込と旧世代回収待機を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  射影予約と四role中断回収を追加。
 * Ver.01.06.01 Shunji Ogawa  2026/09/28  新予約の全対象scope結合を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/29  専用workerだけの非変更readinessを追加。
 * Ver.01.08.00 Shunji Ogawa  2026/09/29  初回専用の全join・所有予約・非保存prepareを追加。
 * Ver.01.09.00 Shunji Ogawa  2026/09/29  予約前の空履歴固定と応答・CACHE候補の同時準備を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/09/30  登録済み履歴の読取り専用検証を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/09/30  初回所有結果のv4保存・四role精算入口を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/09/30  初回世代の完了保存・回復と追加容量検査を追加。
 * Ver.01.13.00 Shunji Ogawa  2026/09/30  初回完了履歴の全inventoryを読取り専用contextへ接続。
 * Ver.01.14.00 Shunji Ogawa  2026/09/30  全完了世代・全CACHE鎖・元日archiveの読取り検査を追加。
 * Ver.01.15.00 Shunji Ogawa  2026/09/30  全完了検査coreを通常非変更再読込みへ接続。
 * Ver.01.16.00 Shunji Ogawa  2026/09/30  明示次回開始・未応答末尾・所有履歴予約を追加。
 * Ver.01.17.00 Shunji Ogawa  2026/09/30  次世代所有結果の履歴保存・末尾完了を追加。
 * Ver.01.18.00 Shunji Ogawa  2026/09/30  次世代の未登録応答・準備prefix復旧を追加。
 * Ver.01.19.00 Shunji Ogawa  2026/09/30  登録commitと反映途中の非再送復旧を追加。
 * Ver.01.20.00 Shunji Ogawa  2026/10/01  再起動した次世代RUNNINGの明示中断精算を追加。
 * Ver.01.21.00 Shunji Ogawa  2026/10/01  次世代の二開始保存prefixを明示中断へ接続。
 * Ver.01.21.01 Shunji Ogawa  2026/10/01  所有受領の注釈を二開始prefix対応へ整合。
 * Ver.01.22.00 Shunji Ogawa  2026/10/01  全完了履歴からの日次切替prefix回復を追加。
 * Ver.01.22.01 Shunji Ogawa  2026/10/01  明示中断と通常全完了の日次復旧を注釈で区別。
 * Ver.01.23.00 Shunji Ogawa  2026/10/01  全履歴先行検査済みの末尾完了prefix復旧を追加。
 * Ver.01.23.01 Shunji Ogawa  2026/10/01  起動・受領・完了の注釈を有限suffix復旧へ整合。
 * Ver.01.24.00 Shunji Ogawa  2026/10/01  読取り容量の部分観測を非変更診断へ追加。
 * Ver.01.25.00 Shunji Ogawa  2026/10/02  全完了v3 rootの実raw封印contextを追加。
 * Ver.01.26.00 Shunji Ogawa  2026/10/02  同親結合専用の私有同時再照合入口を追加。
 * Ver.01.27.00 Shunji Ogawa  2026/10/02  HTTP実所有の私有発行とfreeze拒否を追加。
 * Ver.01.27.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 開発用の単一writer監督です。明示中断・日次切替／末尾完了prefix回復に対応し、通常CLIは後続です。
 */
//------------------------------------------------------------------------------
#pragma once

#include "local_collector_campaign.h"
#include "official_collector_http_control.h"
#include "local_collector_http_activity.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 既存raw読取りの容量拒否箇所です。他の68を推定分類しません。 */
enum class CollectorHistoryCapacity {
	/// 当観測でraw容量拒否を記録していません。全検査成功の意味ではありません。
	NONE,
	/// 今回のrawを課金すると64 MiB累積を超えます。
	RAW_BYTES,
	/// 新しい参照名を加えると6,000名を超えます。
	REFERENCE_NAMES
} ;

/** @brief 読取り専用入口の部分観測です。context・保存／取得権限ではありません。 */
struct CollectorHistoryReadDiagnostics {
	/// 同じfileの再読取りも含む、成功して課金したraw byte合計。
	std::size_t				 chargedBytes{} ;
	/// 最後の成功store.readで得たraw byte。容量拒否時は未課金の場合があります。
	std::size_t				 attemptedBytes{} ;
	/// 不在名も含む、最初のidentityを登録済みの参照名数。
	std::size_t				 referencedNames{} ;
	/// 成功store.readの回数。後続hash／関係検査の成功数ではありません。
	std::size_t				 readCalls{} ;
	/// 公開前の最終raw再照合へ入った場合だけtrueです。
	bool					 recheckStarted{} ;
	/// 既存raw容量requireの直前で観測した拒否分類です。
	CollectorHistoryCapacity capacity{CollectorHistoryCapacity::NONE} ;
} ;

struct CollectorStoreUsage ;
struct CollectorProjectedCampaignDefinition ;
class LocalCollectorProjectedExecutor ;
struct CollectorProjectedResponseBytes ;
struct CollectorProjectedPreparedUpdate ;
class CollectorRegisteredProjectedHistory ;
class CollectorPreparedProjectedJob ;
class CollectorCompletedRootInventory ;
struct CollectorCompletedRootEvidence ;
enum class CollectorProjectedHashStage ;

/** @brief 四roleとCACHEの保守的な追加保存枠を検査します。
 * @param[in] usage 現在の全保存量。
 * @param[in] jobCount 0～300のjob数。
 * @param[in] requestCount 0～jobCountの異なるrequest数。
 * @return 成功0、容量不足68、範囲外87。
 */
[[nodiscard]] DWORD checkCollectorProjectedRecoveryCapacity( const CollectorStoreUsage &usage,
															std::size_t				   jobCount,
															std::size_t requestCount) noexcept ;

/** @brief 四role保存枠に初回完了記録の有限枠を加えて検査します。
 * @param[in] usage 既存の全entry／byte。
 * @param[in] jobCount 元入力の0～300 job。
 * @param[in] requestCount 異なるrequest数。jobCount以下です。
 * @return 成功0、範囲外87、容量不足68。保存はしません。
 */
[[nodiscard]] DWORD checkCollectorProjectedCompletionCapacity( const CollectorStoreUsage &usage,
															  std::size_t				 jobCount,
															  std::size_t requestCount) noexcept ;

/** @brief 元保存量と固定job数から全応答・前後像の有限保存枠を検査します。
 * @param[in] usage 保護handleで集計した既存entry／byte。ここではfileを読みません。
 * @param[in] jobCount 元入力のjob数0～300。
 * @return 容量内0、容量不足68、範囲外job数87。保存・削除・予約は行いません。
 */
[[nodiscard]] DWORD checkCollectorRecoveryCapacity( const CollectorStoreUsage &usage,
												   std::size_t				  jobCount) noexcept ;

/** @brief 固定manifestと組み込みsourceから構成する監督入力です。 */
struct CollectorRecoveryInput {
	/// 元の公開manifest本文。実byte hashを保存します。
	std::string							 manifestBytes ;
	/// 呼出し側が固定するsource registry。manifestから許可を作りません。
	std::vector<CollectorCampaignSource> sources ;
	/// 実binaryとsourceに結合したartifact契約。
	std::wstring						 artifactSha256 ;
	/// 重複除去済みjobと同順序の公開request hash。
	std::vector<std::wstring>			 requestKeys ;
	/// Parser／artifact／policy／scopeへ別に結合するcache hash。
	std::vector<std::wstring>			 cacheBindings ;
} ;

/** @brief 保存前に型と有限値を検証する非実行応答です。 */
struct CollectorRecoveryResponse {
	/// 実送信回数0／1。未観測はnulloptであり、予約数とは区別します。
	std::optional<std::uint32_t> sentRequests ;
	/// OBSERVED／FAILED／HELDだけを受理します。
	CollectorCampaignJobState	 state{CollectorCampaignJobState::FAILED} ;
	/// 元workerの完了UTC millisecond。
	std::uint64_t				 finishedUtcMillis{} ;
	/// 元監督の受領UTC millisecond。
	std::uint64_t				 acceptedUtcMillis{} ;
	/// 未知の実byteを0観測と区別します。
	bool						 bytesKnown{} ;
	/// 既知の受信byte。未知の場合は0表現です。
	std::uint64_t				 receivedBytes{} ;
	/// 応答前失敗0、または検証済みHTTP status。
	std::uint32_t				 status{} ;
	/// 元の非機密数値error。
	std::uint32_t				 error{} ;
	/// 旧v2はNONE／WIN32／HTTP／PARSER、制御付きv3だけWINSOCK／HRESULTも許可します。
	std::wstring				 errorDomain{L"NONE"} ;
	/// 検証済み絶対待機。未指定0です。
	std::uint64_t				 retryAfterUtcMillis{} ;
	/// 自動解除しない応答由来の要確認。
	bool						 needsReview{} ;
	/// Challengeの確認結果。
	bool						 challenge{} ;
	/// 本文hash。未取得・未観測は空です。
	std::wstring				 bodySha256 ;
	/// 元射影hash。取得・製品適合の認定ではありません。
	std::wstring				 projectionSha256 ;
} ;

/** @brief 保存窓fixtureだけに使う有限checkpointです。 */
enum class CollectorRecoveryCheckpoint {
	/// 日次予算だけを先払いしました。
	RESERVED,
	/// 開始intentを保存しました。
	STARTED,
	/// JobのRUNNINGを保存しました。
	RUNNING,
	/// 元応答intentをimmutable保存しました。
	RESPONSE,
	/// 更新前後像を全role分保存しました。
	EFFECTS,
	/// 固定commitをrootへ登録しました。
	REGISTERED,
	/// 各roleのatomic保存後です。
	APPLIED,
	/// Commitを完了しました。
	COMPLETED,
	/// 共通root初回登録後、generation未作成の保存窓です。
	ROOT_ENROLLED,
	/// 検証済み旧rootをv3へ移行する直前です。
	BEFORE_ROOT_UPGRADE,
	/// Root v3のatomic保存後です。
	ROOT_UPGRADED,
	/// 新generation入力をimmutable保存しました。
	PROJECTED_INPUT,
	/// 新generation markerをimmutable保存しました。
	PROJECTED_MARKER,
	/// 新generation初期stateを保存しました。
	PROJECTED_STATE,
	/// 新generationをrootへ登録しました。
	PROJECTED_REGISTERED,
	/// 新四roleの各準備effect保存後。共有fileは未変更です。
	PROJECTED_EFFECT,
	/// 新四roleの更新前像だけを保存した窓。
	PROJECTED_BEFORE_EFFECT,
	/// 初回世代の固定完了intentを保存しました。
	FINISH_INTENT,
	/// 対象順を保った完了shardを保存しました。
	FINISH_SHARD,
	/// 固定分母の完了summaryを保存しました。
	FINISH_SUMMARY,
	/// 完了generation pointerを保存しました。
	FINISH_POINTER,
	/// Rootのsummary登録とactive解除を同時確定しました。
	FINISH_REGISTERED,
	/// 全完了履歴からの日次切替intentを固定保存しました。
	DAY_ROLL_INTENT,
	/// 日次切替の三準備像の各保存後です。共有台帳は未変更です。
	DAY_ROLL_EFFECT
} ;

/** @brief 次のHTTP接続へ渡す、永続化済みの有限予約です。 */
struct CollectorRecoveryDispatch {
	/** @brief 旧制御予約と新射影予約を混用しない固定modeです。 */
	enum class Mode {
		/// 旧v3までの制御付き予約。
		CONTROLLED,
		/// 新metadata射影専用予約。開発用poolからのみ発行します。
		PROJECTED
	} ;
	/// 旧制御予約を既定とし、新射影予約は明示指定だけで作ります。
	Mode					mode{Mode::CONTROLLED} ;
	/// 入力jobの固定index。
	std::size_t				jobIndex{} ;
	/// 登録済みgeneration hash。
	std::wstring			generationKey ;
	/// 元予約と開始intentの共通開始時刻。
	std::uint64_t			startedUtcMillis{} ;
	/// 元入力のjob key。
	std::wstring			jobKey ;
	/// 公開requestへ結合した恒久key。
	std::wstring			requestKey ;
	/// Parser・artifact等へ結合したcache key。
	std::wstring			cacheBinding ;
	/// 新射影modeの全対象scope。旧modeでは空です。
	std::wstring			scopeSha256 ;
	/// Callerが固定したsource・resource・group・本文上限。
	CollectorCampaignSource source ;
	/// 予約保存前に採取したUTC。秒丸め前の値です。
	std::uint64_t			anchorUtcMillis{} ;
	/// 同じ予約保存前のprocess単調時計。
	std::uint64_t			anchorSteadyMillis{} ;
	/// Job120秒・日次4時間・batch60分の最小UTC期限。
	std::uint64_t			deadlineUtcMillis{} ;
	/// 同じprocess中だけ使う単調期限。再起動で延長しません。
	std::uint64_t			deadlineSteadyMillis{} ;
} ;

/** @brief 元予約の全fieldを再送許可を作らずに照合します。
 * @param[in] first 永続予約の正本。
 * @param[in] second 再照合するworkerの結合。
 * @return 全fieldが一致する場合true。
 */
[[nodiscard]] bool sameCollectorRecoveryDispatch( const CollectorRecoveryDispatch &first,
												 const CollectorRecoveryDispatch &second) noexcept ;

/** @brief 次の予約を待つ理由を、通信や保存なしで区別します。 */
enum class CollectorRecoveryReadinessKind {
	/// 固定jobを直ちに予約できます。
	READY,
	/// 実行中の予約がslotまたはgroupを占有しています。
	ACTIVE_WAIT,
	/// 同groupの2秒間隔だけが未到達です。
	INTERVAL_WAIT,
	/// 日付・予算・長期待機・要確認により当runでは進めません。
	DEFERRED,
	/// 全jobが非再送の終端にあります。Summary完了とは異なります。
	TERMINAL
} ;

/** @brief 非変更で求めた候補と有限待機です。予約許可tokenではありません。 */
struct CollectorRecoveryReadiness {
	/// 現在の待機分類。
	CollectorRecoveryReadinessKind kind{CollectorRecoveryReadinessKind::DEFERRED} ;
	/// READY時だけの固定job index。
	std::optional<std::size_t>	   jobIndex ;
	/// 2秒間隔の残時間。その他の分類は0です。
	std::uint64_t				   waitMillis{} ;
	/// READY時だけの元日次／batchから計算したUTC期限。
	std::uint64_t				   deadlineUtcMillis{} ;
	/// 既存数値APIと共用する有限理由。URLや端末情報を含みません。
	std::wstring				   reason ;
} ;

/** @brief 単一writer下で保存応答を優先し、固定順の更新を回収します。 */
class LocalCollectorRecovery final {
public:
	/** @brief 未接続の監督を作ります。 */
	LocalCollectorRecovery() ;
	/** @brief Storeの借用だけを解放します。保存物は保持します。 */
	~LocalCollectorRecovery() ;

	/** @brief 初回射影世代の全終端を再検証し、完了記録を固定順で保存します。
	 * @param[in] utcMillis 現監督のUTC millisecond。巻戻しを拒否します。
	 * @param[in] steadyMillis 現processの単調millisecond。
	 * @return 保存成功0、未終端1237、次回末尾の非対応50、拒否13、第一I/O／HRESULT／OOM。
	 * @note 初回保存と登録済み全完了の再検査用入口です。任意summary値を受け取らず、新世代・HTTPは開始しません。
	 * 登録後の再呼出しは非変更です。保存窓の回復はinitializeProjectedで行います。
	 * 明示次回開始後の末尾は、この初回専用入口で完了させません。
	 */
	[[nodiscard]] DWORD finishInitialProjected( std::uint64_t utcMillis, std::uint64_t steadyMillis) ;
	/**
	 * @brief 単一writer下のstore借用と回収状態の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorRecovery( const LocalCollectorRecovery &) = delete ;
	/**
	 * @brief 単一writer下のstore借用と回収状態を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorRecovery &operator=( const LocalCollectorRecovery &) = delete ;

	/** @brief 旧全契約を検査し、応答・中断を回収して固定入力を登録します。
	 * @param[in,out] store Writer初期化済みの借用store。
	 * @param[in] input 公開manifestと呼出し側固定契約。
	 * @param[in] utcMillis 現在のUTC millisecond。
	 * @param[in] steadyMillis process内の単調millisecond。
	 * @param[in] stop 非通信fixture用の保存後停止。通常は空です。
	 * @return 成功0、待機1237、形式13、容量68、取消し995または元I/O code。
	 */
	[[nodiscard]] DWORD		initialize( LocalCollectorStateStore		&store,
									   const CollectorRecoveryInput &input, std::uint64_t utcMillis,
									   std::uint64_t									steadyMillis,
									   std::function<bool( CollectorRecoveryCheckpoint)> stop = {}) ;

	/** @brief 射影専用input-v3を登録し、旧世代が残る場合は回収して待機します。
	 * @param[in,out] store 同じworkspace内の単一writer store。
	 * @param[in] input 元manifestと組み込みsource定義。
	 * @param[in] utcMillis 現在のUTC millisecond。
	 * @param[in] steadyMillis 現processの単調millisecond。
	 * @param[in] stop 非通信fixtureの保存後停止。通常は空です。
	 * @return 登録・再読込成功0、旧世代待ち1237、形式13、元I/O code。
	 * @note 専用poolだけが射影予約を発行します。初回所有workerのv4保存に対応し、旧reserve／acceptは拒否します。
	 * 全世代完了・activeなしは最新完了入力を非変更再読込みし、入力変更でも次回世代を開始しません。
	 * 完了prefixと末尾を全検査し、元v4応答と未登録準備prefix一件だけを非再送で精算します。
	 * 登録v4／canonical v2中断commitは固定前像の全履歴検査後だけ反映suffixを回復します。
	 * 入力一致のPENDINGだけ予約を許可し、応答のないRUNNINGは明示中断入口まで非変更です。
	 * 二開始prefixは明示中断まで非変更です。全完了履歴に残った日次切替は元時刻で一回だけ回復します。
	 * 未完了末尾の固定完了prefixは全履歴検査後だけ元時刻で不足suffixを保存します。
	 * 切替証跡のない全完了再読込みは非変更です。通常CLI接続は後続です。
	 */
	[[nodiscard]] DWORD		initializeProjected(
			LocalCollectorStateStore &store, const CollectorProjectedCampaignDefinition &input,
			std::uint64_t utcMillis, std::uint64_t steadyMillis,
			std::function<bool( CollectorRecoveryCheckpoint)> stop = {}) ;

	/** @brief 再検査済み全完了から明示的に次の未応答世代を登録します。
	 * @param[in] input 新しい公開定義。既登録Gを作り直しません。
	 * @param[in] utcMillis 次回開始の現在UTC。
	 * @param[in] steadyMillis 同じ監督の単調時計。
	 * @return 登録成功0、既登録／待機1237、上限68、元I/O／HRESULT／OOM。
 * @note 初回initialize後だけ。次回RUNNINGと二開始prefixは別の明示中断入口を持ち、日次切替途中は通常起動で全検査します。
	 */
	[[nodiscard]] DWORD beginNextProjected( const CollectorProjectedCampaignDefinition &input,
										   std::uint64_t utcMillis, std::uint64_t steadyMillis) ;

	/** @brief 再起動後の次世代RUNNINGと二開始prefixを全履歴検査後だけ欠測中断として精算します。
	 * @param[in] utcMillis 復旧監督の現在UTC。初回中断のfinished／acceptedだけへ固定します。
	 * @param[in] steadyMillis 復旧processの単調時計。後退を拒否します。
	 * @return 精算／非変更反復0、稼働所有170、元I/O／HRESULT／OOM／関係error。
	 * @note 開発用の明示入口です。通常initializeの非変更待機を維持し、通信・新規dispatch・完了は行いません。
 * 元応答なしの予約だけをv2中断へ固定し、旧成功sliceを保持します。PENDINGの開始intentを補完しません。
 * 日次切替の復旧はこの明示精算へ流用せず、通常の全完了起動へ分離します。
	 */
	[[nodiscard]] DWORD recoverNextProjectedReservations( std::uint64_t utcMillis,
														 std::uint64_t steadyMillis) ;

	/** @brief 最大4枠、同group一件の未予約jobを永続予約します。
	 * @param[in] utcMillis 現在のUTC millisecond。
	 * @param[in] steadyMillis process内の単調millisecond。
	 * @param[out] dispatch 成功時だけ利用する元予約。
	 * @return 成功0、待機／完了1237、拒否またはI/O code。
	 * @note 本部品自身はHTTPを実行しません。
	 */
	[[nodiscard]] DWORD reserve( std::uint64_t utcMillis, std::uint64_t steadyMillis,
								CollectorRecoveryDispatch &dispatch) ;

	/** @brief v3必須の予約を保存し、旧acceptへの観測省略を拒否します。
     * @param[in] utcMillis 元予約直前のUTC。
     * @param[in] steadyMillis 同じprocessの単調時計。
     * @param[out] dispatch 成功時だけの元予約。
     * @return 保存成功0、枠待ち1237、拒否または元I/O code。
     */
	[[nodiscard]] DWORD reserveControlled( std::uint64_t utcMillis, std::uint64_t steadyMillis,
										  CollectorRecoveryDispatch &dispatch) ;

	/** @brief reserveと同じ選択判定を、台帳と監督時計を変更せず照会します。
	 * @param[in] utcMillis 現在のUTC millisecond。
	 * @param[in] steadyMillis 同一processの単調millisecond。
	 * @param[out] readiness 成功0の場合だけ有効な候補／待機分類。失敗時は空です。
	 * @return 照会成功0、時計／形式拒否または元I/O code。予約やHTTPは行いません。
	 * @note 単一writer threadで使用し、READY結果自体は送信許可にしません。
	 */
	[[nodiscard]] DWORD readiness( std::uint64_t utcMillis, std::uint64_t steadyMillis,
								  CollectorRecoveryReadiness &readiness) const ;

	/** @brief 元応答を先に保存し、CONTROL→JOB→BUDGETを一度反映します。
	 * @param[in] jobIndex 元予約のjob index。
	 * @param[in] response 型付きの有限応答。中断intentの自作は認めません。
	 * @param[in] utcMillis 現在の検査UTC millisecond。
	 * @param[in] steadyMillis 完了後の単調millisecond。
	 * @return 成功0、拒否または元I/O code。失敗後の継続を拒否します。
	 */
	[[nodiscard]] DWORD accept( std::size_t jobIndex, const CollectorRecoveryResponse &response,
							   std::uint64_t utcMillis, std::uint64_t steadyMillis) ;

	/** @brief 元dispatchと確定I/O観測を結合したv3を一回保存・精算します。
     * @param[in] binding 元の制御付き予約。全fieldを保存時の値と照合します。
     * @param[in] response 元終了と監督受領を分けた基本結果。
     * @param[in] observation Workerが確定した観測。変更・未確定・時計欠測を拒否します。
     * @param[in] utcMillis 現在の監督UTC。
     * @param[in] steadyMillis 現在のprocess単調時計。
     * @return 成功0、拒否または第一I/O error。
     */
	[[nodiscard]] DWORD acceptControlled( const CollectorRecoveryDispatch &binding,
										 const CollectorRecoveryResponse &response,
										 const CollectorIoSnapshot		 &observation,
										 std::uint64_t utcMillis, std::uint64_t steadyMillis) ;

	/** @brief 全join済み初回収集を元予約へ結合し、非保存応答を一度だけ生成します。
	 * @param[in,out] executor 同じ監督が予約した専用executor。任意DTOは受け取りません。
	 * @param[in] slot 元予約slot。二度目の試行を拒否します。
	 * @param[in] utcMillis 親writerが観測した現在UTC。
	 * @param[in] steadyMillis 同じprocessの現在単調時計。
	 * @param[out] prepared 独立read-back後だけの値。失敗時は空。永続受入証明ではありません。
	 * @param[in] probe 任意のhash失敗専用診断。成功値は注入できません。
	 * @return 成功0、関係拒否13、容量68、原hash HRESULT／I/O数値。失敗後は再試行しません。
	 * @note CACHE登録・現fileともに欠損の場合だけです。保存・精算・履歴再利用は行いません。
	 */
	[[nodiscard]] DWORD prepareInitialProjected(
		LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
		std::uint64_t steadyMillis, CollectorProjectedResponseBytes &prepared,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe = {}) ;

	/** @brief 予約前に固定した初回履歴根拠を再照合し、応答とCACHE候補を一度作ります。
	 * @param[in,out] executor 同じ監督が予約した全join済みexecutor。
	 * @param[in] slot 元予約slot。一回だけ準備可能です。
	 * @param[in] utcMillis 親の現在UTC。
	 * @param[in] steadyMillis 親の現在単調時計。
	 * @param[out] prepared 成功時の応答とCACHE候補。失敗時は全て空。
	 * @param[in] probe 応答codecのhash失敗専用診断。
	 * @return 成功0、関係拒否、元I/O／hash HRESULT／OOM。失敗後の再試行はしません。
	 * @note 初回のみ。次回末尾は50で拒否します。成功履歴の読込み、永続保存、精算、304送信は行いません。
	 */
	[[nodiscard]] DWORD prepareInitialProjectedUpdate(
		LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
		std::uint64_t steadyMillis, CollectorProjectedPreparedUpdate &prepared,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe = {}) ;
	/** @brief 全join済み初回所有結果からv4を保存し、四roleとCACHE登録を確定します。
	 * @param[in,out] executor 元予約を所有する専用executor。任意DTOは受け取りません。
	 * @param[in] slot 元予約slot。一回prepareと共用し、二重保存を拒否します。
	 * @param[in] utcMillis 親writerが観測した現在UTC。
	 * @param[in] steadyMillis 同じprocessの現在単調時計。
	 * @param[in] probe 親codecのhash失敗専用診断。成功は実CNGを使います。
	 * @return 全保存成功0、関係拒否、元I/O／HRESULT／OOM。以後の保存を停止します。
	 * @note 初回のみ。保存途中の応答と予約を残し再起動回復へ渡します。304・履歴更新なし。
	 */
	[[nodiscard]] DWORD acceptInitialProjected(
		LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
		std::uint64_t													steadyMillis,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe = {}) ;
	/** @brief 次世代の全join済み所有結果を検査済み成功履歴で最終化します。
	 * @param[in,out] executor 同じ監督の予約と元観測を所有するexecutor。
	 * @param[in] slot 元予約slot。一回prepare／acceptと共用します。
	 * @param[in] utcMillis 現在の親UTC。
	 * @param[in] steadyMillis 同じprocessの単調時計。
	 * @param[out] prepared 全検査後の非保存応答とCACHE。失敗時は空。
	 * @param[in] probe 元hash失敗専用診断。
	 * @return 成功0、関係拒否、元I/O／HRESULT／OOM。失敗後は停止します。
	 * @note 全履歴と予約前CACHEhashを再照合します。304・保存・中断回復は行いません。
	 */
	[[nodiscard]] DWORD prepareNextProjectedUpdate(
		LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
		std::uint64_t steadyMillis, CollectorProjectedPreparedUpdate &prepared,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe = {}) ;
	/** @brief 次世代の所有結果を元CACHE前像と四roleへ一度保存します。
	 * @param[in,out] executor 元予約を所有する全join済みexecutor。
	 * @param[in] slot 元slot。prepareとの二重受領は拒否します。
	 * @param[in] utcMillis 親の現在UTC。
	 * @param[in] steadyMillis 親の現在単調時計。
	 * @param[in] probe 元hash失敗専用診断。
	 * @return 全保存成功0、第一I/O／HRESULT／OOMまたは関係拒否。
	 * @note 保存途中は停止し証跡を保持します。応答と四role反映中はinitializeで復旧します。
	 * 未応答RUNNINGと二開始prefixは明示中断入口を持ち、日次切替／末尾完了の保存窓は通常起動で別検査します。
	 */
	[[nodiscard]] DWORD acceptNextProjected(
		LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
		std::uint64_t													steadyMillis,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe = {}) ;
	/** @brief 全履歴と全終端を検証し最後の次世代だけを明示完了します。
	 * @param[in] utcMillis 現在の親UTC。元完了時刻の再保存はしません。
	 * @param[in] steadyMillis 同じprocessの単調時計。
	 * @return 完了0、未終端1237、第一I/O／HRESULT／OOMまたは関係拒否。
	 * @note 既完了の再呼出しは非変更です。末尾完了の保存途中はinitializeProjectedが元時刻で復旧します。
	 */
	[[nodiscard]] DWORD finishNextProjected( std::uint64_t utcMillis, std::uint64_t steadyMillis) ;
	/** @brief 保護storeの登録済みCACHEと全参照を読み取り専用で検査します。
	 * @param[in,out] store 保護handleで開いたstore。同じwriter threadから呼びます。
	 * @param[in] job 今回の元prepared job。履歴と同requestを要求します。
	 * @param[in] sources 組み込みsourceの全契約。保存sourceを通信許可にしません。
	 * @param[in] utcMillis 検査現在UTC。未来参照を拒否します。
	 * @param[out] history 全検査後だけ生成する変更不能context。失敗時は空。
	 * @param[in] probe 元v4 codecのhash失敗専用診断。
	 * @param[out] diagnostics 任意の容量部分観測。開始時resetし失敗時も残します。権限ではありません。
	 * @return 成功0、元I/O／hash／OOM、関係拒否13、閉包容量超過68。
	 * @note 全世代が保存版3・完了済みなら全CACHE／全job／完了像／日次archiveを再導出します。
	 * 全request合計300操作・6000名／再照合込み64 MiB。完了保存途中・稼働との混在は拒否します。
	 * 登録なしは拒否。保存・回収・精算・HTTPと稼働予約への接続は行いません。
	 */
	[[nodiscard]] static DWORD inspectRegisteredProjectedHistory(
		LocalCollectorStateStore &store, const CollectorPreparedProjectedJob &job,
		std::span<const CollectorCampaignSource> sources, std::uint64_t utcMillis,
		std::shared_ptr<const CollectorRegisteredProjectedHistory>	   &history,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe		= {},
		CollectorHistoryReadDiagnostics								   *diagnostics = nullptr) ;

	/** @brief Terminal化したjob数を返します。
	 * @return DEFERREDも含む非再送job数。製品成功数ではありません。
	 */
	[[nodiscard]] std::size_t		  terminalJobs() const noexcept ;
	/** @brief 登録中のgenerationを返します。
	 * @return 未登録時は空。Object存続中だけ有効です。
	 */
	[[nodiscard]] const std::wstring &generationKey() const noexcept ;
	/** @brief 元errorを保持して返します。
	 * @return 成功0、または最初の拒否code。
	 */
	[[nodiscard]] DWORD				  lastError() const noexcept ;
	/** @brief 最後の停止理由を返します。
	 * @return URLや端末IDを持たない固定codeです。
	 */
	[[nodiscard]] const std::wstring &reason() const noexcept ;

	/** @brief 全完了v3 rootを元rawから封印検査します。保存・回復・通信は行いません。
	 * @param[in,out] store Writer初期化済みの単一thread store。既存監督借用は170で拒否します。
	 * @param[in] sources 元履歴を再構築する固定source契約。1～20件です。
	 * @param[in] utcMillis 検査UTC。元時刻・期限を更新しません。
	 * @param[out] inventory 全raw／全名再照合後だけimmutable根拠。失敗時は空です。
	 * @param[in] beforeFinalRecheck 決定的fixtureだけの数値故障／改変checkpoint。通常は空。
	 * @param[out] diagnostics 新入口のraw先払いを含む部分計数。証明／保存許可ではありません。
	 * @return 成功0、非writer87、既存借用170、内容13、容量68、元I/O／HRESULT／OOM。
	 * @note 新区間台帳／親headとは未接続です。返却後のlive leaseを保持しません。
	 */
	[[nodiscard]] static DWORD		  inspectCompletedRootInventory(
			   LocalCollectorStateStore &store, std::span<const CollectorCampaignSource> sources,
			   std::uint64_t utcMillis, std::shared_ptr<const CollectorCompletedRootInventory> &inventory,
			   const std::function<DWORD()>	   &beforeFinalRecheck = {},
			   CollectorHistoryReadDiagnostics *diagnostics		   = nullptr) ;

private:
	friend class LocalCollectorProjectedExecutor ;
	friend class LocalCollectorSegmentInventory ;
	/** @brief 結合監督だけが両借用中の最終再照合を組み立てます。
	 * @param[in,out] store 同じleaseのhistory writer。
	 * @param[in] sources 元source契約。
	 * @param[in] utcMillis 検査UTC。
	 * @param[out] inventory 全検査後だけの所有根拠。失敗時は空。
	 * @param[in] beforeFinalRecheck 公開入口の数値診断。結合時は空です。
	 * @param[out] diagnostics 任意の部分計数。
	 * @param[in] couple 私有結合監督。未公開値と一回限りの同期再検査を借用します。
	 * @return 第一error。成功にはcouple内の再検査成功が必須です。
	 * @note Callbackは保存権限ではなく、引数を呼出し外へ保持できません。
	 */
	[[nodiscard]] static DWORD inspectCompletedRootInventoryBound(
		LocalCollectorStateStore &store, std::span<const CollectorCampaignSource> sources,
		std::uint64_t utcMillis, std::shared_ptr<const CollectorCompletedRootInventory> &inventory,
		const std::function<DWORD()>							   &beforeFinalRecheck,
		CollectorHistoryReadDiagnostics							   *diagnostics,
		const std::function<DWORD( const CollectorCompletedRootEvidence &,
								  const std::function<DWORD()> &)> &couple) ;
	/** @brief 読取りcontextと通常全完了inventoryの有限検査を共有します。
	 * @param[in,out] store Writer初期化済みの借用store。保存・lease変更は行いません。
	 * @param[in] job 要求context用の借用job。nullは通常inventory／内部末尾完了の検査です。
	 * @param[in] sources 今回の組み込みsource契約。
	 * @param[in] utcMillis 検査UTC。
	 * @param[in] expectedRoot 通常監督の元root本文hash。空は読取り入口です。
	 * @param[out] history 非null jobの成功時だけ所有context。失敗／通常検査では空です。
	 * @param[in] probe 読取りhashの有限fixture故障。通常は空です。
	 * @param[in] allowActive 内部入口だけが未完了末尾一世代の予約・精算済み操作を認めます。
	 * @param[out] verifiedOperations 非null時だけ全検査済み操作集合。失敗時は空。
	 * @param[in] allowPrepared 通常起動だけが未登録v4一件と再導出済み四role準備prefixを認めます。
	 * @param[in] allowCommit 通常inventoryだけが登録v4 commitから固定五前像を検査します。
	 * @param[in] allowPartialStart 通常起動／明示中断だけが最後の予約とPENDINGの二開始prefixを認めます。
	 * @param[in] allowDayRoll 通常全完了inventoryだけが未登録／登録日次切替を検査します。
	 * @param[out] verifiedDayRoll 非null時に全再照合成功後だけ元canonical intentを返します。失敗時は空。
	 * @param[in] allowFinish 通常未完了末尾inventoryだけが固定完了prefixを検査します。他例外と混用しません。
	 * @param[out] verifiedFinish 全再照合成功後だけ元時刻で再導出した四本文を返します。失敗時は空。
	 * @param[out] diagnostics 任意の非変更raw容量観測。保存権限や成功判定に使用しません。
	 * @param[out] completedInventory 専用入口だけの全raw封印context。失敗時は空です。
	 * @param[in] beforeFinalRecheck 封印専用の最終再照合前checkpoint。通常入口は空です。
	 * @param[in] couple 同時借用を結合する私有監督。全完了専用入口だけです。
	 * @return 成功0、形式13、上限68、元I/O／HRESULT／OOM。全raw／全名を公開前再照合します。
	 */
	[[nodiscard]] static DWORD inspectProjectedHistoryCore(
		LocalCollectorStateStore &store, const CollectorPreparedProjectedJob *job,
		std::span<const CollectorCampaignSource> sources, std::uint64_t utcMillis,
		std::wstring_view												expectedRoot,
		std::shared_ptr<const CollectorRegisteredProjectedHistory>	   &history,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe,
		bool allowActive = false, std::set<std::wstring> *verifiedOperations = nullptr,
		bool allowPrepared = false, bool allowCommit = false, bool allowPartialStart = false,
		bool allowDayRoll = false, std::string *verifiedDayRoll = nullptr, bool allowFinish = false,
		std::optional<std::array<std::string, 4U>>				   *verifiedFinish	   = nullptr,
		CollectorHistoryReadDiagnostics							   *diagnostics		   = nullptr,
		std::shared_ptr<const CollectorCompletedRootInventory>	   *completedInventory = nullptr,
		const std::function<DWORD()>							   &beforeFinalRecheck = {},
		const std::function<DWORD( const CollectorCompletedRootEvidence &,
								  const std::function<DWORD()> &)> &couple			   = {}) ;
	/** @brief 初回と次世代で同じ所有・原I/O検査と最終化を共有します。
	 * @param[in,out] executor 元所有executor。
	 * @param[in] slot 元slot。
	 * @param[in] utcMillis 親UTC。
	 * @param[in] steadyMillis 親単調時計。
	 * @param[out] prepared 成功時の応答とCACHE。失敗時は空。
	 * @param[in] probe 元hash失敗専用診断。
	 * @param[in] next 次世代専用の場合true。初回へ流用しません。
	 * @return 第一error。保存は行いません。
	 */
	[[nodiscard]] DWORD prepareProjectedUpdateForMode(
		LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
		std::uint64_t steadyMillis, CollectorProjectedPreparedUpdate &prepared,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe, bool next) ;
	/** @brief 初回と次世代の所有結果保存を共通順序で行います。
	 * @param[in,out] executor 元所有executor。
	 * @param[in] slot 元slot。
	 * @param[in] utcMillis 親UTC。
	 * @param[in] steadyMillis 親単調時計。
	 * @param[in] probe 元hash失敗専用診断。
	 * @param[in] next 次世代専用の場合true。
	 * @return 第一error。保存途中は停止します。
	 */
	[[nodiscard]] DWORD acceptProjectedForMode(
		LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
		std::uint64_t													steadyMillis,
		const std::function<std::int32_t( CollectorProjectedHashStage)> &probe, bool next) ;
	/** @brief 同一Gの別監督と区別する非再利用tokenを専用executorだけへ貸します。
	 * @return 監督存続後もexecutorが保持する唯一の所有identity。保存や通信許可ではありません。
	 */
	[[nodiscard]] const std::shared_ptr<const std::byte> &projectedOwnerToken() const noexcept ;
	/** @brief 専用executorだけが新世代の次候補を非変更照会します。
	 * @param[in] utcMillis 現在UTC。
	 * @param[in] steadyMillis 現在単調時計。
	 * @param[out] readiness 成功時だけ元選択結果。失敗時は空です。
	 * @return 元error。通信・予約・状態変更は行いません。
	 */
	[[nodiscard]] DWORD readinessProjected( std::uint64_t utcMillis, std::uint64_t steadyMillis,
										   CollectorRecoveryReadiness &readiness) const ;
	/** @brief 世代別gate後だけ元selectJobへ渡す非変更照会です。
	 * @param[in] utcMillis 現在UTC。
	 * @param[in] steadyMillis 現在単調時計。
	 * @param[out] readiness 成功時だけ元選択結果。
	 * @param[in] projected 専用新世代の場合true。
	 * @return 元error。旧modeからの新世代照会は拒否します。
	 */
	[[nodiscard]] DWORD readinessForMode( std::uint64_t utcMillis, std::uint64_t steadyMillis,
										 CollectorRecoveryReadiness &readiness,
										 bool						 projected) const ;
	/** @brief 元v3入力に結合した開発用予約。専用permit発行元だけが呼びます。
	 * @param[in] utcMillis 元UTC。
	 * @param[in] steadyMillis 元単調時計。
	 * @param[out] dispatch 全保存後の予約。失敗時は空。
	 * @return 保存結果または第一error。
	 */
	[[nodiscard]] DWORD reserveProjected( std::uint64_t utcMillis, std::uint64_t steadyMillis,
										 CollectorRecoveryDispatch &dispatch) ;
	friend class CollectorHttpPermitPool ;
	/** @brief 元writerのHTTP実所有を予約前に登録します。
	 * @param[out] lease 同じstoreの私有所有ticket。失敗時は空です。
	 * @return 第一監督error、能力87、freeze170、上限68、確保8。
	 */
	[[nodiscard]] DWORD acquireHttpActivity(
		std::shared_ptr<const CollectorStoreHttpLease> &lease) noexcept ;
	/** @brief 同じwriter・旧回収を共有し、世代schemaだけを入口別に検査します。
	 * @param[in,out] store 借用writer。
	 * @param[in] input 旧profileだけの入力。
	 * @param[in] projected 新profileの場合だけの定義。
	 * @param[in] utcMillis 現UTC。
	 * @param[in] steadyMillis 現単調時計。
	 * @param[in] stop Fixture停止点。
	 * @return 登録結果と元error。
	 */
	[[nodiscard]] DWORD initializeForMode( LocalCollectorStateStore					 &store,
										  const CollectorRecoveryInput				 &input,
										  const CollectorProjectedCampaignDefinition *projected,
										  std::uint64_t utcMillis, std::uint64_t steadyMillis,
										  std::function<bool( CollectorRecoveryCheckpoint)> stop) ;
	/** @brief 旧予約と制御付き予約で同じ選択・保存順を使用します。
     * @param[in] utcMillis 元UTC。
     * @param[in] steadyMillis 元単調時計。
     * @param[out] dispatch 保存後の結合。
     * @param[in] controlled v3必須の場合true。
     * @param[in] projected 新input-v3の専用予約の場合true。
     * @return 保存結果。
     */
	[[nodiscard]] DWORD reserveForMode( std::uint64_t utcMillis, std::uint64_t steadyMillis,
									   CollectorRecoveryDispatch &dispatch, bool controlled,
									   bool projected = false) ;
	/** @brief 保存・commitの共通手順で旧／制御付き応答を別codecへ渡します。
     * @param[in] jobIndex 元job。
     * @param[in] response 基本結果。
     * @param[in] utcMillis 監督UTC。
     * @param[in] steadyMillis 監督単調時計。
     * @param[in] observation 制御付きの場合だけ非null。
     * @param[in] binding 制御付きの場合だけ元dispatch。
     * @return 保存結果または第一error。
     */
	[[nodiscard]] DWORD acceptForMode( std::size_t					   jobIndex,
									  const CollectorRecoveryResponse &response,
									  std::uint64_t utcMillis, std::uint64_t steadyMillis,
									  const CollectorIoSnapshot		  *observation,
									  const CollectorRecoveryDispatch *binding) ;
	/** @brief 保護storeと固定更新の単一監督状態です。 */
	struct State ;
	/// Storeより短く存続する監督状態。
	std::unique_ptr<State> state_ ;
} ;
} // namespace drivercrate
