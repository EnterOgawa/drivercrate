//------------------------------------------------------------------------------
/**
 * @file official_preparation.h
 * @brief 配布物単位の検査用取得承認と予算管理。
 * @version 01.04.01
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得前提の独立確認を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  配布物単位の取得承認を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  UIの独立検証objectとthread契約を明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  同一EULAを共有する短命group tokenを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  許諾の共通検証へ明示停止callbackを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * </pre>
 *
 * @note 一objectは同一threadだけで使用し、取得taskを導入許可として扱いません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
// UIとworkerで共有する本文上限。単位はUTF-16 code unitで、終端NULを含めない。
inline constexpr std::size_t MAXIMUM_PREPARATION_EULA_CHARACTERS = 65536U ;
// 最大256対象の計画全体に保持できる本文量。Copy前にも同じ上限を検査する。
inline constexpr std::size_t MAXIMUM_PREPARATION_PLAN_EULA_CHARACTERS = 262144U ;

/**
 * @brief EULA本文を変形せずに表示できる、有限なUTF-16 plain textか確認する。
 * 本文を切詰め・正規化せず、全文snapshotの比較で同revisionの変更も検出する。
 * @param[in] text 同意対象の全文。呼出し中だけ参照する。 表示と同意に使用するUTF-16の全文。
 * @return 非空・上限内で、制御文字や不正surrogateを含まない場合true。 非空・有限で、表示を妨げる制御を含まない場合true。
 */
[[nodiscard]] bool			 validPreparationEulaText( std::wstring_view text) noexcept ;

/** @brief Download前の利用条件についてProviderが確認した状態。 */
enum class OfficialPreparationTerms {
	/// 条件未確認のため取得承認できない。
	UNRESOLVED,
	/// Download前の同意が不要とProviderが確認した。
	CONFIRMED_NO_CONSENT,
	/// 指定revisionの条件への明示同意を必要とする。
	ACCEPTANCE_REQUIRED
} ;

/** @brief 一scan内の計画をまたいで維持する予約予算。 */
struct OfficialPreparationLimits {
	/// 一fileに予約できる上限byte数。
	std::uint64_t maximumFileBytes{} ;
	/// 一Providerに予約できる累計byte数。
	std::uint64_t maximumProviderBytes{} ;
	/// 一scan全体に予約できる累計byte数。
	std::uint64_t maximumSessionBytes{} ;
	/// 一Providerに予約できる累計file数。
	std::uint32_t maximumProviderFiles{} ;
	/// 一scanで予約できる累計file数。最大256。
	std::uint32_t maximumSessionFiles{} ;

	/**
     * @brief 計画時と承認時の上限を完全一致で比較する。
     * @param[in] other 比較対象の上限。
     * @return 全field一致時true。
     */
	bool		  operator==( const OfficialPreparationLimits &other) const = default ;
} ;

/** @brief Payload URLや実device IDを含まない固定snapshot。EULA内のURLは文字列に限る。 */
struct OfficialPreparationTarget {
	/// 計画内で一意のopaque対象ID。
	std::wstring			 identity ;
	/// Registryにある公式network Provider ID。
	std::wstring			 providerId ;
	/// 後続adapterが照合するpayload resource ID。
	std::wstring			 resourceId ;
	/// workerが保存した配布情報のopaque ID。
	std::wstring			 releaseIdentity ;
	/// 保存した配布情報のparser revision。0は無効。
	std::uint32_t			 parserRevision{} ;
	/// 同意を求める転送上限。公開sizeの推定値ではない。
	std::uint64_t			 maximumBytes{} ;
	/// 関連device数。適用性判定済み件数ではない。
	std::uint32_t			 deviceCount{} ;
	/// Download条件。
	OfficialPreparationTerms terms{OfficialPreparationTerms::UNRESOLVED} ;
	/// 明示同意対象のrevision。条件不明／同意不要なら空。
	std::wstring			 eulaRevision ;
	/// 同意対象の全文。外部送信・永続保存せず、snapshot全体で照合する。
	std::wstring			 eulaText ;
	/// 元sourceIdと公式起点に結合した規約出典主体です。通常logへ出しません。
	std::wstring			 eulaSourceSubject ;
	/// EULAと独立した具体的取得条件の全文です。元target承認へ結合します。
	std::wstring			 prerequisiteText ;
	/// 同一scan内の完全一致EULAを一度だけ表示するopaque group token。従来対象は0。
	std::uint64_t			 sharedEulaToken{} ;
	/// 既存契約・権限・用途等の確認が必要ならtrue。
	bool					 requiresPrerequisiteConfirmation{} ;

	/**
     * @brief 表示済みsnapshotと承認対象の全fieldを完全一致で比較する。
     * @param[in] other 比較対象の配布物snapshot。
     * @return 全field一致時true。
     */
	bool					 operator==( const OfficialPreparationTarget &other) const = default ;
} ;

/** @brief 一scanに属する有限な取得計画。 */
struct OfficialPreparationPlan {
	/// workerが発行した検索session。0は無効。
	ScanSessionId						   scanSessionId{} ;
	/// 同じ管理objectで単調増加する計画ID。
	std::uint64_t						   planId{} ;
	/// Scan中に変更しない予約上限。
	OfficialPreparationLimits			   limits ;
	/// 配布物を重複排除した最大256対象。
	std::vector<OfficialPreparationTarget> targets ;
} ;

/** @brief 一対象について利用者が明示した取得可否。 */
struct OfficialPreparationDecision {
	/// 利用者へ提示した対象snapshot。
	OfficialPreparationTarget target ;
	/// trueの場合だけ取得を選択する。
	bool					  acquire{} ;
	/// 今回の指定revisionに明示同意した場合true。
	bool					  eulaAccepted{} ;
	/// 今回だけ課金／不明networkを許可する場合true。
	bool					  restrictedNetworkApproved{} ;
	/// 本文記載の取得前提を利用者が確認した場合だけtrue。
	bool					  prerequisitesConfirmed{} ;
} ;

/** @brief 全表示対象の判断を含む、一度だけ使用できる承認。 */
struct OfficialPreparationApproval {
	/// 単調増加する操作ID。0は無効。
	OperationId								 operationId{} ;
	/// 承認した計画が属する検索session。
	ScanSessionId							 scanSessionId{} ;
	/// 承認した計画の識別番号。
	std::uint64_t							 planId{} ;
	/// 提示した容量・件数上限のsnapshot。
	OfficialPreparationLimits				 limits ;
	/// 全対象の可否。順序は任意。
	std::vector<OfficialPreparationDecision> decisions ;
} ;

/** @brief 取得承認境界の拒否理由。HTTPや導入の成功とは別に扱う。 */
enum class OfficialPreparationError {
	/// 要求を受理した。
	NONE,
	/// 取得操作またはその取消し結果を待っている。
	BUSY,
	/// 計画の形式・Provider・件数・上限が不正。
	INVALID_PLAN,
	/// Sessionまたは計画IDが古い。
	STALE_PLAN,
	/// 有効な未使用計画がない。
	NO_PLAN,
	/// 対象・上限・利用条件のsnapshotが一致しない。
	INVALID_APPROVAL,
	/// 操作IDが再使用または0。
	STALE_OPERATION,
	/// Scan累計またはProvider別の予約予算を超える。
	BUDGET_EXCEEDED
} ;

/** @brief Plan管理の状態。Completedは全件取得成功を意味しない。 */
enum class OfficialPreparationState {
	/// 有効な計画がない。
	EMPTY,
	/// 固定計画への判断を待っている。
	AWAITING_APPROVAL,
	/// 選択対象の取得と結果通知を受理できる。
	PREPARING,
	/// 未開始対象を取消し、開始済み対象の結果を待っている。
	CANCELLING,
	/// 未選択を含む全対象の状態が確定した。
	COMPLETED
} ;

/** @brief 対象別の取得状態。監査合格・導入可能を表す状態は持たない。 */
enum class OfficialPreparationItemState {
	/// 利用者が取得しないと判断した。
	NOT_SELECTED,
	/// 承認済みで未開始。
	PENDING,
	/// 一度だけclaimし、完了通知を待っている。
	IN_PROGRESS,
	/// 検査用取得の結果を受領した。適用性は未確認。
	ACQUIRED_FOR_INSPECTION,
	/// Networkの制限または不明状態について同意不足。
	AWAITING_NETWORK_CONSENT,
	/// 未開始取消しまたは転送取消し。
	CANCELLED,
	/// 共通取得層等の検証が拒否した。
	REJECTED,
	/// 取得処理でエラーが発生した。
	FAILURE
} ;

/** @brief 一対象の完了通知に使用する、URLを含まない結果。 */
struct OfficialPreparationTransferResult {
	/// 終端状態。
	OfficialPreparationItemState state{OfficialPreparationItemState::FAILURE} ;
	/// 成功時0。取得しなかった終端結果は負のHRESULT。
	NativeError					 error{} ;
	/// 成功時だけ実取得byte数。失敗／取消しは0。
	std::uint64_t				 byteCount{} ;
} ;

/** @brief 表示へ渡せる対象別の状態。 */
struct OfficialPreparationItem {
	/// 対応する計画内対象ID。
	std::wstring					  identity ;
	/// 現在状態または確定した取得結果。
	OfficialPreparationTransferResult result ;
} ;

/** @brief workerが一度だけ取得を開始するための照合token。公式由来の証拠ではない。 */
struct OfficialPreparationTask {
	/// 承認を消費した操作ID。
	OperationId				  operationId{} ;
	/// 承認時の検索session。
	ScanSessionId			  scanSessionId{} ;
	/// 承認済み計画のID。
	std::uint64_t			  planId{} ;
	/// 変更を許可しない取得対象。
	OfficialPreparationTarget target ;
	/// 対象別に承認されたnetwork例外。
	bool					  restrictedNetworkApproved{} ;

	/**
     * @brief 開始済みtaskと完了通知の照合tokenを完全一致で比較する。
     * @param[in] other 比較対象の照合token。
     * @return 全field一致時true。
     */
	bool					  operator==( const OfficialPreparationTask &other) const = default ;
} ;

/** @brief 確定件数だけで算出する、選択分の取得進捗。 */
struct OfficialPreparationProgress {
	/// 取得を選択した対象数。未選択は含まない。
	std::uint32_t total{} ;
	/// 取得済み・拒否・失敗・取消し等の確定した対象数。
	std::uint32_t completed{} ;
} ;

/**
 * @brief 対象別承認、同一scanの複数計画をまたぐ予算、単一取得taskの状態を管理する。
 * @note 一objectの全methodを同一threadから呼ぶ。UI検証用とworker実行用のobjectを共有しない。
 * HTTP、署名、導入許可の判定は行わない。最終承認はworker所有objectで再照合する。
 */
class OfficialPreparationSession final {
public:
	/** @brief 有効計画と予約のない管理objectを生成する。 */
	OfficialPreparationSession() = default ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialPreparationSession( const OfficialPreparationSession &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialPreparationSession &operator=( const OfficialPreparationSession &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialPreparationSession( OfficialPreparationSession &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialPreparationSession			  &operator=( OfficialPreparationSession &&) = delete ;

	/**
	 * @brief 新計画を固定する。同じscanでは予約予算を維持する。
	 * Active計画は維持する。それ以外の不正要求は旧計画を失効させ、予算高水位を残す。
	 * @param[in] plan workerが生成した新しい計画の所有値。 新計画の所有値。成功時に管理objectへ移す。
	 * @return 不正計画は拒否し、非active時には旧計画も失効させる。 受理時None。それ以外は拒否理由。
	 */
	[[nodiscard]] OfficialPreparationError initialize( OfficialPreparationPlan plan) ;

	/**
	 * @brief 全対象の判断を照合し、選択分の最大容量を一度だけ予約する。
	 * 失敗時に一部だけ同意・予約しない。受理後の同じ計画は再使用できない。
	 * @param[in] approval 利用者が明示した計画全体への判断。 全対象の取得可否と提示時のsnapshot。
	 * @return 受理時None。それ以外はtaskを生成せず予算も変更しない。 全件照合と予約に成功した場合None。
	 */
	[[nodiscard]] OfficialPreparationError approve( const OfficialPreparationApproval &approval) ;

	/**
	 * @brief 未開始の選択対象を計画順に一つだけ開始済みにする。
	 * 一度に一転送だけを許可し、コピー失敗時には開始済み状態へ変更しない。
	 * @return 次のtaskの所有値。未承認、取消し済み、別task実行中ならnullopt。 未開始の承認済みtask。開始できなければnullopt。
	 */
	[[nodiscard]] std::optional<OfficialPreparationTask> claimNext() ;
	/** @brief 本sessionが実claimした未完了taskを公開tokenと完全照合します。
	 * @param[in] task 比較だけを行うtoken。自己申告では開始権限を得られません。
	 * @return PREPARINGで同じ私有active taskを保持する場合だけtrue。
	 * @note 同一workerで呼び、同意・公式性・導入許可の検査を代替しません。
	 */
	[[nodiscard]] bool ownsActiveTask( const OfficialPreparationTask &task) const noexcept ;

	/**
	 * @brief 現在taskだけの確定結果を保存する。
	 * 古い結果・矛盾したbyte数・未確定状態を拒否する。取得結果から導入許可を生成しない。
	 * @param[in] task claimNextが返した未変更token。 現在処理中の承認済みtoken。
	 * @param[in] result 共通取得層から変換した終端結果。 URLを含まない取得層の終端結果。
	 * @return 正しい結果を受理した場合true。不整合時は現在taskを維持してfalse。 一致する結果を受理した場合true。
	 */
	[[nodiscard]] bool complete( const OfficialPreparationTask			&task,
								const OfficialPreparationTransferResult &result) ;

	/**
	 * @brief 未開始の選択対象を取消す。開始済みtaskの結果は引き続き受け付ける。
	 * 未開始だけを取消す。開始済みtaskは取得層の協調取消し結果まで保持する。
	 */
	void			   cancel() noexcept ;

	/**
	 * @brief 非active計画を失効させる。予算とIDの高水位は保持する。
	 * 予約予算と単調IDを消さず、同じscanでの再初期化による予算回避を防ぐ。
	 * @return 失効時true。開始済み操作の完了待ちならfalse。 非active計画を失効させた場合true。
	 */
	[[nodiscard]] bool invalidate() noexcept ;

	/**
	 * @brief 現在の計画状態を返す。
	 * Completedだけを根拠に全件取得成功と表示しない。
	 * @return 現在の計画状態。
	 */
	[[nodiscard]] OfficialPreparationState				   state() const noexcept ;

	/**
	 * @brief 結果一覧を参照する。
	 * 次の状態変更までだけ有効であり、別threadへviewを渡さない。
	 * @return 管理objectが所有する対象別状態の非所有view。
	 */
	[[nodiscard]] std::span<const OfficialPreparationItem> items() const noexcept ;

	/**
	 * @brief 確定した選択項目から進捗を返す。
	 * 最大256件だけを集計し、経過時間や未選択項目で進捗を増やさない。
	 * @return 選択分の総件数と確定件数。
	 */
	[[nodiscard]] OfficialPreparationProgress			   progress() const noexcept ;

private:
	friend class RecordScopedDownloadGrant ;
	/** @brief 同じ実taskの索引grant発行をadapterをまたいで一回だけ予約します。
	 * @param[in] task 本sessionの未完了task。
	 * @return 完全一致の未使用taskを予約した場合だけtrue。
	 */
	[[nodiscard]] bool claimIndexAcquisition( const OfficialPreparationTask &task) noexcept ;
	/// 現active taskが索引grantを一回発行済みの場合trueです。次taskの実claim時だけ解除します。
	bool			   activeIndexAcquisitionClaimed_{} ;
	/** @brief 一scan中のProvider別予約累計。失敗・取消しで返却しない。 */
	struct ProviderReservation {
		/// 対応する公式Providerのstable ID。
		std::wstring  providerId ;
		/// 承認時に予約した最大byte数累計。
		std::uint64_t bytes{} ;
		/// 承認時に予約したfile数累計。
		std::uint32_t files{} ;
	} ;

	/// このobjectが所有する固定計画。
	OfficialPreparationPlan				   plan_ ;
	/// 計画順の対象別状態。
	std::vector<OfficialPreparationItem>   items_ ;
	/// 計画順の対象別network同意。
	std::vector<bool>					   networkApprovals_ ;
	/// Scan全体のProvider別予約。
	std::vector<ProviderReservation>	   reservations_ ;
	/// 最後に受理したscanの不変上限。
	OfficialPreparationLimits			   limits_ ;
	/// 予算を所有するsessionの高水位。
	ScanSessionId						   latestSessionId_{} ;
	/// 再使用を拒否するplan ID高水位。
	std::uint64_t						   latestPlanId_{} ;
	/// 再使用を拒否するoperation ID高水位。
	OperationId							   latestOperationId_{} ;
	/// 全Providerの予約byte数合計。
	std::uint64_t						   reservedBytes_{} ;
	/// 全Providerの予約file数合計。
	std::uint32_t						   reservedFiles_{} ;
	/// 完了待ちtaskの照合用所有値。
	std::optional<OfficialPreparationTask> activeTask_ ;
	/// activeTask_がある場合だけ有効なitems_のindex。
	std::size_t							   activeIndex_{} ;
	/// 現在の状態。
	OfficialPreparationState			   state_{OfficialPreparationState::EMPTY} ;
} ;

/**
 * @brief 許諾本文検証の同期停止確認callbackです。
 */
using PreparationTextCheckpoint = void ( *)( void *context) ;

/**
 * @brief 旧入口と同じ検証を、最大256 UTF-16単位ごとの必須確認付きで行います。
 * @param[in] text 有限許諾本文。
 * @param[in] checkpoint 必須の同期callback。例外を変換しません。
 * @param[in,out] context Callbackが借用する必須context。
 * @return 有効な全文ならtrue。Null引数を無制御へ補完しません。
 */
[[nodiscard]] bool validPreparationEulaTextControlled( std::wstring_view			text,
													  PreparationTextCheckpoint checkpoint,
													  void					   *context) ;
} // namespace drivercrate
