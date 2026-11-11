//------------------------------------------------------------------------------
/**
 * @file local_diagnostic_log.h
 * @brief EXE隣へ保存する匿名数値診断の有界入口。
 * @version 01.04.02
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  明示要求された匿名診断を非待機queueへ接続。
 * Ver.01.01.00 Shunji Ogawa  2026/11/03  取得前の版比較分類件数を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/11/08  匿名導入診断と保存状態・元数値の有限確認を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/11/08  準備不成立後の元表示保持と段階別匿名診断を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/11/09  内部fixtureの排出開始制御を追加し、通常非待機契約を維持。
 * Ver.01.04.02 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 保存不能は通常処理へ伝播しません。文字列本文や端末identityを受けません。
 * @see docs/adr/0427-local-anonymous-scan-diagnostics.md
 */
//------------------------------------------------------------------------------
#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace local_diagnostic_detail {
struct Access ;
}

/** @brief 任意本文を持たない記録地点。 */
enum class DiagnosticEvent {
	/// Process開始とtokenElevation。
	STARTUP,
	/// 操作開始の受付結果。
	OPERATION_STARTED,
	/// 受理済み通常scanの確定結果。
	SCAN_COMPLETED,
	/// 組込みProvider別の確定結果。
	PROVIDER_SCAN,
	/// 元HTTP/codecとcache利用の区別。
	INDEX_REFRESH,
	/// 保存世代と認証cacheの区別。
	INDEX_STORE,
	/// 全record処理と関係件数。
	INDEX_SCAN,
	/// Lookupの未判定と部分positive。
	INDEX_LOOKUP,
	/// 計画有無と実target件数。
	PREPARATION_PLAN,
	/// 候補と表示device/filterの区別。
	CANDIDATE_DISPLAY,
	/// 閉じた分類別の候補件数。
	CANDIDATE_REASONS,
	/// 元操作の受理された終端。
	OPERATION_COMPLETED,
	/// Queueの欠落件数。
	QUEUE_DROPPED,
	/// Scan開始時の固定Provider有効設定。
	PROVIDER_CONFIGURATION,
	/// 利用者のInstall要求。操作受理とは別です。
	INSTALL_REQUESTED,
	/// Controllerが受理した導入開始です。
	INSTALL_STARTED,
	/// 準備操作の開始または終端の固定件数です。
	PREPARATION_OPERATION,
	/// 元候補一件の取得/導入/引継ぎ結果です。
	INSTALL_ITEM,
	/// 必要役割のstage/指定API/反映区分です。
	INSTALL_ROLE,
	/// 元選択だけの事後読取状態です。
	POST_INSTALL,
	/// 保護開始と終了の元結果です。
	INSTALL_PROTECTION,
	/// 選択した準備targetの固定段階と元数値です。
	PREPARATION_TARGET,
	/// 元Install意図の検査後解決区分です。
	PREPARATION_RESOLUTION,
	/// UIの導入継続を停止した固定理由です。
	PREPARATION_CONTINUATION,
} ;

/** @brief 診断列の閉じた名前集合。値は整数だけです。 */
enum class DiagnosticField {
	/// Token照会が成立しました。
	ELEVATION_KNOWN,
	/// TokenElevationのboolです。
	ELEVATED,
	/// 確定状態機械の区分です。
	STATE,
	/// 操作または元APIが成立しました。
	SUCCEEDED,
	/// 元処理の結果区分です。
	OUTCOME,
	/// 未計測と0の区別です。
	KNOWN,
	/// 当該設定で有効です。
	ENABLED,
	/// 生identityを含まない総数です。
	TOTAL,
	/// 処理済みの件数です。
	PROCESSED,
	/// 未処理の件数です。
	REMAINING,
	/// 元HTTP statusです。
	HTTP_STATUS,
	/// HTTP送信開始回数です。
	SENDS,
	/// 受信したbyte数です。
	RECEIVED_BYTES,
	/// 元HTTP HRESULTのuint32 bit patternです。
	HTTP_ERROR,
	/// Manifest codec拒否区分です。
	MANIFEST_STATUS,
	/// Asset codec拒否区分です。
	ASSET_STATUS,
	/// Record codec拒否区分です。
	RECORDS_STATUS,
	/// 元manifestの認証済み世代です。
	ATTEMPTED_GENERATION,
	/// 保存済み高水位世代です。
	PERSISTED_GENERATION,
	/// 世代値が実観測されたことを表します。
	GENERATION_KNOWN,
	/// 原commitの確定区分です。
	COMMIT,
	/// 現時点で認証snapshotがあります。
	USABLE_SNAPSHOT,
	/// Fresh取得とは異なるcache利用です。
	USED_CACHE,
	/// 認証cacheの保存世代です。
	CACHE_GENERATION,
	/// 認証cacheの世代を実観測しました。
	CACHE_GENERATION_KNOWN,
	/// Storeの元区分です。
	STORE_STATUS,
	/// Lookupの元区分です。
	LOOKUP_STATUS,
	/// 保持された関係tuple数です。
	RELATIONS,
	/// 関係のあるopaque device数です。
	RELATED_DEVICES,
	/// 一意な公開ID照合関係数です。
	MATCHED,
	/// 非一意関係数です。
	NON_UNIQUE,
	/// 未判定関係数です。
	UNDETERMINED,
	/// 未判定に含まれる部分positive関係数です。
	PARTIAL_POSITIVE,
	/// 実resolver呼出し数です。
	RESOLVER_CALLS,
	/// 計画objectがあります。対象数とは別です。
	PLAN_PRESENT,
	/// 元計画のtarget件数です。
	TARGETS,
	/// 索引由来の計画target件数です。
	INDEX_TARGETS,
	/// 取得対象を構築できない関係数です。
	UNAVAILABLE,
	/// 既存保持上限で除外された関係数です。
	CAPACITY_REJECTED,
	/// 現在観測行数です。
	CURRENT,
	/// Install可能とされた候補数です。
	INSTALLABLE,
	/// 元predicateで推奨表示される候補数です。
	RECOMMENDED,
	/// 元predicateで表示される未検査初回参照数です。
	INITIAL_REFERENCES,
	/// 取得前参照の総数です。
	PENDING_REFERENCES,
	/// 初回確認へ分類されなかった取得前参照数です。
	NON_INITIAL_REFERENCES,
	/// 推奨filterが有効です。
	RECOMMENDED_FILTER,
	/// 実treeへ保持されたdevice行数です。
	VISIBLE_DEVICES,
	/// 通常更新へ分類された候補数です。
	UPDATES,
	/// 同版または再導入へ分類された候補数です。
	REINSTALLS,
	/// 旧版へ分類された候補数です。
	DOWNGRADES,
	/// 初回導入へ分類された候補数です。
	INITIAL_INSTALLS,
	/// system適用性が未確認の件数です。
	APPLICABILITY_PENDING,
	/// system適用性で拒否された件数です。
	APPLICABILITY_REJECTED,
	/// 明示されたOS不一致理由の件数です。
	OS_REJECTED,
	/// 元Providerの対象device件数です。
	ELIGIBLE,
	/// 元Providerの評価済み件数です。
	ASSESSED,
	/// 計測snapshotが受理されました。
	MEASUREMENT_ACCEPTED,
	/// 登録driverの一意な現在観測がある取得前参照数です。
	REGISTERED_REFERENCES,
	/// driver有無を確認できない取得前参照数です。
	UNKNOWN_PRESENCE_REFERENCES,
	/// 元statusに数える推奨のinstallable候補数です。
	RECOMMENDED_INSTALLABLE,
	/// 新版と比較できた取得前参照数です。
	NEWER_REFERENCES,
	/// 同版と比較できた取得前参照数です。
	SAME_REFERENCES,
	/// 旧版と比較できた取得前参照数です。
	OLDER_REFERENCES,
	/// 版比較条件が不足した取得前参照数です。
	UNKNOWN_VERSION_REFERENCES,
	/// 操作内だけの1起点連番です。
	ORDINAL,
	/// 元処理段階です。
	STAGE,
	/// DriverActionまたはDriverPlanRoleです。
	ACTION,
	/// 元download結果です。
	DOWNLOAD_OUTCOME,
	/// HRESULT bit patternです。
	DOWNLOAD_ERROR,
	/// 元install結果です。
	INSTALL_OUTCOME,
	/// HRESULT bit patternです。
	INSTALL_ERROR,
	/// 公式installer引継ぎです。
	HANDOFF,
	/// 引継ぎ結果です。
	HANDOFF_OUTCOME,
	/// HRESULT bit patternです。
	HANDOFF_ERROR,
	/// Windowsの元再起動要求です。
	REBOOT_REQUIRED,
	/// 元roleの反映区分です。
	REFLECTION,
	/// 元APIが失敗診断を返さなかった事実です。
	DIAGNOSTIC_MISSING,
	/// 元scan/deviceへの一意結合です。
	BOUND,
	/// DeviceDriverPresenceです。
	PRESENCE,
	/// 元node読取区分です。
	NODE_READ,
	/// 元driverKey読取区分です。
	DRIVER_KEY_READ,
	/// 元version読取区分です。文字列は含みません。
	VERSION_READ,
	/// 元問題codeが読めました。
	PROBLEM_KNOWN,
	/// 元問題codeだけです。
	PROBLEM_CODE,
	/// 要求Windows版と事後版の0不明/1一致/2不一致です。
	REQUEST_VERSION_RELATION,
	/// 事前Windows版と事後版の0不明/1不変/2変化です。
	BEFORE_VERSION_RELATION,
	/// 元Install意図の件数です。
	INTENT_COUNT,
	/// READY解決件数です。
	READY_COUNT,
	/// 元DTOに非zeroの診断codeがあります。UI拒否からcodeを作りません。
	CODE_KNOWN,
	/// 元計画で取得を明示選択した件数です。
	SELECTED_COUNT,
	/// 診断投影上限による省略件数です。処理失敗数ではありません。
	OMITTED,
	/// 内容構造とINF解析を通過した件数です。
	PARSED_COUNT,
	/// 通常Windows署名検査で拒否したINF件数です。
	SIGNATURE_REJECTED_COUNT,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	BINDING_PATH,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	BINDING_REJECTION,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	BINDING_OBSERVED,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	BINDING_STAGE,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	BINDING_FLAGS,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	DEPENDENCY_REASON,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	ROOT_SIGNATURE_ERROR,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	DEPENDENCY_SIGNATURE_ERROR,
	/// 元bindingの固定数値です。本文や権限を持ちません。
	DEPENDENCY_PROVENANCE_ERROR,
} ;

/** @brief 保存状態です。実行権限/driverの成否には使いません。 */
enum class DiagnosticStorageState {
	/// 未開始です。
	NOT_STARTED,
	/// 保存先の確認中です。
	STARTING,
	/// 保存先を確保しました。queue全保存とは別です。
	ACTIVE,
	/// 保存を停止しました。
	FAILED,
	/// 有界終了でwriter終端を確認しました。
	STOPPED,
	/// 有界待機で終端を確認できませんでした。
	STOP_TIMEOUT
} ;
/** @brief 自由本文を持たない保存失敗の固定段階です。 */
enum class DiagnosticStorageStage {
	/// 失敗を観測していません。
	NONE,
	/// 実module位置を取得できません。
	MODULE_PATH,
	/// 許可する通常絶対pathではありません。
	PATH,
	/// 祖先の固定を拒否しました。
	ANCESTOR,
	/// log folderの作成/固定を拒否しました。
	FOLDER,
	/// 安全なslotを確保できません。
	SLOT,
	/// 所有headerの保存に失敗しました。
	HEADER,
	/// 原byteの読取/所有文法を拒否しました。
	READ,
	/// 行write/完全byte数の確認に失敗しました。
	WRITE,
	/// 元flushに失敗しました。
	FLUSH,
	/// 資源の確保に失敗しました。
	RESOURCE,
	/// 有界終了を確認できません。
	STOP
} ;
/** @brief 保存workerの匿名read-only状態です。投入と永続化を区別します。 */
struct DiagnosticStorageStatus {
	/// 保存可能/停止/未完了の区分です。
	DiagnosticStorageState state{DiagnosticStorageState::NOT_STARTED} ;
	/// 最初の保存停止段階です。
	DiagnosticStorageStage stage{DiagnosticStorageStage::NONE} ;
	/// 元Win32 code。codeKnown=falseなら0に意味を付けません。
	std::uint32_t		   code{} ;
	/// 元APIからcodeを取得しました。
	bool				   codeKnown{} ;
	/// 起動recordのwriteとflushが完了しました。
	bool				   startupFlushed{} ;
	/// 実writeとflushを確認したrecord数です。
	std::uint64_t		   saved{} ;
	/// 投入済みで保存をまだ確認していないrecord数です。
	std::uint64_t		   pending{} ;
	/// 投入競合/容量/停止で保存できなかったrecord数です。
	std::uint64_t		   dropped{} ;
} ;

/** @brief Registryからだけ生成するProvider名token。 */
class DiagnosticProvider final {
public:
	/**
	 * @brief applicationを既定値にします。
	 */
	DiagnosticProvider() noexcept = default ;
	/**
	 * @brief 任意文字列を保存せずcanonical registryへ照合します。
	 * @param[in] id 呼出し中だけ借用する元stable ID。
	 * @return 既知registryの静的IDまたは固定unknown token。
	 */
	[[nodiscard]] static DiagnosticProvider fromId( std::wstring_view id) noexcept ;
	/**
	 * @brief Canonical static IDだけを同期serializeへ貸します。
	 * @return Process lifetimeの固定ID。任意入力のviewではありません。
	 */
	[[nodiscard]] std::wstring_view			id() const noexcept ;

private:
	/// Registry由来または固定literalだけを借用します。
	std::wstring_view id_{L"application"} ;
} ;

/** @brief 文字列本文を含まない固定容量の一記録。 */
struct DiagnosticRecord {
	/// 閉じた記録地点です。
	DiagnosticEvent											   event{DiagnosticEvent::STARTUP} ;
	/// Canonical Provider tokenです。
	DiagnosticProvider										   provider ;
	/// Process内の操作連番だけです。
	std::uint64_t											   operation{} ;
	/// 元enumの数値区分です。
	std::int32_t											   status{} ;
	/// 元HRESULT/Win32診断です。
	std::int32_t											   error{} ;
	/// 閉じた列と整数の最大16組です。
	std::array<std::pair<DiagnosticField, std::uint64_t>, 16U> fields{} ;
	/// 実使用列数です。
	std::uint8_t											   fieldCount{} ;
	/**
	 * @brief 固定枠へ一つの数値列を追加します。
	 * @param[in] field 閉じた列識別子。
	 * @param[in] value 個数/enum/boolだけの値。
	 * @return 同じ記録。超過分は保持しません。
	 */
	DiagnosticRecord &add( DiagnosticField field, std::uint64_t value) noexcept ;
} ;

/** @brief 専用workerへ固定queueで渡し、保存失敗を機能へ返さないlogger。 */
class LocalDiagnosticLog final {
public:
	/**
	 * @brief 未開始loggerを構築します。
	 */
	LocalDiagnosticLog() noexcept = default ;
	/**
	 * @brief 最大200msだけ終了を待ち、残worker所有を安全に残します。
	 */
	~LocalDiagnosticLog() ;
	/**
	 * @brief 単一queue所有のcopyを禁止します。
	 */
	LocalDiagnosticLog( const LocalDiagnosticLog &) = delete ;
	/**
	 * @brief 単一queue所有のcopyを禁止します。
	 */
	LocalDiagnosticLog					 &operator=( const LocalDiagnosticLog &) = delete ;
	/**
	 * @brief 実EXEの絶対directoryだけで非同期保存を開始します。
	 */
	void								  start() noexcept ;
	/**
	 * @brief I/Oを行わずqueueへ非待機で投入します。
	 * @param[in] record 文字列本文を持たない有界snapshotです。
	 */
	void								  append( const DiagnosticRecord &record) noexcept ;
	/**
	 * @brief 新規投入を止め、終了を最大200msだけ待ちます。
	 */
	void								  stop() noexcept ;
	/**
	 * @brief I/Oや待機をせず保存状態を読みます。
	 * @return 保存済みと未保存/失敗を区別した固定snapshot。
	 */
	[[nodiscard]] DiagnosticStorageStatus status() const noexcept ;

private:
	/// Workerと共有する有限queue・所有handleです。
	struct State ;
	/// Worker終了まで有効な共有所有です。
	std::shared_ptr<State>	state_ ;
	/// Workerを開始できなかった元理由です。開始threadだけが書きます。
	DiagnosticStorageStatus startFailure_ ;
	/**
	 * @brief 製品または内部fixtureの絶対folderへだけ開始します。
	 * @param[in] folder 元EXE directoryまたは内部fixtureの新規directory。
	 * @param[in] paused 内部fixtureだけがthread開始前にqueue排出を止めます。
	 */
	void					startInFolder( std::wstring_view folder, bool paused = false) noexcept ;
	friend struct local_diagnostic_detail::Access ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 製品のprocess loggerを開始し、昇格有無だけを記録します。
 */
//------------------------------------------------------------------------------
void startLocalDiagnostics() noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 製品のprocess loggerへ数値snapshotを非待機投入します。
 * @param[in] record 有界な匿名記録です。
 */
//------------------------------------------------------------------------------
void recordLocalDiagnostic( const DiagnosticRecord &record) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief Message loop終了後に最大200msだけ保存終了を待ちます。
 */
//------------------------------------------------------------------------------
void stopLocalDiagnostics() noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief Process loggerの保存状態を非待機で読みます。
 * @return 固定数値だけの現在snapshot。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DiagnosticStorageStatus localDiagnosticStatus() noexcept ;

namespace local_diagnostic_detail {
/** @brief 通信・実inventoryを使わない内部file回帰用入口。 */
struct Access {
	/**
	 * @brief Fixture folderで製品と同じ保存処理を開始します。
	 * @param[in,out] log 未開始logger。
	 * @param[in] folder Fixtureの絶対folder。製品設定には接続しません。
	 */
	static void start( LocalDiagnosticLog &log, std::wstring_view folder) noexcept ;
	/**
	 * @brief 内部fixtureのqueue排出だけをthread開始前から止めます。
	 * @param[in,out] log 未開始loggerです。
	 * @param[in] folder Fixtureの絶対folderです。製品設定には接続しません。
	 * @note 通常の投入は非待機のままです。resumeまたはstopが元wakeで排出を許可します。
	 */
	static void startPaused( LocalDiagnosticLog &log, std::wstring_view folder) noexcept ;
	/**
	 * @brief 内部fixtureの排出を一度だけ再開します。再pauseや再初期化はしません。
	 * @param[in,out] log startPausedで開始した試験所有loggerです。
	 */
	static void resume( LocalDiagnosticLog &log) noexcept ;
	/**
	 * @brief 投入済み記録の保存を有限に待ちます。
	 * @param[in] log 試験所有logger。
	 * @return Queue空か保存停止を観測した場合true。
	 */
	[[nodiscard]] static bool drain( const LocalDiagnosticLog &log) noexcept ;
	/**
	 * @brief 自己所有fixtureだけでwriter失敗/有界終了を注入します。
	 * @param[in,out] log 試験所有logger。
	 * @param[in] stage WRITE/FLUSH/STOPだけ。製品から呼びません。
	 */
	static void				  fail( LocalDiagnosticLog &log, DiagnosticStorageStage stage) noexcept ;
	/**
	 * @brief 内部UI fixtureのprocess writerだけへ固定失敗を与えます。
	 * @param[in] stage WRITE/FLUSH/STOPだけです。製品から呼びません。
	 */
	static void				  failProcess( DiagnosticStorageStage stage) noexcept ;
} ;
}
}
