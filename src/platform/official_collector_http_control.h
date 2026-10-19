//------------------------------------------------------------------------------
/**
 * @file official_collector_http_control.h
 * @brief 台帳へ依存しない収集HTTPの制御interfaceと観測型です。
 * @version 01.00.00
 * @date 2026/09/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  共通HTTPの固定観測と抽象制御境界を追加。
 * </pre>
 *
 * @note 実装や台帳を保持せず、呼出し中だけworker所有の制御を借用します。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <functional>
#include <optional>

namespace drivercrate {

/** @brief 最初に確定したjob終端を表します。 */
enum class CollectorIoCause {
	/// 終端が未確定です。
	NONE,
	/// 全段階とnative解放が期限内に完了しました。
	COMPLETE,
	/// 利用者の取消しを受理しました。
	CANCELLED,
	/// UTCまたは単調期限へ到達しました。
	DEADLINE,
	/// 名前解決を拒否しました。
	DNS,
	/// HTTPの送受信または応答を拒否しました。
	HTTP,
	/// 本文上限を超える根拠を観測しました。
	BODY_LIMIT,
	/// 本文終端や完全な長さが未確認です。
	BODY_INCOMPLETE,
	/// 本文解析・射影を拒否しました。
	PARSER,
	/// 準備・identity・資源回収が不成立です。
	SETUP,
	/// 他jobの保存失敗等により新規I/Oを停止しました。
	SHARED_STOP,
	/// 時計の後退・欠損・範囲外を観測しました。
	CLOCK
} ;

/** @brief 自由文やURLを持たない固定I/O段階です。 */
enum class CollectorIoStage {
	/// 永続予約からの起動準備。
	RESERVATION,
	/// Workerの準備。
	SETUP,
	/// Public宛先の名前解決。
	DNS,
	/// HTTP handle生成とoption設定。
	OPEN,
	/// 一度だけの送信。
	SEND,
	/// 応答待機。
	RECEIVE,
	/// 有限header検査。
	HEADERS,
	/// 受信可能量の照会。
	QUERY,
	/// 本文の有限読取り。
	READ,
	/// 厳密UTF-8変換。
	DECODE,
	/// 本文hash計算。
	HASH,
	/// 公式metadata解析。
	PARSE,
	/// 対象製品への射影。
	PROJECT,
	/// 所有native資源の解放。
	CLEANUP,
	/// 結果確定。
	COMPLETE
} ;

/** @brief 元数値の意味を区別する固定domainです。 */
enum class CollectorIoErrorDomain {
	/// Errorなし。
	NONE,
	/// GetLastErrorの原値。
	WIN32_ERROR,
	/// Winsock APIの原値。
	WINSOCK_ERROR,
	/// HRESULTの原32 bit。
	HRESULT_ERROR,
	/// HTTP statusによる拒否。
	HTTP,
	/// Parserの固定拒否。
	PARSER
} ;

/** @brief 同じ観測で採取したUTCとprocess単調時計です。 */
struct CollectorHttpClockSample {
	/// UTC millisecond。
	std::uint64_t utcMillis{} ;
	/// Process内の単調millisecond。
	std::uint64_t steadyMillis{} ;
} ;

/** @brief Thread-safeかつ非blockingの時計です。例外はclock異常として扱います。 */
using CollectorHttpClock = std::function<CollectorHttpClockSample()> ;

/** @brief APIの原値を後続APIで上書きしない固定診断です。 */
struct CollectorIoError {
	/// 元数値のdomain。
	CollectorIoErrorDomain domain{CollectorIoErrorDomain::NONE} ;
	/// 符号なしで保存する原32 bit。HRESULTの符号を削りません。
	std::uint32_t		   code{} ;
	/// 失敗したAPIの段階。
	CollectorIoStage	   stage{CollectorIoStage::RESERVATION} ;
} ;

/** @brief Allocationなしでコピーできるworkerの観測値です。 */
struct CollectorIoSnapshot {
	/// 最初に確定した原因。後続errorで置換しません。
	CollectorIoCause				cause{CollectorIoCause::NONE} ;
	/// 最初の終端時の段階。未終端なら現在段階。
	CollectorIoStage				stage{CollectorIoStage::RESERVATION} ;
	/// 分類用の数値とdomain。
	CollectorIoError				error ;
	/// 最初のnative API失敗。取消し先着時も副診断として保持します。
	std::optional<CollectorIoError> native ;
	/// 明示SendRequest API呼出し回数。予約数ではありません。
	std::uint32_t					sends{} ;
	/// 本文量が既知の場合true。Wire全量を意味しません。
	bool							bytesKnown{true} ;
	/// 成功readの累積。未知終了では本文量の下限です。
	std::uint64_t					lowerBytes{} ;
	/// 元予約からのUTC期限。
	std::uint64_t					deadlineUtcMillis{} ;
	/// 予約前clock対からの単調経過。欠測はnullopt。
	std::optional<std::uint64_t>	elapsedMillis ;
	/// Headerを実観測したUTC。
	std::optional<std::uint64_t>	headerUtcMillis ;
	/// 外部停止を最初に受理した単調経過。
	std::optional<std::uint64_t>	stopElapsedMillis ;
	/// 結果確定時のUTC。時計異常ではnullopt。
	std::optional<std::uint64_t>	finishedUtcMillis ;
	/// 所有native資源の全解放を確認した場合true。
	bool							nativeReleased{true} ;
	/// 終端後のcleanupも終了し、結果を確定した場合true。
	bool							sealed{} ;
} ;

/** @brief 共通HTTPが借用する制御境界です。台帳・worker・native I/Oは所有しません。 */
class OfficialCollectorHttpControl {
public:
	/** @brief 実装を所有する呼出し側が破棄します。 */
	virtual ~OfficialCollectorHttpControl() = default ;
	/** @brief 停止と二clockを確認します。
	 * @param[in] stage 次の固定段階。
	 * @param[in] phaseLimitMillis 正数のphase上限。
	 * @return 許可する正数timeout、停止は0。
	 */
	[[nodiscard]] virtual std::uint32_t begin( CollectorIoStage stage,
											  std::uint32_t	   phaseLimitMillis) = 0 ;
	/** @brief SEND開始確定後、API呼出しを一度だけ計数します。
	 * @return 呼出し可能ならtrue。
	 */
	[[nodiscard]] virtual bool			noteSendCall() = 0 ;
	/** @brief 成功read量を停止確認より先に計数します。
	 * @param[in] requested 正数の要求量。
	 * @param[in] received 実際に返された量。
	 * @return 範囲内ならtrue。
	 */
	[[nodiscard]] virtual bool noteRead( std::uint32_t requested, std::uint32_t received) = 0 ;
	/** @brief Header観測UTCを一度だけ保存します。
	 * @return 停止していなければtrue。
	 */
	[[nodiscard]] virtual bool noteHeaders() = 0 ;
	/** @brief 最初の失敗とnative副診断を保持します。
	 * @param[in] cause 固定終端原因。
	 * @param[in] error 元errorと段階。
	 * @param[in] bytesUnknown 完全な受信量が未知ならtrue。
	 */
	virtual void fail( CollectorIoCause cause, CollectorIoError error, bool bytesUnknown) = 0 ;
	/** @brief 所有native資源の全解放確認を更新します。
	 * @param[in] released 全解放が確認できた場合true。
	 */
	virtual void setNativeReleased( bool released) = 0 ;
	/** @brief 整合した固定観測値を取得します。
	 * @return URLを含まない観測値。
	 */
	[[nodiscard]] virtual CollectorIoSnapshot snapshot() const = 0 ;
} ;
} // namespace drivercrate
