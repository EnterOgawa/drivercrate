//------------------------------------------------------------------------------
/**
 * @file official_driver_rank.h
 * @brief 公式driverのPnP具体性およびrank非退行判定定義。
 * @version 01.02.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  Native未導入根拠を既知現在driverと別のrank modeへ結合。
 * Ver.01.02.00 Shunji Ogawa  2026/10/13  観測Class未確定とINF/native ClassGUIDの独立照合を追加。
 * </pre>
 *
 * @note SetupAPIが算出したrankと端末内PnP IDだけを比較し、versionや日付で適用性を補完しません。実PnP IDを結果へ複写しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// PnP rank監査値型定義。
//------------------------------------------------------------------------------

/**
 * @brief Device側で一致したPnP identifierの種類を表す。
 */
enum class PnpIdentifierKind {
	/// 有効な完全一致がない。
	NONE,
	/// DeviceのHardware ID一覧へ完全一致した。
	HARDWARE_ID,
	/// DeviceのCompatible ID一覧へ完全一致した。
	COMPATIBLE_ID,
} ;

/**
 * @brief Device側PnP identifier一覧内の一致位置をID文字列なしで表す。
 */
struct PnpIdentifierPosition {
	/// 一致したID一覧の種類。
	PnpIdentifierKind kind{PnpIdentifierKind::NONE} ;
	/// Hardware IDまたはCompatible ID一覧内の0-based位置。
	std::uint32_t	  index{} ;
} ;

/** @brief Nativeの現在driver確認結果とrank比較方式を区別します。 */
enum class OfficialDriverRankCurrentState {
	/// 現在driverのMatching IDとfull rankによる非退行比較を必須にします。
	KNOWN_DRIVER,
	/// Present/Code28/属性欠損/installed-node不在をnativeで確認した初回導入です。
	NO_DRIVER,
} ;

/** @brief 元deviceのClass観測をINFのClassと独立に表します。 */
enum class OfficialDriverRankDeviceClassState {
	/// 非空の既知Classを観測し、候補のClass名との一致を要求します。
	KNOWN_CLASS,
	/// NativeがClass propertyの正式な不存在を返しました。
	NOT_PRESENT,
	/// Nativeが正式Unknown名とUnknown GUIDを返しました。
	UNKNOWN_CLASS,
} ;

/**
 * @brief PnP具体性およびrank監査の判断結果を表す。
 */
enum class OfficialDriverRankDecision {
	/// 監査をまだ実行していない。
	NOT_EVALUATED,
	/// ID具体性とWindows rankが現在driver以上である。
	APPLICABLE,
	/// 入力上限、ID構文または一意性が成立しない。
	INVALID_EVIDENCE,
	/// DeviceとINFのsetup classが一致しない。
	CLASS_MISMATCH,
	/// Candidate INFのPnP IDがdeviceへ一致しない。
	CANDIDATE_NOT_MATCHED,
	/// 現在MatchingDeviceIdをdevice一覧へ解決できない。
	CURRENT_MATCH_UNAVAILABLE,
	/// 現在driverのWindows rankを取得できない。
	CURRENT_RANK_UNAVAILABLE,
	/// CandidateのWindows rankを取得できない。
	CANDIDATE_RANK_UNAVAILABLE,
	/// Candidateがdevice側の弱いIDへ一致する。
	IDENTIFIER_POSITION_REGRESSION,
	/// Windows identifier scoreが現在driverより悪い。
	IDENTIFIER_SCORE_REGRESSION,
	/// Signature等を含むfull rankが現在driverより悪い。
	OVERALL_RANK_REGRESSION,
} ;

/**
 * @brief Worker内で取得したPnP IDとWindows rankをpure判定へ渡す。
 *
 * @note 全文字列viewは本呼出し中だけ有効であり、外部送信または結果への複写を行わない。
 */
struct OfficialDriverRankEvidence {
	/// 現在deviceのsetup class名。
	std::wstring_view				   deviceClass ;
	/// G11-Cで検証したcandidate INF Class名。
	std::wstring_view				   candidateClass ;
	/// Device側の順序付きHardware ID群。
	std::span<const std::wstring>	   deviceHardwareIds ;
	/// 順序付きCompatible ID群。
	std::span<const std::wstring>	   deviceCompatibleIds ;
	/// Candidate INFの検証済みPnP ID群。
	std::span<const std::wstring>	   candidateIds ;
	/// Windowsが現在driverに使用したPnP ID。
	std::wstring_view				   currentMatchingDeviceId ;
	/// 現在driverのSetupAPI Rank。
	std::optional<std::uint32_t>	   currentRank ;
	/// CandidateのSetupAPI Rank。
	std::optional<std::uint32_t>	   candidateRank ;
	/// Workerのnative確認に結合する比較方式。空版からNO_DRIVERを推測しません。
	OfficialDriverRankCurrentState	   currentState{OfficialDriverRankCurrentState::KNOWN_DRIVER} ;
	/// 元Classの観測方式。失敗や空文字をNOT_PRESENTへ変換しません。
	OfficialDriverRankDeviceClassState deviceClassState{
		OfficialDriverRankDeviceClassState::KNOWN_CLASS} ;
	/// 同じ検査済みINFのWindows ClassGUID。未確定初回だけで必須にします。
	std::wstring_view candidateInfClassGuid ;
	/// 単一INFのWindows互換一覧が返したClassGUID。INFと完全一致を要求します。
	std::wstring_view candidateNativeClassGuid ;
} ;

/**
 * @brief PnP identifierとrank非退行の監査結果をID文字列なしで表す。
 */
struct OfficialDriverRankAudit {
	/// 判断。
	OfficialDriverRankDecision	   decision{OfficialDriverRankDecision::NOT_EVALUATED} ;
	/// 現在MatchingDeviceIdのdevice側位置。
	PnpIdentifierPosition		   currentPosition ;
	/// Candidateが一致した最良のdevice側位置。
	PnpIdentifierPosition		   candidatePosition ;
	/// 現在driverのfull Windows rank。
	std::uint32_t				   currentRank{} ;
	/// Candidateのfull Windows rank。
	std::uint32_t				   candidateRank{} ;
	/// 現在rankの下位16-bit。
	std::uint16_t				   currentIdentifierScore{} ;
	/// Candidate rankの下位16-bit。
	std::uint16_t				   candidateIdentifierScore{} ;
	/// 現在rankを使った比較か、native未導入状態の候補rank確認かを保持します。
	OfficialDriverRankCurrentState currentState{OfficialDriverRankCurrentState::KNOWN_DRIVER} ;
} ;

/**
 * @brief PnP identifierの具体性とSetupAPI rankが現在driverから退行しないか判定する。
 * 公式driverのPnP具体性とrank非退行を判定する。
 * Policy拒否はdecisionに残し、Windows rankを独自再計算せずversionまたは日付を判断へ使用しない。
 * @param[in] evidence Worker内で固定したdevice、candidateおよびrank evidence。 Worker内で固定したIDとWindows rank。
 * @param[out] audit ID文字列を含まない監査結果。 ID文字列を含まない判断結果。
 * @return 入力構造が有限で妥当な場合は`true`。不正入力の場合は`false`。 入力構造が妥当なら`true`、不正なら`false`。
 * @note Policy上の拒否は`true`と各decisionで返し、versionまたは日付を使用しない。
 */
[[nodiscard]] bool evaluateOfficialDriverRank( const OfficialDriverRankEvidence &evidence,
											  OfficialDriverRankAudit		   &audit) noexcept ;

} // namespace drivercrate
