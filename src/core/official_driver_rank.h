//------------------------------------------------------------------------------
/**
 * @file official_driver_rank.h
 * @brief 公式driverのPnP具体性およびrank非退行判定定義
 * @version 01.02.05
 * @date 2026/09/04
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  Native未導入根拠を既知現在driverと別のrank modeへ結合
 * Ver.01.02.00 Shunji Ogawa  2026/10/13  観測Class未確定とINF/native ClassGUIDの独立照合を追加
 * Ver.01.02.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.02.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.02.03 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.02.04 Shunji Ogawa  2026/11/19  独自クラスの登録読取り失敗を専用段階へ追加
 * Ver.01.02.05 Shunji Ogawa  2026/11/23  同梱INF委譲の読取り失敗を診断段階へ追加
 * </pre>
 *
 * @note SetupAPIが算出したrankと端末内PnP IDだけを比較し、versionや日付で適用性を補完しません。実PnP IDを結果へ複写しません
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

/** @brief 最初のINF適用性失敗の閉じた評価経路です */
enum class InfDiagnosticPath {
	/// 元失敗の経路を保持していません
	NONE,
	/// 同INFの公開identity読取です
	PUBLISHED_IDENTITY,
	/// 候補だけのWindows rank観測です
	CANDIDATE_OBSERVATION,
	/// 現在状態を含む完全rank監査です
	FULL_RANK_AUDIT,
} ;

/** @brief 同rank評価内の現在/候補の区間です */
enum class InfDiagnosticPhase {
	/// 区間の区別を保持していません
	NONE,
	/// rank前の現在snapshotです
	CURRENT_BEFORE,
	/// 現在driverのrankです
	CURRENT_RANK,
	/// 候補INFのrankです
	CANDIDATE_RANK,
	/// rank後の現在snapshotです
	CURRENT_AFTER,
} ;

/** @brief 原codeを得たAPIと内部整合を区別します */
enum class InfDiagnosticOrigin {
	/// 下位のAPI/内部整合の区別が未記録です
	UNRECORDED,
	/// 実API失敗地点で原codeを観測しました
	NATIVE_API,
	/// 型/境界/tuple等の内部整合拒否です
	INTERNAL_CONTRACT,
} ;

/** @brief 本文を持たないINF適用性失敗のleafです */
enum class InfDiagnosticStage {
	/// 失敗leafを保持していません
	NONE,
	/// 元入力/owner/sessionの検査です
	INPUT,
	/// 同INF読取前のhashです
	HASH_BEFORE,
	/// 同INFをread-onlyで開くAPIです
	IDENTITY_OPEN,
	/// 公開ClassGUIDの元directive読取です
	IDENTITY_CLASS_READ,
	/// 公開ClassGUIDの構文/長さです
	IDENTITY_CLASS_VALUE,
	/// 同INFのWindows Models読取です
	IDENTITY_MODELS,
	/// 元ID列/Modelsとの整合です
	IDENTITY_TUPLE,
	/// 読取後の同INF hashです
	HASH_AFTER,
	/// 読取前後の原byte一致です
	HASH_MATCH,
	/// 一deviceの情報集合作成です
	DEVICE_CREATE,
	/// 同native deviceのopenです
	DEVICE_OPEN,
	/// 現在Class属性readerの失敗です
	CURRENT_CLASS_PROPERTY,
	/// 現在ClassGUIDのbyte幅です
	CURRENT_CLASS_SIZE,
	/// 現在nodeと属性GUIDの一致です
	CURRENT_CLASS_MATCH,
	/// 現在Class名/GUID/欠損の整合です
	CURRENT_CLASS_STATE,
	/// 現在driver属性readerの失敗です
	CURRENT_PROPERTY,
	/// 現在present属性readerの失敗です
	PRESENT_PROPERTY,
	/// 現在node statusの読取です
	NODE_STATE,
	/// present/nodeの型/実在整合です
	PRESENT_STATE,
	/// 未導入とinstalled-nodeの整合です
	INSTALLED_NODE,
	/// 現在driver/Class/IDの完全性です
	CURRENT_TUPLE,
	/// 一覧構築parameter取得です
	PARAMETERS_READ,
	/// 限定parameter保存です
	PARAMETERS_WRITE,
	/// 候補INF ClassのWindows読取です
	INF_CLASS_READ,
	/// 候補INF Class名/GUIDの整合です
	INF_CLASS_VALUE,
	/// 限定互換driver listの構築です
	LIST_BUILD,
	/// 元INFとWindows一覧Classの一致です
	LIST_CLASS_MATCH,
	/// 限定listのdriver node列挙です
	NODE_ENUMERATION,
	/// driver detailの必要容量通知です
	DETAIL_SIZE,
	/// driver detail本体のAPI読取です
	DETAIL_READ,
	/// driver detailの容量/終端整合です
	DETAIL_BOUNDS,
	/// driver detailの必須metadata不足です
	DETAIL_EMPTY,
	/// 一driver nodeのWindows rank読取です
	RANK_READ,
	/// 監査前後の現在snapshot一致です
	STATE_MATCH,
	/// 既知deviceと候補Classの一致です
	DEVICE_CLASS_MATCH,
	/// 純粋rank評価の根拠整合です
	RANK_EVIDENCE,
	/// 正常終端前の有限列挙上限です
	ENUMERATION_LIMIT,
	/// 同所有INFの現在属性です
	INF_ATTRIBUTES,
	/// 完全rank前の同INF内容再検証です
	CONTENT_REVERIFY,
	/// 独自クラスの登録と元端末の作用の読取りです
	DECLARATIVE_CLASS_EFFECTS,
	/// ストレージの実選択・元ID・Windows同梱INFの委譲照合です
	INBOX_NULL_DRIVER,
} ;

/** @brief 最初の同pair errorへだけ結ぶ匿名診断です。許可/判定を持ちません */
struct InfFailureDiagnostic {
	/// 最初の元失敗に対応する評価経路です
	InfDiagnosticPath	path{InfDiagnosticPath::NONE} ;
	/// 現在/候補rankの区間です
	InfDiagnosticPhase	phase{InfDiagnosticPhase::NONE} ;
	/// 元失敗leafです。成功時はNONEです
	InfDiagnosticStage	stage{InfDiagnosticStage::NONE} ;
	/// API/内部整合/未記録を区別します
	InfDiagnosticOrigin origin{InfDiagnosticOrigin::UNRECORDED} ;
	/// 元firstPairErrorと照合する32bit HRESULTです
	std::int32_t		error{} ;
	/// 直後に観測した元native codeです。0も実値として保持します
	std::uint32_t		nativeCode{} ;
	/// nativeCodeを元API地点で保持した場合だけtrueです
	bool				nativeCodeKnown{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同評価内の最初の失敗leafだけを記録します
 * @param[in,out] diagnostic 任意の同期出力です。nullは診断を保存しません
 * @param[in] stage 元失敗地点です。後段の補足で上書きしません
 * @param[in] origin 元codeの由来です。未保持をAPIと推定しません
 * @param[in] nativeCode 元地点で観測したcodeです。未観測はnulloptです
 * @note API/割当てを呼ばず、元のGetLastError/判定/戻値へ作用しません
 */
//------------------------------------------------------------------------------
inline void markInfFailure( InfFailureDiagnostic *diagnostic, const InfDiagnosticStage stage,
						   const InfDiagnosticOrigin		  origin,
						   const std::optional<std::uint32_t> nativeCode = std::nullopt) noexcept
{
	// より深い元leafやnull出力を変更しません
	if( diagnostic && diagnostic->stage == InfDiagnosticStage::NONE) {
		diagnostic->stage			= stage ;
		diagnostic->origin			= origin ;
		diagnostic->nativeCode		= nativeCode.value_or( 0U) ;
		diagnostic->nativeCodeKnown = nativeCode.has_value() ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元戻値と同じ失敗へ診断を閉じ、成功時は全て消去します
 * @param[in,out] diagnostic 任意の同期出力です。null可です
 * @param[in] path 当該公開評価入口です
 * @param[in] error 元処理が返したHRESULTです。変更しません
 * @return 常に元errorそのものです
 * @note native APIを呼ばず、診断から実行可否を決めません
 */
//------------------------------------------------------------------------------
[[nodiscard]] inline std::int32_t finishInfFailure( InfFailureDiagnostic	  *diagnostic,
												   const InfDiagnosticPath path,
												   const std::int32_t	   error) noexcept
{
	// 成功に失敗leafを残さず、異pairの成功/失敗を混ぜません
	if( diagnostic) {
		// 成功時は元失敗leafを残さず、当該条件だけを処理します
		if( error == 0) {
			*diagnostic = {} ;
		} else {
			diagnostic->path  = path ;
			diagnostic->error = error ;
		}
	}

	return error ;
}

//------------------------------------------------------------------------------
// PnP rank監査値型定義
//------------------------------------------------------------------------------

/**
 * @brief Device側で一致したPnP identifierの種類を表す
 */
enum class PnpIdentifierKind {
	/// 有効な完全一致がない
	NONE,
	/// DeviceのHardware ID一覧へ完全一致した
	HARDWARE_ID,
	/// DeviceのCompatible ID一覧へ完全一致した
	COMPATIBLE_ID,
} ;

/**
 * @brief Device側PnP identifier一覧内の一致位置をID文字列なしで表す
 */
struct PnpIdentifierPosition {
	/// 一致したID一覧の種類
	PnpIdentifierKind kind{PnpIdentifierKind::NONE} ;
	/// Hardware IDまたはCompatible ID一覧内の0-based位置
	std::uint32_t	  index{} ;
} ;

/** @brief Nativeの現在driver確認結果とrank比較方式を区別します */
enum class OfficialDriverRankCurrentState {
	/// 現在driverのMatching IDとfull rankによる非退行比較を必須にします
	KNOWN_DRIVER,
	/// Present/Code28/属性欠損/installed-node不在をnativeで確認した初回導入です
	NO_DRIVER,
} ;

/** @brief 元deviceのClass観測をINFのClassと独立に表します */
enum class OfficialDriverRankDeviceClassState {
	/// 非空の既知Classを観測し、候補のClass名との一致を要求します
	KNOWN_CLASS,
	/// NativeがClass propertyの正式な不存在を返しました
	NOT_PRESENT,
	/// Nativeが正式Unknown名とUnknown GUIDを返しました
	UNKNOWN_CLASS,
} ;

/**
 * @brief PnP具体性およびrank監査の判断結果を表す
 */
enum class OfficialDriverRankDecision {
	/// 監査をまだ実行していない
	NOT_EVALUATED,
	/// ID具体性とWindows rankが現在driver以上である
	APPLICABLE,
	/// 入力上限、ID構文または一意性が成立しない
	INVALID_EVIDENCE,
	/// DeviceとINFのsetup classが一致しない
	CLASS_MISMATCH,
	/// Candidate INFのPnP IDがdeviceへ一致しない
	CANDIDATE_NOT_MATCHED,
	/// 現在MatchingDeviceIdをdevice一覧へ解決できない
	CURRENT_MATCH_UNAVAILABLE,
	/// 現在driverのWindows rankを取得できない
	CURRENT_RANK_UNAVAILABLE,
	/// CandidateのWindows rankを取得できない
	CANDIDATE_RANK_UNAVAILABLE,
	/// Candidateがdevice側の弱いIDへ一致する
	IDENTIFIER_POSITION_REGRESSION,
	/// Windows identifier scoreが現在driverより悪い
	IDENTIFIER_SCORE_REGRESSION,
	/// Signature等を含むfull rankが現在driverより悪い
	OVERALL_RANK_REGRESSION,
} ;

/**
 * @brief Worker内で取得したPnP IDとWindows rankをpure判定へ渡す
 *
 * @note 全文字列viewは本呼出し中だけ有効であり、外部送信または結果への複写を行わない
 */
struct OfficialDriverRankEvidence {
	/// 現在deviceのsetup class名
	std::wstring_view				   deviceClass ;
	/// G11-Cで検証したcandidate INF Class名
	std::wstring_view				   candidateClass ;
	/// Device側の順序付きHardware ID群
	std::span<const std::wstring>	   deviceHardwareIds ;
	/// 順序付きCompatible ID群
	std::span<const std::wstring>	   deviceCompatibleIds ;
	/// Candidate INFの検証済みPnP ID群
	std::span<const std::wstring>	   candidateIds ;
	/// Windowsが現在driverに使用したPnP ID
	std::wstring_view				   currentMatchingDeviceId ;
	/// 現在driverのSetupAPI Rank
	std::optional<std::uint32_t>	   currentRank ;
	/// CandidateのSetupAPI Rank
	std::optional<std::uint32_t>	   candidateRank ;
	/// Workerのnative確認に結合する比較方式。空版からNO_DRIVERを推測しません
	OfficialDriverRankCurrentState	   currentState{OfficialDriverRankCurrentState::KNOWN_DRIVER} ;
	/// 元Classの観測方式。失敗や空文字をNOT_PRESENTへ変換しません
	OfficialDriverRankDeviceClassState deviceClassState{
		OfficialDriverRankDeviceClassState::KNOWN_CLASS} ;
	/// 同じ検査済みINFのWindows ClassGUID。未確定初回だけで必須にします
	std::wstring_view candidateInfClassGuid ;
	/// 単一INFのWindows互換一覧が返したClassGUID。INFと完全一致を要求します
	std::wstring_view candidateNativeClassGuid ;
} ;

/**
 * @brief PnP identifierとrank非退行の監査結果をID文字列なしで表す
 */
struct OfficialDriverRankAudit {
	/// 判断
	OfficialDriverRankDecision	   decision{OfficialDriverRankDecision::NOT_EVALUATED} ;
	/// 現在MatchingDeviceIdのdevice側位置
	PnpIdentifierPosition		   currentPosition ;
	/// Candidateが一致した最良のdevice側位置
	PnpIdentifierPosition		   candidatePosition ;
	/// 現在driverのfull Windows rank
	std::uint32_t				   currentRank{} ;
	/// Candidateのfull Windows rank
	std::uint32_t				   candidateRank{} ;
	/// 現在rankの下位16-bit
	std::uint16_t				   currentIdentifierScore{} ;
	/// Candidate rankの下位16-bit
	std::uint16_t				   candidateIdentifierScore{} ;
	/// 現在rankを使った比較か、native未導入状態の候補rank確認かを保持します
	OfficialDriverRankCurrentState currentState{OfficialDriverRankCurrentState::KNOWN_DRIVER} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief PnP identifierの具体性とSetupAPI rankが現在driverから退行しないか判定する。公式driverのPnP具体性とrank非退行を判定する。Policy拒
 *        否はdecisionに残し、Windows rankを独自再計算せずversionまたは日付を判断へ使用しない
 * @param[in] evidence Worker内で固定したdevice、candidateおよびrank evidence。 Worker内で固定したIDとWindows rank
 * @param[out] audit ID文字列を含まない監査結果。 ID文字列を含まない判断結果
 * @return 入力構造が有限で妥当な場合は`true`。不正入力の場合は`false`。 入力構造が妥当なら`true`、不正なら`false`
 * @note Policy上の拒否は`true`と各decisionで返し、versionまたは日付を使用しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool evaluateOfficialDriverRank( const OfficialDriverRankEvidence &evidence,
											  OfficialDriverRankAudit		   &audit) noexcept ;

} // namespace drivercrate
