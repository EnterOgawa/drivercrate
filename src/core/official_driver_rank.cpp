//------------------------------------------------------------------------------
/**
 * @file official_driver_rank.cpp
 * @brief 公式driverのPnP具体性およびrank非退行判定実装。
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
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  未導入modeで候補IDとWindows rankを検証し架空現在rankを作らない。
 * Ver.01.02.00 Shunji Ogawa  2026/10/13  元未確定Classを別軸へ保存しINF/native GUID一致を要求。
 * </pre>
 *
 * @note Windowsが返したrank値を再計算せず、IDの完全一致と非退行だけをallocationなしで判定します。
 */
//------------------------------------------------------------------------------

#include "core/official_driver_rank.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_CLASS_CHARACTERS	  = 256U ;	// Setup class名の文字数上限。
constexpr std::size_t	MAXIMUM_IDENTIFIER_CHARACTERS = 256U ;	// 一PnP IDの文字数上限。
constexpr std::size_t	MAXIMUM_DEVICE_HARDWARE_IDS	  = 64U ;	// 一deviceのHardware ID数上限。
constexpr std::size_t	MAXIMUM_DEVICE_COMPATIBLE_IDS = 64U ;	// 一deviceのCompatible ID数上限。
constexpr std::size_t	MAXIMUM_CANDIDATE_IDS = 4096U ;			// 一candidate packageのPnP ID数上限。
constexpr std::uint32_t IDENTIFIER_SCORE_MASK = 0x0000FFFFU ;	// Rank内identifier score領域。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII英字を大文字へ変換する。
 *
 * Localeに依存せずWindows identifierのcase差だけを除外する。
 *
 * @param[in] character PnP IDまたはsetup classを構成する文字。
 * @return ASCII小文字は大文字、それ以外は入力値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] wchar_t	asciiUpper( const wchar_t character) noexcept
{
	return character >= L'a' && character <= L'z' ? static_cast<wchar_t>( character - L'a' + L'A')
												  : character ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのASCII identifierがcaseを除いて完全一致するか調べる。
 *
 * Prefixや部分一致を許可せず、長さを含めて照合する。
 *
 * @param[in] left 比較する一つ目の文字列。
 * @param[in] right 比較する二つ目の文字列。
 * @return 全文字がcaseを除いて一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool stringsEqual( const std::wstring_view left,
								const std::wstring_view right) noexcept
{
	return left.size() == right.size() &&
		   std::ranges::equal( left, right, []( const wchar_t first, const wchar_t second) noexcept {
			   return asciiUpper( first) == asciiUpper( second) ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief PnP identifierの構文を検証する。
 *
 * 空値、埋込みnull、control文字、Unicode別名を拒否する。
 *
 * @param[in] value DeviceまたはINFから取得したPnP ID。
 * @return 有限長の表示可能ASCIIでbus separatorを持つ場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidIdentifier( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= MAXIMUM_IDENTIFIER_CHARACTERS &&
		   value.find( L'\\') != std::wstring_view::npos &&
		   std::ranges::all_of( value, []( const wchar_t character) noexcept {
			   return character >= 0x21 && character <= 0x7e ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief PnP ID一覧が有限かつ重複なしであるか検証する。
 *
 * 重複でindexの意味が曖昧になるevidenceをfail-closedにする。
 *
 * @param[in] values 順序を維持するPnP ID群。
 * @param[in] maximumCount 受理するID数上限。
 * @return 空または全IDの構文とcase非依存一意性が成立すれば`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validateIdentifiers( const std::span<const std::wstring> values,
									   const std::size_t				   maximumCount) noexcept
{
	// 照合に使用するID件数を制限し、過大入力による比較量の増加を防ぐ。
	if( values.size() > maximumCount) {
		return false ;
	}

	// indexは検証対象位置を表し、各IDを先行要素だけと比較して一意性を確認する。
	for( std::size_t index = 0; index < values.size(); ++index) {
		// 不正なIDや同じIDの重複を含む一覧では、順序に基づく具体性を評価しない。
		if( !isValidIdentifier( values[index]) ||
		   std::ranges::any_of( values.first( index),
							   [&values, index]( const std::wstring &previous) noexcept {
								   return stringsEqual( previous, values[index]) ;
							   })) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのdevice ID一覧をまたぐ重複がないか検証する。
 *
 * 同じIDに二種類の具体性を割り当てる曖昧な入力を拒否する。
 *
 * @param[in] left Hardware ID等の一方の一覧。
 * @param[in] right Compatible ID等の他方の一覧。
 * @return Caseを除く同一IDが一覧間にない場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool identifiersDisjoint( const std::span<const std::wstring> left,
									   const std::span<const std::wstring> right) noexcept
{
	return std::ranges::none_of( left, [&right]( const std::wstring &value) noexcept {
		return std::ranges::any_of( right, [&value]( const std::wstring &other) noexcept {
			return stringsEqual( value, other) ;
		}) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのIDをdevice側の順序付き一覧へ解決する。
 *
 * Hardware IDを常にCompatible IDより先に検索する。
 *
 * @param[in] identifier 完全一致で検索するPnP ID。
 * @param[in] hardwareIds 具体性順のHardware ID群。
 * @param[in] compatibleIds 具体性順のCompatible ID群。
 * @return 最初に完全一致した一覧種別とindex。該当なしはNone。
 */
//------------------------------------------------------------------------------
[[nodiscard]] PnpIdentifierPosition findIdentifierPosition(
	const std::wstring_view identifier, const std::span<const std::wstring> hardwareIds,
	const std::span<const std::wstring> compatibleIds) noexcept
{
	// indexはHardware ID位置を表し、具体性順を変えずに検索する。
	for( std::size_t index = 0; index < hardwareIds.size(); ++index) {
		// より具体的なHardware IDの最初の一致を優先し、Compatible IDへ順位を下げない。
		if( stringsEqual( identifier, hardwareIds[index])) {
			return {PnpIdentifierKind::HARDWARE_ID, static_cast<std::uint32_t>( index)} ;
		}
	}

	// indexはCompatible ID位置を表し、Hardware IDにない場合だけ検索する。
	for( std::size_t index = 0; index < compatibleIds.size(); ++index) {
		// Hardware IDに一致しなかった場合だけ、最初に一致したCompatible IDの位置を採用する。
		if( stringsEqual( identifier, compatibleIds[index])) {
			return {PnpIdentifierKind::COMPATIBLE_ID, static_cast<std::uint32_t>( index)} ;
		}
	}

	return {} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Candidateが一致する最も具体的なdevice ID位置を求める。
 *
 * Candidate IDの記載順ではなくdevice側の具体性を優先する。
 *
 * @param[in] candidateIds INF Models sectionの全PnP ID。
 * @param[in] hardwareIds Device側の具体性順Hardware ID群。
 * @param[in] compatibleIds Device側の具体性順Compatible ID群。
 * @return Candidateへ一致した最良のdevice側位置。該当なしはNone。
 */
//------------------------------------------------------------------------------
[[nodiscard]] PnpIdentifierPosition findCandidatePosition(
	const std::span<const std::wstring> candidateIds,
	const std::span<const std::wstring> hardwareIds,
	const std::span<const std::wstring> compatibleIds) noexcept
{
	// indexはdevice側Hardware ID位置を表し、INF内の完全一致だけを受理する。
	for( std::size_t index = 0; index < hardwareIds.size(); ++index) {
		// 候補側のいずれかのIDが一致した最も具体的なHardware ID位置を採用する。
		if( std::ranges::any_of( candidateIds,
							   [&hardwareIds, index]( const std::wstring &candidate) noexcept {
								   return stringsEqual( candidate, hardwareIds[index]) ;
							   })) {
			return {PnpIdentifierKind::HARDWARE_ID, static_cast<std::uint32_t>( index)} ;
		}
	}

	// indexはdevice側Compatible ID位置を表し、Hardware ID一致がない場合だけ調べる。
	for( std::size_t index = 0; index < compatibleIds.size(); ++index) {
		// Hardware IDで解決できない候補に限り、最初のCompatible ID一致を採用する。
		if( std::ranges::any_of( candidateIds,
							   [&compatibleIds, index]( const std::wstring &candidate) noexcept {
								   return stringsEqual( candidate, compatibleIds[index]) ;
							   })) {
			return {PnpIdentifierKind::COMPATIBLE_ID, static_cast<std::uint32_t>( index)} ;
		}
	}

	return {} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Candidateのdevice側ID位置が現在driverより弱いか判定する。
 *
 * 全Hardware IDをCompatible IDより具体的として比較する。
 *
 * @param[in] current 現在MatchingDeviceIdの位置。
 * @param[in] candidate Candidateが一致した最良位置。
 * @return Candidateの種類またはindexが弱くなる場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool positionRegressed( const PnpIdentifierPosition &current,
									 const PnpIdentifierPosition &candidate) noexcept
{
	// ID種別が変わる場合は、Hardware IDからCompatible IDへの切替だけを具体性の後退とする。
	if( current.kind != candidate.kind) {
		return current.kind == PnpIdentifierKind::HARDWARE_ID &&
			   candidate.kind == PnpIdentifierKind::COMPATIBLE_ID ;
	}

	return candidate.index > current.index ;
}

/** @brief INF/native ClassGUIDの有限構文と既知値を確認します。
 * @param[in] value 呼出し中だけ借用するGUID表記です。外へ保持しません。
 * @return 正式GUID構文でnull/Unknown以外の場合trueです。
 * @note allocation・I/Oを行わず、実INF/Windows由来の検証は呼出側が担当します。
 */
[[nodiscard]] bool validKnownClassGuid( const std::wstring_view value) noexcept
{
	// 空・途中NUL・不正な長さを既知Classへ補完しません。
	if( value.size() != 38U || value.front() != L'{' || value.back() != L'}') {
		return false ;
	}

	bool nonzero{} ;	// null GUIDを通常Classとして受理しません。
	// 固定38文字の全hexと四区切りを一度だけ確認します。
	for( std::size_t index = 1U; index < 37U; ++index) {
		const wchar_t character = value[index] ;	// 借用GUIDの一文字です。
		const bool	  separator =
			// 固定区切りです。
			index == 9U || index == 14U || index == 19U || index == 24U ;
		// 不正文字をcase補正や切詰めで受理しません。
		if( separator ? character != L'-'
					 : !((character >= L'0' && character <= L'9') ||
						 (character >= L'A' && character <= L'F') ||
						 (character >= L'a' && character <= L'f'))) {
			return false ;
		}

		nonzero = nonzero || (!separator && character != L'0') ;
	}

	return nonzero && !stringsEqual( value, L"{4D36E97E-E325-11CE-BFC1-08002BE10318}") ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/official_driver_rank.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool evaluateOfficialDriverRank( const OfficialDriverRankEvidence &evidence,
								OfficialDriverRankAudit			 &audit) noexcept
{
	audit = {} ;
	const bool initialInstall =
		evidence.currentState ==
		OfficialDriverRankCurrentState::NO_DRIVER ;	// Native確認済み未導入方式。
	const bool knownClass =
		evidence.deviceClassState ==
		OfficialDriverRankDeviceClassState::KNOWN_CLASS ;	// 既知観測だけに名前一致を要求します。
	const bool missingClass =
		evidence.deviceClassState == OfficialDriverRankDeviceClassState::NOT_PRESENT &&
		// 正式不存在です。
		evidence.deviceClass.empty() ;
	const bool unknownClass =
		evidence.deviceClassState == OfficialDriverRankDeviceClassState::UNKNOWN_CLASS &&
		// 正式Unknownです。
		stringsEqual( evidence.deviceClass, L"Unknown") ;
	const bool nativeClassBound =	// 未確定をINF/native両GUIDの実証拠へ結合します。
		validKnownClassGuid( evidence.candidateInfClassGuid) &&
		validKnownClassGuid( evidence.candidateNativeClassGuid) &&
		stringsEqual( evidence.candidateInfClassGuid, evidence.candidateNativeClassGuid) ;
	const bool validClasses =	// 空Classを通常更新や成功自己申告へ転用しません。
		(knownClass ? !evidence.deviceClass.empty()
					: initialInstall && (missingClass || unknownClass) && nativeClassBound) &&
		evidence.deviceClass.size() <= MAXIMUM_CLASS_CHARACTERS &&
		evidence.deviceClass.find( L'\0') == std::wstring_view::npos &&
		!evidence.candidateClass.empty() &&
		evidence.candidateClass.size() <= MAXIMUM_CLASS_CHARACTERS &&
		evidence.candidateClass.find( L'\0') == std::wstring_view::npos ;
	const bool validIdentifiers =	// 三つのID一覧の構文、上限、一意性。
		(!evidence.deviceHardwareIds.empty() || !evidence.deviceCompatibleIds.empty()) &&
		!evidence.candidateIds.empty() &&
		validateIdentifiers( evidence.deviceHardwareIds, MAXIMUM_DEVICE_HARDWARE_IDS) &&
		validateIdentifiers( evidence.deviceCompatibleIds, MAXIMUM_DEVICE_COMPATIBLE_IDS) &&
		validateIdentifiers( evidence.candidateIds, MAXIMUM_CANDIDATE_IDS) &&
		identifiersDisjoint( evidence.deviceHardwareIds, evidence.deviceCompatibleIds) &&
		(initialInstall ? evidence.currentMatchingDeviceId.empty() && !evidence.currentRank
						: isValidIdentifier( evidence.currentMatchingDeviceId)) ;
	// classやIDの根拠が不正なら比較を成立させず、監査不能の結果を残す。
	if( !validClasses || !validIdentifiers ||
	   (evidence.currentState != OfficialDriverRankCurrentState::KNOWN_DRIVER && !initialInstall)) {
		audit.decision = OfficialDriverRankDecision::INVALID_EVIDENCE ;
		return false ;
	}

	// 異なるdriver classの候補はrank比較の良否に関係なく対象外とする。
	if( knownClass && !stringsEqual( evidence.deviceClass, evidence.candidateClass)) {
		audit.decision = OfficialDriverRankDecision::CLASS_MISMATCH ;
		return true ;
	}

	audit.currentState = evidence.currentState ;
	// 初回でも候補のID具体性とWindows full rankを要求し、未知現在状態を通しません。
	if( initialInstall) {
		audit.candidatePosition = findCandidatePosition(
			evidence.candidateIds, evidence.deviceHardwareIds, evidence.deviceCompatibleIds) ;
		// Candidate IDが一致しない初回候補を導入へ進めません。
		if( audit.candidatePosition.kind == PnpIdentifierKind::NONE) {
			audit.decision = OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED ;
			return true ;
		}

		// 現在rankは存在しませんが、候補rankの欠損は引き続き拒否します。
		if( !evidence.candidateRank) {
			audit.decision = OfficialDriverRankDecision::CANDIDATE_RANK_UNAVAILABLE ;
			return true ;
		}

		audit.candidateRank = *evidence.candidateRank ;
		audit.candidateIdentifierScore =
			static_cast<std::uint16_t>( audit.candidateRank & IDENTIFIER_SCORE_MASK) ;
		audit.decision = OfficialDriverRankDecision::APPLICABLE ;
		return true ;
	}

	audit.currentPosition = findIdentifierPosition(
		evidence.currentMatchingDeviceId, evidence.deviceHardwareIds, evidence.deviceCompatibleIds) ;
	// 現在driverの一致位置が分からない場合、候補が非退行とは推測しない。
	if( audit.currentPosition.kind == PnpIdentifierKind::NONE) {
		audit.decision = OfficialDriverRankDecision::CURRENT_MATCH_UNAVAILABLE ;
		return true ;
	}

	audit.candidatePosition = findCandidatePosition(
		evidence.candidateIds, evidence.deviceHardwareIds, evidence.deviceCompatibleIds) ;
	// 端末のIDに一致しない候補は、versionが新しくても適用候補として認めない。
	if( audit.candidatePosition.kind == PnpIdentifierKind::NONE) {
		audit.decision = OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED ;
		return true ;
	}

	// 現在driverのWindows rankが取得できない場合は非退行比較を成立させない。
	if( !evidence.currentRank.has_value()) {
		audit.decision = OfficialDriverRankDecision::CURRENT_RANK_UNAVAILABLE ;
		return true ;
	}

	// 候補のWindows rankが不明な場合は、ID一致だけで導入を許可しない。
	if( !evidence.candidateRank.has_value()) {
		audit.decision = OfficialDriverRankDecision::CANDIDATE_RANK_UNAVAILABLE ;
		return true ;
	}

	audit.currentRank	= evidence.currentRank.value() ;
	audit.candidateRank = evidence.candidateRank.value() ;
	audit.currentIdentifierScore =
		static_cast<std::uint16_t>( audit.currentRank & IDENTIFIER_SCORE_MASK) ;
	audit.candidateIdentifierScore =
		static_cast<std::uint16_t>( audit.candidateRank & IDENTIFIER_SCORE_MASK) ;
	// 候補のID一致が現在driverより弱い場合は、総合rankが良くても後退として扱う。
	if( positionRegressed( audit.currentPosition, audit.candidatePosition)) {
		audit.decision = OfficialDriverRankDecision::IDENTIFIER_POSITION_REGRESSION ;
		return true ;
	}

	// ID scoreの悪化を独立して検出し、他のrank成分で覆い隠さない。
	if( audit.candidateIdentifierScore > audit.currentIdentifierScore) {
		audit.decision = OfficialDriverRankDecision::IDENTIFIER_SCORE_REGRESSION ;
		return true ;
	}

	// Windowsの総合rankが悪化する候補は、versionの新しさに関係なく拒否する。
	if( audit.candidateRank > audit.currentRank) {
		audit.decision = OfficialDriverRankDecision::OVERALL_RANK_REGRESSION ;
		return true ;
	}

	audit.decision = OfficialDriverRankDecision::APPLICABLE ;
	return true ;
}

} // namespace drivercrate
