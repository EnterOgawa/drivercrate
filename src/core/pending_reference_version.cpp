//------------------------------------------------------------------------------
/**
 * @file pending_reference_version.cpp
 * @brief 登録driverに対する取得前版の純粋比較を実装します。
 * @version 01.00.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  同じ現在観測だけから取得前の比較分類を生成。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note version-onlyの適用性判定やUNKNOWNの成功換算を行いません。
 * @see docs/adr/0428-newer-index-reference-confirmation.md
 */
//------------------------------------------------------------------------------
#include "core/pending_reference_version.h"
#include "core/candidate_audit.h"
#include "core/device_observation.h"
#include "core/provider_registry.h"

namespace drivercrate {
//------------------------------------------------------------------------------
/**
 * @brief 明示4個の16bit十進数だけをWindows版比較へ変換します。
 * @param[in] version 元の版文字列。欠損/省略/任意suffixを補完しません。
 * @return 四要素のpacked値。不正/不足はnullopt。
 */
//------------------------------------------------------------------------------
std::optional<std::uint64_t> parseFourPartDriverVersion( std::wstring_view version) noexcept
{
	std::uint64_t packed{} ;	// 4個の16bit整数を順に保持します。
	// 全四要素だけを読み、部分版やsuffixを補完しません。
	for( unsigned component{}; component < 4U; ++component) {
		const auto	  dot  = version.find( L'.') ;		// 元要素の終端です。
		const auto	  part = version.substr( 0U, dot) ;	// 元表記を正規化しません。
		std::uint64_t number{} ;						// 現要素の有限値です。
		// 空要素を0と推定しません。
		if( part.empty()) {
			return std::nullopt ;
		}

		// 全文字の十進数/16bit上限を確認します。
		for( const auto character : part) {
			// 不正文字やoverflowを分類根拠にしません。
			if( character < L'0' || character > L'9' ||
			   number > (65535U - (character - L'0')) / 10U) {
				return std::nullopt ;
			}

			number = number * 10U + static_cast<std::uint64_t>( character - L'0') ;
		}

		packed = (packed << 16U) | number ;
		// 最終要素より後のsuffixを受理しません。
		if( component == 3U) {
			return dot == std::wstring_view::npos ? std::optional{packed} : std::nullopt ;
		}

		// 三要素以下の版を補完しません。
		if( dot == std::wstring_view::npos) {
			return std::nullopt ;
		}

		version.remove_prefix( dot + 1U) ;
	}

	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanの一意な登録済み現在観測との取得前比較を行います。
 * @param[in] candidate 記述済みの署名索引参照。producerが原metadataだけを投影します。
 * @param[in] candidates 同じsnapshotの現在行と候補。
 * @param[in] scanSessionId 現在有効な同scan。
 * @return 比較条件が全て成立した場合だけNEWER/SAME/OLDER。導入actionは変更しません。
 */
//------------------------------------------------------------------------------
PendingReferenceVersion classifyPendingReferenceVersion(
	const UpdateCandidate &candidate, const std::span<const UpdateCandidate> candidates,
	const ScanSessionId scanSessionId) noexcept
{
	// 実候補/他経路/未結合を取得前の確認候補へ変換しません。
	if( scanSessionId == 0U || candidate.current || candidate.installable || candidate.recommended ||
	   candidate.action != DriverAction::NONE || candidate.identity.empty() ||
	   candidate.deviceIdentity.empty() || candidate.providerId != SIGNED_INDEX_PROVIDER_ID ||
	   candidate.discoveryBasis != CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ||
	   candidate.preparationTargetIdentity.empty() || candidate.deviceClassGuid.empty() ||
	   candidate.audit.sourceOrigin != CandidateAuditGateState::PASSED ||
	   candidate.audit.inspectionDownload != CandidateAuditGateState::PENDING ||
	   candidate.audit.contentIntegrity != CandidateAuditGateState::PENDING ||
	   candidate.audit.systemApplicability != CandidateAuditGateState::PENDING ||
	   candidate.allContentCached || !isCandidateDetailsValid( candidate, scanSessionId)) {
		return PendingReferenceVersion::UNKNOWN ;
	}

	const UpdateCandidate *current{} ;	// 同deviceの一意な現在行だけを借用します。
	// 他deviceの版や名前を比較根拠にしません。
	for( const auto &value : candidates) {
		// 現在代表行以外を登録状態の証拠にしません。
		if( !value.current || value.deviceIdentity != candidate.deviceIdentity) {
			continue ;
		}

		// 重複現在行を都合よく一つへ丸めません。
		if( current) {
			return PendingReferenceVersion::UNKNOWN ;
		}

		current = &value ;
	}

	// 初回/未知/古い観測を登録済み通常更新へ分類しません。
	if( !current || current->deviceClassGuid != candidate.deviceClassGuid ||
	   !isCandidateDetailsValid( *current, scanSessionId) || !current->deviceObservation ||
	   !isDeviceObservationBound( *current->deviceObservation, scanSessionId,
								 candidate.deviceIdentity) ||
	   current->deviceObservation->driverPresence != DeviceDriverPresence::REGISTERED ||
	   current->deviceObservation->version.state != DevicePropertyReadState::VALUE) {
		return PendingReferenceVersion::UNKNOWN ;
	}

	const auto oldVersion =
		// 成立した現在版だけです。
		parseFourPartDriverVersion( current->version) ;
	const auto newVersion = parseFourPartDriverVersion( candidate.version) ;	// 元収集者の版だけです。
	// 空/不足/任意配布文字列は不明のまま保持します。
	if( !oldVersion || !newVersion) {
		return PendingReferenceVersion::UNKNOWN ;
	}

	return *newVersion > *oldVersion	? PendingReferenceVersion::NEWER
		   : *newVersion == *oldVersion ? PendingReferenceVersion::SAME
										: PendingReferenceVersion::OLDER ;
}
}
