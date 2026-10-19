//------------------------------------------------------------------------------
/**
 * @file candidate_selection.cpp
 * @brief Driver候補の既定選択実装。
 * @version 01.02.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  探索経路境界検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  取得元未証明package境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  詳細検証不整合と初回actionの選択を拒否。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * </pre>
 *
 * @note 候補順に依存して取得元が入れ替わらないよう、候補ごとの検証根拠を比較します。不明なProviderまたは矛盾した根拠はfail-closedで拒否します。
 */
//------------------------------------------------------------------------------

#include "core/candidate_selection.h"
#include "core/candidate_audit.h"

#include <cstdint>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Providerが指定capabilityを持つか判定する。
 *
 * 候補が主張する検証根拠をregistryの信頼境界へ照合する。
 *
 * @param[in] provider 検証するProvider定義。
 * @param[in] capability 必須とする単一capability。
 * @return 指定bitがProvider定義に含まれる場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool providerHasCapability( const ProviderDescriptor &provider,
										 const ProviderCapability  capability) noexcept
{
	const auto required = static_cast<ProviderCapabilityMask>( capability) ;	// 必須bit。
	return (provider.capabilities & required) != 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 候補別既定選択根拠を比較用順位へ変換する。
 *
 * ADR 0038の順位をenumの宣言順から独立させて固定する。
 *
 * @param[in] preference 変換する既定選択根拠。
 * @return 小さいほど優先する順位。定義外値は最大値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t preferenceRank( const CandidateDefaultPreference preference) noexcept
{
	// 列挙の宣言順に依存せず既定選択の順位を固定し、未知の根拠は最下位とする。
	switch( preference) {
		// OEM 検証根拠のある候補を既定選択順位の先頭にする。
		case CandidateDefaultPreference::OEM_VALIDATED:
			return 0U ;
		// Component reference 候補を OEM 検証候補に続けて比較する。
		case CandidateDefaultPreference::COMPONENT_REFERENCE:
			return 1U ;
		// 管理 service の適用可能候補を対応する既定順位へ置く。
		case CandidateDefaultPreference::MANAGED_APPLICABLE:
			return 2U ;
		// Component generic 候補は明示 reference の後に比較する。
		case CandidateDefaultPreference::COMPONENT_GENERIC:
			return 3U ;
		// 既定選択根拠がない候補は既知の優先根拠より後に置く。
		case CandidateDefaultPreference::NONE:
			return 4U ;
		// 未知の既定選択根拠には最下位 sentinel を返す。
		default:
			return std::numeric_limits<std::uint32_t>::max() ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 候補が初期選択対象の推奨通常更新か判定する。
 *
 * 現在版、同版再導入、旧版、OEM未検証generic候補、および区分B／Cの候補を除外する。
 *
 * @param[in] candidate 判定する候補。
 * @return 一括選択可能な推奨通常更新の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDefaultSelectionCandidate( const UpdateCandidate &candidate) noexcept
{
	const bool stableDiscovery =	// 自動選択を許可する管理serviceまたは区分Aの場合true。
		candidate.discoveryBasis == CandidateDiscoveryBasis::MANAGED_SERVICE ||
		candidate.discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
	return candidate.recommended && candidate.installable && !candidate.current &&
		   isCandidateDetailsValid( candidate) && candidate.action == DriverAction::UPDATE &&
		   stableDiscovery && candidate.defaultPreference != CandidateDefaultPreference::NONE &&
		   candidate.defaultPreference != CandidateDefaultPreference::COMPONENT_GENERIC ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_selection.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isCandidateDiscoveryBasisValid( const UpdateCandidate	 &candidate,
									const ProviderDescriptor &provider) noexcept
{
	// Providerの登録と探索根拠が一致しない候補を、取得元の比較へ進めない。
	if( candidate.providerId.empty() || candidate.providerId != provider.id ||
	   candidate.discoveryBasis == CandidateDiscoveryBasis::UNSPECIFIED ||
	   candidate.discoveryBasis != provider.discoveryBasis) {
		return false ;
	}

	// 探索経路に対応する取得元tierと能力を照合し、候補の自己申告だけで信頼しない。
	switch( candidate.discoveryBasis) {
		// 管理 service の根拠には registry の同種 tier と能力を要求する。
		case CandidateDiscoveryBasis::MANAGED_SERVICE:
			return provider.selectionTier == ProviderSelectionTier::MANAGED_SERVICE &&
				   providerHasCapability( provider, ProviderCapability::MANAGED_SERVICE) ;
		// Local 根拠には inventory の tier と能力を要求する。
		case CandidateDiscoveryBasis::LOCAL_INVENTORY:
			return provider.selectionTier == ProviderSelectionTier::LOCAL_INVENTORY &&
				   providerHasCapability( provider, ProviderCapability::LOCAL_INVENTORY) ;
		// 構造化 catalog の根拠は公式 Provider の共通条件へ進む。
		case CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG:
		// 公式 Web 根拠には OEM／component の公式 tier と network 能力を要求する。
		case CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE:
			return (provider.selectionTier == ProviderSelectionTier::OEM_OFFICIAL ||
					provider.selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL) &&
				   providerHasCapability( provider, ProviderCapability::OFFICIAL_NETWORK) ;
		// 利用者指定根拠には許可 tier と file 指定能力を要求する。
		case CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE:
			return (provider.selectionTier == ProviderSelectionTier::OEM_OFFICIAL ||
					provider.selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL ||
					provider.selectionTier == ProviderSelectionTier::USER_PROVIDED) &&
				   providerHasCapability( provider, ProviderCapability::USER_SELECTED_FILE) ;
		// 収集者確認の独立境界を公式networkやWindows管理へ読み替えません。
		case CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION:
			return provider.selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL &&
				   providerHasCapability( provider, ProviderCapability::SIGNED_INDEX_ACQUISITION) &&
				   !candidate.recommended &&
				   candidate.defaultPreference == CandidateDefaultPreference::NONE ;
		// 未指定の探索根拠は共通拒否へ進む。
		case CandidateDiscoveryBasis::UNSPECIFIED:
		// 未知の探索根拠は既定選択の前提へ受理しない。
		default:
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_selection.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool candidateDefaultPreferencePrecedes( const CandidateDefaultPreference left,
										const CandidateDefaultPreference right) noexcept
{
	const std::uint32_t leftRank	= preferenceRank( left) ;	// 左辺の固定順位。
	const std::uint32_t rightRank	= preferenceRank( right) ;	// 右辺の固定順位。
	const std::uint32_t invalidRank =							// 定義外値に割り当てるsentinel順位。
		std::numeric_limits<std::uint32_t>::max() ;
	return leftRank != invalidRank && rightRank != invalidRank && leftRank < rightRank ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_selection.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isCandidateDefaultPreferenceValid( const UpdateCandidate	&candidate,
									   const ProviderDescriptor &provider) noexcept
{
	// 探索経路そのものが不正なら、推奨度の情報で正当化させない。
	if( !isCandidateDiscoveryBasisValid( candidate, provider) ||
	   !isCandidateDetailsValid( candidate)) {
		return false ;
	}

	const bool updateCandidate =	// System変更を伴う通常更新候補の場合true。
		candidate.installable && !candidate.current && candidate.action == DriverAction::UPDATE ;
	const bool officialNetwork =	// 公式network境界をregistryが明示する場合true。
		providerHasCapability( provider, ProviderCapability::OFFICIAL_NETWORK) ;
	const bool managedService =	// WUA等の管理service境界を明示する場合true。
		providerHasCapability( provider, ProviderCapability::MANAGED_SERVICE) ;
	const bool explicitSelectionOnly =	// 区分B／Cとして自動選択を禁止する場合true。
		candidate.discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ||
		candidate.discoveryBasis == CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
	// 明示選択を要する候補を推奨扱いにせず、初期選択の対象から分離する。
	if( explicitSelectionOnly && candidate.recommended) {
		return false ;
	}

	// 推奨根拠ごとに必要な取得元と能力を照合し、根拠のない自動選択を防ぐ。
	switch( candidate.defaultPreference) {
		case CandidateDefaultPreference::NONE:
			// 推奨通常更新が根拠を欠く場合は候補順による暗黙選択を許可しない。
			return !(candidate.recommended && updateCandidate) ;
		// OEM 検証の優先根拠には推奨更新と OEM 公式 network tier を要求する。
		case CandidateDefaultPreference::OEM_VALIDATED:
			return candidate.recommended && updateCandidate && officialNetwork &&
				   provider.selectionTier == ProviderSelectionTier::OEM_OFFICIAL ;
		// Component reference の優先根拠には推奨更新と component 公式 tier を要求する。
		case CandidateDefaultPreference::COMPONENT_REFERENCE:
			return candidate.recommended && updateCandidate && officialNetwork &&
				   provider.selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL ;
		// 管理適用性の優先根拠には推奨更新と管理 service tier を要求する。
		case CandidateDefaultPreference::MANAGED_APPLICABLE:
			return candidate.recommended && updateCandidate && managedService &&
				   provider.selectionTier == ProviderSelectionTier::MANAGED_SERVICE ;
		case CandidateDefaultPreference::COMPONENT_GENERIC:
			// OEM未検証candidateは表示と明示選択だけを許可し、初期選択しない。
			return !candidate.recommended && updateCandidate && officialNetwork &&
				   provider.selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL ;
		// 未知の優先根拠を既定選択へ受理しない。
		default:
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_selection.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<std::vector<bool>> buildDefaultCandidateSelection(
	const std::span<const UpdateCandidate>	  candidates,
	const std::span<const ProviderDescriptor> providers)
{
	// 取得元の定義がない状態では候補の根拠を検証できないため、選択結果を返さない。
	if( providers.empty()) {
		return std::nullopt ;
	}

	// Spanの有効期間内だけ参照するstable ID別Provider定義。
	std::unordered_map<std::wstring, const ProviderDescriptor *> providersById ;
	providersById.reserve( providers.size()) ;
	// Registry entryの空IDと重複を選択処理前に拒否する。
	for( const ProviderDescriptor &provider : providers) {
		// 空IDや重複登録で取得元の照合先が曖昧になる構成を拒否する。
		if( provider.id.empty() || !providersById.emplace( provider.id, &provider).second) {
			return std::nullopt ;
		}
	}

	std::vector<bool> selection( candidates.size(), false) ;	// Candidate index別の初期選択状態。
	// 同じdeviceで現在選択しているcandidate index。
	std::unordered_map<std::wstring, std::size_t> selectedByDevice ;
	selectedByDevice.reserve( candidates.size()) ;
	std::unordered_set<std::wstring> candidateIdentities ;	// Candidate ID重複検出集合。
	candidateIdentities.reserve( candidates.size()) ;

	// 全candidateを検証し、推奨通常更新だけをdevice単位で一件へ絞る。
	for( std::size_t index = 0; index < candidates.size(); ++index) {
		const UpdateCandidate &candidate = candidates[index] ;				// 現在検証する候補。
		const auto provider = providersById.find( candidate.providerId) ;	// Provider照合結果。
		// IDの一意性と取得元・推奨根拠を全候補で検証し、不正な一覧から部分選択を作らない。
		if( candidate.identity.empty() || candidate.deviceIdentity.empty() ||
		   !candidateIdentities.insert( candidate.identity).second ||
		   provider == providersById.end() ||
		   !isCandidateDefaultPreferenceValid( candidate, *provider->second)) {
			return std::nullopt ;
		}

		// 明示選択が必要な候補を飛ばし、通常の推奨更新だけで初期選択を作る。
		if( !isDefaultSelectionCandidate( candidate)) {
			continue ;
		}

		const auto previous =	// 同一deviceですでに選択した候補の検索結果。
			selectedByDevice.find( candidate.deviceIdentity) ;
		// このdeviceで最初の推奨候補を仮選択し、後続候補は同じ一枠と比較する。
		if( previous == selectedByDevice.end()) {
			selectedByDevice.emplace( candidate.deviceIdentity, index) ;
			selection[index] = true ;
			continue ;
		}

		const std::size_t	   previousIndex	 = previous->second ;			// 現在選択中の候補index。
		const UpdateCandidate &previousCandidate = candidates[previousIndex] ;	// 現在選択候補。
		// 同じdeviceでは根拠が明確に優先する候補へ一枠を移し、同時に二候補を選択しない。
		if( candidateDefaultPreferencePrecedes( candidate.defaultPreference,
											  previousCandidate.defaultPreference)) {
			selection[previousIndex] = false ;
			selection[index]		 = true ;
			previous->second		 = index ;
		}
	}

	return selection ;
}

} // namespace drivercrate
