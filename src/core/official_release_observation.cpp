//------------------------------------------------------------------------------
/**
 * @file official_release_observation.cpp
 * @brief 公式release端末内観測比較。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Local probe失効分類追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Provider観測のatomic統合を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 保存前の上限とidentity形式を検証し、環境・policy・release差分を決定的に分類します。Network、永続化、driver導入は行いません。
 */
//------------------------------------------------------------------------------

#include "core/official_release_observation.h"

#include <cstddef>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t SHA256_CHARACTERS				 = 64U ;	// 小文字SHA-256の文字数。
constexpr std::size_t MAXIMUM_IDENTITY_CHARACTERS	 = 128U ;	// Stable ID一項目の上限。
constexpr std::size_t MAXIMUM_RELEASE_KEY_CHARACTERS = 256U ;	// Release keyの上限。
constexpr std::size_t MAXIMUM_VERSION_CHARACTERS	 = 128U ;	// 表示版の上限。
constexpr std::size_t MAXIMUM_BINDING_COUNT			 = 4'096U ;	// 一回のlocal probe上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 小文字SHA-256表記を検証する。
 *
 * Fingerprint表記を一意にし、大小文字差による誤失効を防ぐ。
 *
 * @param[in] value 検証するhash文字列。
 * @return 64桁小文字hexの場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool	  isLowerSha256( const std::wstring_view value) noexcept
{
	// SHA-256の固定長に合わない表記を、内容識別の根拠として受理しない。
	if( value.size() != SHA256_CHARACTERS) {
		return false ;
	}

	// 全文字が小文字hexであることを有限長で確認する。
	for( const wchar_t character : value) {
		const bool decimal		= character >= L'0' && character <= L'9' ;	// 10進数範囲。
		const bool lowercaseHex = character >= L'a' && character <= L'f' ;	// 16進英字範囲。
		// 数字と小文字16進以外を拒否し、hash表記を暗黙に補正して比較しない。
		if( !decimal && !lowercaseHex) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Stable IDを検証する。
 *
 * 任意path、URL、制御文字を保存keyへ混入させない。
 *
 * @param[in] value 組み込み定義が与えるID。
 * @return 有限長ASCII stable IDの場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isStableIdentifier( const std::wstring_view value) noexcept
{
	// 空IDや過大な識別子を保存対象へ持ち込ませず、照合量を有限にする。
	if( value.empty() || value.size() > MAXIMUM_IDENTITY_CHARACTERS) {
		return false ;
	}

	// 組み込みstable IDに許可したASCII文字だけを確認する。
	for( const wchar_t character : value) {
		const bool lowercase = character >= L'a' && character <= L'z' ;	// 小文字英字範囲。
		const bool uppercase = character >= L'A' && character <= L'Z' ;	// 大文字英字範囲。
		const bool decimal	 = character >= L'0' && character <= L'9' ;	// 数字範囲。
		const bool separator = character == L'-' || character == L'_' || character == L'.' ||
							   // Stable ID用区切り文字。
							   character == L':' ;
		// URLや表示文をIDへ流用させないよう、許可したASCII文字と区切りだけを受理する。
		if( !lowercase && !uppercase && !decimal && !separator) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Release表示文字列を検証する。
 *
 * UI表示値の改行やNULを永続形式へ持ち込まない。
 *
 * @param[in] value 公式metadata由来の文字列。
 * @param[in] maximumCharacters 許可する最大文字数。
 * @return 空でなく制御文字を含まない有限文字列の場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isBoundedReleaseText( const std::wstring_view value,
										const std::size_t		maximumCharacters) noexcept
{
	// 空欄や表示上限を超えるmetadataを、切詰めて有効な観測へ変換しない。
	if( value.empty() || value.size() > maximumCharacters) {
		return false ;
	}

	// 永続形式のfield境界を壊す制御文字を拒否する。
	for( const wchar_t character : value) {
		// 制御文字を表示metadataへ混ぜず、利用者が読む内容の改変を防ぐ。
		if( character < L' ' || character == L'\x7f') {
			return false ;
		}
	}

	return value.front() != L' ' && value.back() != L' ' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未確認理由enumを検証する。
 *
 * Cast等で混入した未知値を保存せずfail-closedにする。
 *
 * @param[in] reason 永続化前の未確認理由。
 * @return 定義済みenumの場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isPendingReasonValid( const ReleaseObservationPendingReason reason) noexcept
{
	// 定義済みの未確認理由だけを保存し、不明な状態を確認済みへ解釈しない。
	switch( reason) {
		// 追加確認不要は既知の保留理由分類として共通受理へ進む。
		case ReleaseObservationPendingReason::NONE:
		// Endpoint 変更は既知の未確認理由として共通受理へ進む。
		case ReleaseObservationPendingReason::ENDPOINT_CHANGED:
		// 取得元での操作要求は既知の未確認理由として共通受理へ進む。
		case ReleaseObservationPendingReason::SOURCE_INTERACTION_REQUIRED:
		// 内容再検証の必要性は既知の未確認理由として共通受理へ進む。
		case ReleaseObservationPendingReason::CONTENT_REVALIDATION_NEEDED:
		// Metadata 拒否を含む既知の未確認理由を形式上有効と認める。
		case ReleaseObservationPendingReason::METADATA_REJECTED:
			return true ;
		// 未知の保留理由を保存可能な観測値として受理しない。
		default:
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 端末内公式source bindingを検証する。
 *
 * 生PnP ID、URL、pathをstable ID欄へ混入させない。
 *
 * @param[in] binding Local probeが生成したbinding。
 * @return Fingerprintと全stable IDが保存契約を満たす場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLocalBindingValid( const LocalOfficialSourceBinding &binding) noexcept
{
	return isLowerSha256( binding.deviceBindingFingerprint) &&
		   isStableIdentifier( binding.providerId) && isStableIdentifier( binding.sourceId) &&
		   isStableIdentifier( binding.familyId) && isStableIdentifier( binding.productKey) &&
		   isStableIdentifier( binding.branch) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 端末内公式release環境を検証する。
 *
 * 未生成fingerprintやrevision 0を現在条件として許可しない。
 *
 * @param[in] environment Local probeと組み込みrevisionの条件。
 * @return 両fingerprintとrevisionが有効な場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLocalEnvironmentValid(
	const LocalOfficialObservationEnvironment &environment) noexcept
{
	return isLowerSha256( environment.operatingSystemFingerprint) &&
		   isLowerSha256( environment.deviceConfigurationFingerprint) &&
		   environment.policyRevision != 0U && environment.parserRevision != 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの端末内公式source bindingを比較する。
 *
 * 表示名、URL、版を推測してbindingを統合しない。
 *
 * @param[in] left 比較する保存済みbinding。
 * @param[in] right 比較する現在binding。
 * @return Fingerprintと全stable IDが完全一致する場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool localBindingsEqual( const LocalOfficialSourceBinding &left,
									  const LocalOfficialSourceBinding &right) noexcept
{
	return left.deviceBindingFingerprint == right.deviceBindingFingerprint &&
		   left.providerId == right.providerId && left.sourceId == right.sourceId &&
		   left.familyId == right.familyId && left.productKey == right.productKey &&
		   left.branch == right.branch ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/official_release_observation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isLocalOfficialReleaseObservationValid(
	const LocalOfficialReleaseObservation &observation) noexcept
{
	const LocalOfficialSourceBinding		  &binding = observation.binding ;	// 取得元とlocal対応。
	const LocalOfficialObservationEnvironment &environment =
		observation.environment ;	// 観測を再利用できる環境条件。
	// 対応先・環境・観測時刻・未確認理由が不正な記録は、比較の正本として保存しない。
	if( !isLocalBindingValid( binding) || !isLocalEnvironmentValid( environment) ||
	   observation.observedFileTime == 0U || !isPendingReasonValid( observation.pendingReason)) {
		return false ;
	}

	const bool hasReleaseKey	 = !observation.releaseKey.empty() ;		// 安定release IDの有無。
	const bool hasPackageVersion = !observation.packageVersion.empty() ;	// 表示版の有無。
	// releaseを区別する明示keyか版を必須とし、不完全または過大な表示値を拒否する。
	if( (!hasReleaseKey && !hasPackageVersion) ||
	   (hasReleaseKey &&
		!isBoundedReleaseText( observation.releaseKey, MAXIMUM_RELEASE_KEY_CHARACTERS)) ||
	   (hasPackageVersion &&
		!isBoundedReleaseText( observation.packageVersion, MAXIMUM_VERSION_CHARACTERS))) {
		return false ;
	}

	return observation.publishedSha256.empty() || isLowerSha256( observation.publishedSha256) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_release_observation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ReleaseObservationDifference compareLocalOfficialReleaseObservation(
	const LocalOfficialReleaseObservation *const previous,
	const LocalOfficialReleaseObservation		&current) noexcept
{
	// 今回の観測が不正なら、過去との差分を分類せず比較不能とする。
	if( !isLocalOfficialReleaseObservationValid( current)) {
		return ReleaseObservationDifference::INVALID ;
	}

	// 過去の観測がない場合は変更検出ではなく初回観測として扱う。
	if( previous == nullptr) {
		return ReleaseObservationDifference::FIRST_OBSERVATION ;
	}

	// 過去の記録が破損している場合は、今回の結果との一致を主張しない。
	if( !isLocalOfficialReleaseObservationValid( *previous)) {
		return ReleaseObservationDifference::INVALID ;
	}

	const LocalOfficialSourceBinding &oldBinding = previous->binding ;	// 前回取得元対応。
	const LocalOfficialSourceBinding &newBinding = current.binding ;	// 今回取得元対応。
	// 取得元や製品・分岐が変わった観測を、同じ配布系列のrelease変更として比較しない。
	if( oldBinding.providerId != newBinding.providerId ||
	   oldBinding.sourceId != newBinding.sourceId || oldBinding.familyId != newBinding.familyId ||
	   oldBinding.productKey != newBinding.productKey || oldBinding.branch != newBinding.branch) {
		return ReleaseObservationDifference::SOURCE_BINDING_CHANGED ;
	}

	// 結び付くdeviceが変わった観測を、同じ対象のrelease更新と混同しない。
	if( oldBinding.deviceBindingFingerprint != newBinding.deviceBindingFingerprint) {
		return ReleaseObservationDifference::DEVICE_BINDING_CHANGED ;
	}

	const LocalOfficialObservationEnvironment &oldEnvironment =
		previous->environment ;	// 前回環境条件。
	const LocalOfficialObservationEnvironment &newEnvironment =
		current.environment ;	// 今回環境条件。
	// OSの差による観測変更を先に示し、同一環境でのrelease差分と混同しない。
	if( oldEnvironment.operatingSystemFingerprint != newEnvironment.operatingSystemFingerprint) {
		return ReleaseObservationDifference::OPERATING_SYSTEM_CHANGED ;
	}

	// 端末構成が変わった場合は、その影響をrelease自体の差分より先に示す。
	if( oldEnvironment.deviceConfigurationFingerprint !=
	   newEnvironment.deviceConfigurationFingerprint) {
		return ReleaseObservationDifference::DEVICE_CONFIGURATION_CHANGED ;
	}

	// 検証policyが変わった観測同士を、同じ判定基準の結果として比較しない。
	if( oldEnvironment.policyRevision != newEnvironment.policyRevision) {
		return ReleaseObservationDifference::POLICY_CHANGED ;
	}

	// parser変更による読取り差を、配布元のrelease変更と区別する。
	if( oldEnvironment.parserRevision != newEnvironment.parserRevision) {
		return ReleaseObservationDifference::PARSER_CHANGED ;
	}

	// 配布物の明示keyまたは版が変わった場合に、releaseの変更として通知する。
	if( previous->releaseKey != current.releaseKey ||
	   previous->packageVersion != current.packageVersion) {
		return ReleaseObservationDifference::RELEASE_CHANGED ;
	}

	// 公開hashの差を内容識別の変更として示し、同じ表示版でも無変更としない。
	if( previous->publishedSha256 != current.publishedSha256) {
		return ReleaseObservationDifference::CONTENT_IDENTITY_CHANGED ;
	}

	// 未確認理由の変化を残し、同じmetadataでも検査状態の差を隠さない。
	if( previous->pendingReason != current.pendingReason) {
		return ReleaseObservationDifference::PENDING_REASON_CHANGED ;
	}

	// 公開hashがない観測は、表示metadataが同じでもpayload同一とは扱わない。
	if( current.publishedSha256.empty()) {
		// 同じURLや表示版だけではpayload同一性を証明できない。
		return ReleaseObservationDifference::METADATA_UNCHANGED ;
	}

	return ReleaseObservationDifference::STRONG_IDENTITY_UNCHANGED ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_release_observation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
LocalOfficialObservationReuse classifyLocalOfficialObservationReuse(
	const LocalOfficialReleaseObservation			 &observation,
	const std::span<const LocalOfficialSourceBinding> currentBindings,
	const LocalOfficialObservationEnvironment		 &currentEnvironment) noexcept
{
	// 保存値や現在環境が不正、または対応表が空・過大なら再利用を判定しない。
	if( !isLocalOfficialReleaseObservationValid( observation) ||
	   !isLocalEnvironmentValid( currentEnvironment) || currentBindings.empty() ||
	   currentBindings.size() > MAXIMUM_BINDING_COUNT) {
		return LocalOfficialObservationReuse::INVALID ;
	}

	bool bindingFound{} ;	// 保存済み観測と完全一致する現在bindingの有無。
	// 全bindingを検証し、曖昧または不正な集合を部分的に使用しない。
	for( std::size_t index = 0U; index < currentBindings.size(); ++index) {
		const LocalOfficialSourceBinding &binding = currentBindings[index] ;	// 現在の検証対象。
		// 現在の結び付きが不正なら、保存済み観測との対応を推測して再利用しない。
		if( !isLocalBindingValid( binding)) {
			return LocalOfficialObservationReuse::INVALID ;
		}

		// 同じbindingが二重登録された曖昧な集合を拒否する。
		for( std::size_t previousIndex = 0U; previousIndex < index; ++previousIndex) {
			// 同じ結び付きの重複を拒否し、保存した観測の再利用先を一意に保つ。
			if( localBindingsEqual( binding, currentBindings[previousIndex])) {
				return LocalOfficialObservationReuse::INVALID ;
			}
		}

		bindingFound = bindingFound || localBindingsEqual( observation.binding, binding) ;
	}

	// 現在の対応表に対象がない観測は、別deviceへ付け替えて再利用しない。
	if( !bindingFound) {
		return LocalOfficialObservationReuse::BINDING_UNAVAILABLE ;
	}

	// OSが変わった観測は、過去の適用環境を前提に再利用しない。
	if( observation.environment.operatingSystemFingerprint !=
	   currentEnvironment.operatingSystemFingerprint) {
		return LocalOfficialObservationReuse::OPERATING_SYSTEM_CHANGED ;
	}

	// device構成が変わった場合は、保存時の環境確認を現在も有効とは扱わない。
	if( observation.environment.deviceConfigurationFingerprint !=
	   currentEnvironment.deviceConfigurationFingerprint) {
		return LocalOfficialObservationReuse::DEVICE_CONFIGURATION_CHANGED ;
	}

	// 異なるpolicyで記録した観測を、現在の検証結果として再利用しない。
	if( observation.environment.policyRevision != currentEnvironment.policyRevision) {
		return LocalOfficialObservationReuse::POLICY_CHANGED ;
	}

	// parserが変わった場合は、同じ解釈で得たmetadataとはみなさない。
	if( observation.environment.parserRevision != currentEnvironment.parserRevision) {
		return LocalOfficialObservationReuse::PARSER_CHANGED ;
	}

	return LocalOfficialObservationReuse::CURRENT ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_release_observation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool mergeLocalOfficialReleaseObservations(
	const std::span<const LocalOfficialReleaseObservation> previous,
	const std::span<const std::wstring>					   refreshedProviderIds,
	const std::span<const LocalOfficialReleaseObservation> current,
	std::vector<LocalOfficialReleaseObservation>		  &merged)
{
	// 入力と更新Provider一覧の件数を制限し、統合処理の保持量を有限にする。
	if( previous.size() > MAXIMUM_BINDING_COUNT || current.size() > MAXIMUM_BINDING_COUNT ||
	   refreshedProviderIds.size() > MAXIMUM_BINDING_COUNT) {
		return false ;
	}

	// Provider集合を全検証し、同じProviderの二重更新を拒否する。
	for( std::size_t index = 0U; index < refreshedProviderIds.size(); ++index) {
		// 更新に成功したProviderの識別子が不正なら、旧記録の削除判断に使わない。
		if( !isStableIdentifier( refreshedProviderIds[index])) {
			return false ;
		}

		// 現在位置より前の有限範囲だけと比較し、更新Provider IDの重複を調べる。
		for( std::size_t previousIndex = 0U; previousIndex < index; ++previousIndex) {
			// 同じProviderの重複した更新指定を拒否し、置換対象の曖昧さを残さない。
			if( refreshedProviderIds[index] == refreshedProviderIds[previousIndex]) {
				return false ;
			}
		}
	}

	std::vector<LocalOfficialReleaseObservation> candidate ;	// 全検証後だけ出力へ移す一時集合。
	candidate.reserve( previous.size() + current.size()) ;
	// 成立Provider以外の前回recordだけを保持する。
	for( const LocalOfficialReleaseObservation &observation : previous) {
		// 不正な旧観測を正常な統合結果へ混ぜず、出力確定前に処理を中止する。
		if( !isLocalOfficialReleaseObservationValid( observation)) {
			return false ;
		}

		bool refreshed{} ;	// この旧recordを今回scan結果で置換する場合true。
		// 正常に更新したProviderの有限一覧を照合し、この旧観測を置換するか判断する。
		for( const std::wstring &providerId : refreshedProviderIds) {
			refreshed = refreshed || observation.binding.providerId == providerId ;
		}

		// 今回正常に更新していないProviderの旧記録は、検索失敗だけを理由に失わせない。
		if( !refreshed) {
			candidate.push_back( observation) ;
		}
	}

	// 今回recordは更新対象Provider由来だけを許可する。
	for( const LocalOfficialReleaseObservation &observation : current) {
		// 不正な新観測で保存結果を置き換えず、検証済みの入力だけを統合する。
		if( !isLocalOfficialReleaseObservationValid( observation)) {
			return false ;
		}

		bool providerAllowed{} ;	// Registryが成立を報告したProvider由来の場合true。
		// 更新成功Providerの有限一覧と照合し、新観測が今回の置換対象に属するか確認する。
		for( const std::wstring &providerId : refreshedProviderIds) {
			providerAllowed = providerAllowed || observation.binding.providerId == providerId ;
		}

		// 更新成功が確認されたProvider以外の新観測を、今回の置換結果へ加えない。
		if( !providerAllowed) {
			return false ;
		}

		candidate.push_back( observation) ;
	}

	// 旧記録の保持と新規追加で総件数が上限を超えたら、部分結果を公開しない。
	if( candidate.size() > MAXIMUM_BINDING_COUNT) {
		return false ;
	}

	// 全Providerを通じて同じsource/device bindingが二重にならないことを確認する。
	for( std::size_t index = 0U; index < candidate.size(); ++index) {
		// 追加済みの先行記録だけを比較し、同じ結び付きが統合結果に重複しないか調べる。
		for( std::size_t previousIndex = 0U; previousIndex < index; ++previousIndex) {
			// 同じ観測先を複数の記録が指す統合結果を拒否し、任意の一件へ丸めない。
			if( localBindingsEqual( candidate[index].binding, candidate[previousIndex].binding)) {
				return false ;
			}
		}
	}

	merged = std::move( candidate) ;
	return true ;
}

} // namespace drivercrate
