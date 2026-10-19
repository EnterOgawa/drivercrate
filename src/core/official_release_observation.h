//------------------------------------------------------------------------------
/**
 * @file official_release_observation.h
 * @brief 公式release端末内観測契約。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 生PnP IDとscan session IDを保存せず、端末内bindingと前回release観測を比較します。比較結果は導入、同意、署名、rankの許可を表しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公式release観測型定義。
//------------------------------------------------------------------------------

/**
 * @brief 前回観測時に解決しなかった処理理由である。
 */
enum class ReleaseObservationPendingReason {
	/// 観測metadataに既知の保留理由がない。
	NONE,
	/// 公式endpointまたはschemaの再審査が必要。
	ENDPOINT_CHANGED,
	/// EULA、login等の利用者操作が必要。
	SOURCE_INTERACTION_REQUIRED,
	/// Payload内容の明示的な再確認が必要。
	CONTENT_REVALIDATION_NEEDED,
	/// 取得したmetadataが組み込み規則を満たさない。
	METADATA_REJECTED,
} ;

/**
 * @brief 前回と今回の端末内観測を比較した結果である。
 *
 * @note どの値もdownloadまたはinstallの許可を表さない。
 */
enum class ReleaseObservationDifference {
	/// 入力が保存契約を満たさず比較できない。
	INVALID,
	/// 比較可能な前回観測がない。
	FIRST_OBSERVATION,
	/// Provider、source、family、product、branchが変わった。
	SOURCE_BINDING_CHANGED,
	/// 端末内device binding fingerprintが変わった。
	DEVICE_BINDING_CHANGED,
	/// OS、architectureのfingerprintが変わった。
	OPERATING_SYSTEM_CHANGED,
	/// 対象device構成のfingerprintが変わった。
	DEVICE_CONFIGURATION_CHANGED,
	/// 監査policy revisionが変わった。
	POLICY_CHANGED,
	/// 公式metadata parser revisionが変わった。
	PARSER_CHANGED,
	/// Release keyまたは表示版が変わった。
	RELEASE_CHANGED,
	/// 公表SHA-256の値または有無が変わった。
	CONTENT_IDENTITY_CHANGED,
	/// 未確認理由が変わった。
	PENDING_REASON_CHANGED,
	/// 弱いidentityの表示metadataだけが一致した。
	METADATA_UNCHANGED,
	/// 公表SHA-256を含むmetadataが一致した。
	STRONG_IDENTITY_UNCHANGED,
} ;

/**
 * @brief 保存済み観測を現在のlocal probe条件で再利用できるかを表す。
 *
 * @note Currentはmetadata取得省略の許可ではなく、X6-04の差分比較へ渡せる状態だけを表す。
 */
enum class LocalOfficialObservationReuse {
	/// 入力、binding集合、環境のいずれかが不正。
	INVALID,
	/// 現在のlocal deviceと同じbindingが存在しない。
	BINDING_UNAVAILABLE,
	/// OSまたはarchitecture fingerprintが異なる。
	OPERATING_SYSTEM_CHANGED,
	/// 対象device集合fingerprintが異なる。
	DEVICE_CONFIGURATION_CHANGED,
	/// 内容・適用性監査policy revisionが異なる。
	POLICY_CHANGED,
	/// 公式metadata parser revisionが異なる。
	PARSER_CHANGED,
	/// Bindingと全環境条件が現在も一致する。
	CURRENT,
} ;

/**
 * @brief 端末ごとに一度生成し、保護state以外へ保存しないHMAC-SHA-256 key。
 */
using LocalOfficialBindingSecret = std::array<std::byte, 32U> ;

/**
 * @brief 公式sourceと端末内deviceの永続的な対応付けである。
 */
struct LocalOfficialSourceBinding {
	/// 端末内で生成する64桁小文字SHA-256。生PnP IDまたはscan IDではない。
	std::wstring deviceBindingFingerprint ;
	/// Provider registryのstable ID。
	std::wstring providerId ;
	/// 組み込み配布元定義のstable ID。
	std::wstring sourceId ;
	/// 組み込み製品系列のstable ID。
	std::wstring familyId ;
	/// 公式source側の公開製品key。端末識別情報を含めない。
	std::wstring productKey ;
	/// OSまたは製品系列で固定した公開配布branch。
	std::wstring branch ;
} ;

/**
 * @brief 観測を再利用できる端末環境と実装revisionである。
 */
struct LocalOfficialObservationEnvironment {
	/// OS edition、build、architectureから端末内生成する64桁小文字SHA-256。
	std::wstring  operatingSystemFingerprint ;
	/// 対象device集合から端末内生成する64桁小文字SHA-256。
	std::wstring  deviceConfigurationFingerprint ;
	/// 内容・適用性監査policyの単調revision。
	std::uint32_t policyRevision{} ;
	/// 公式metadata parserの単調revision。
	std::uint32_t parserRevision{} ;
} ;

/**
 * @brief 端末内へ保存できる一つの公式release観測である。
 */
struct LocalOfficialReleaseObservation {
	/// 公式sourceとlocal deviceの対応。
	LocalOfficialSourceBinding			binding ;
	/// 再評価条件と実装revision。
	LocalOfficialObservationEnvironment environment ;
	/// 公式sourceが明示する安定release key。空を許可する。
	std::wstring						releaseKey ;
	/// 公式sourceの表示版。INF DriverVerではない。
	std::wstring						packageVersion ;
	/// 公表SHA-256。存在しないsourceでは空。
	std::wstring						publishedSha256 ;
	/// 観測時刻を表すUTC FILETIME値。
	std::uint64_t						observedFileTime{} ;
	/// 前回観測時の未確認理由。導入拒否理由の全履歴ではない。
	ReleaseObservationPendingReason		pendingReason{ReleaseObservationPendingReason::NONE} ;
} ;

/**
 * @brief 公式release観測が有限で機密情報を直接保持しない保存契約を満たすか調べる。
 * 端末内公式release観測を検証する。
 * 必須fingerprint、有限ID、revision、観測時刻を確認する。
 * @param[in] observation 検証する端末内観測。 保存前に検証する観測。
 * @return 保存可能な場合はtrue。不明enum、欠落、上限超過、不正hashはfalse。 保存契約を満たす場合はtrue。
 */
[[nodiscard]] bool isLocalOfficialReleaseObservationValid(
	const LocalOfficialReleaseObservation &observation) noexcept ;

/**
 * @brief 前回と今回の端末内release観測をfail-closedで比較する。
 * 端末内公式release観測を比較する。
 * Binding、環境、実装revision、releaseの順に比較する。一致しても導入許可や過去の監査結果は返さない。
 * @param[in] previous 前回観測。初回はnullptrを指定できる。
 * @param[in] current 今回の公式metadataから構築した観測。 今回の検証対象観測。
 * @return 最初に再評価を必要とする差分。入力不正時はInvalid。
 * @note 一致結果でも過去の監査、署名、rank、同意、取得根拠を再利用してはならない。
 */
[[nodiscard]] ReleaseObservationDifference compareLocalOfficialReleaseObservation(
	const LocalOfficialReleaseObservation *previous,
	const LocalOfficialReleaseObservation &current) noexcept ;

/**
 * @brief 保存済み観測を現在のbinding集合と環境へ照合する。
 * 保存済み観測のlocal probe再利用条件を分類する。
 * 入力全体を先に検証し、過去の監査結果を許可へ変換せず、X6-04へ渡せる観測だけを分類する。
 * @param[in] observation 保存済みの検証対象観測。 保存済み観測。
 * @param[in] currentBindings local probeが生成した現在のbinding集合。最大4096件。 現在の有限binding集合。
 * @param[in] currentEnvironment 現在のOS、device構成、policy、parser条件。 現在の環境と実装revision。
 * @return 最初に検出した失効理由。一致時はLocalOfficialObservationReuse::Current。 最初に検出した失効理由。一致時はCurrent。
 * @note Release metadata、署名、INF、PnP rank、EULA、install許可は再利用しない。
 */
[[nodiscard]] LocalOfficialObservationReuse classifyLocalOfficialObservationReuse(
	const LocalOfficialReleaseObservation	   &observation,
	std::span<const LocalOfficialSourceBinding> currentBindings,
	const LocalOfficialObservationEnvironment  &currentEnvironment) noexcept ;

/**
 * @brief 成立したProviderの今回観測だけを前回snapshotへ置換する。
 * 成立Providerの旧recordだけを除去し、失敗・未実行Providerを保持する。全検証終了まで出力を変更しない。
 * @param[in] previous 前回の検証対象snapshot。最大4,096件。 前回の全Provider観測snapshot。
 * @param[in] refreshedProviderIds 今回scanが成立し、旧recordを置換するProvider ID集合。 今回置換するProvider ID集合。
 * @param[in] current 今回Providerが生成した観測集合。 今回scanで生成した観測集合。
 * @param[out] merged 成功時の全Provider snapshot。失敗時は変更しない。 成功時の置換済み全Provider snapshot。
 * @return 全record、Provider対応、重複、上限を検証できた場合true。 全入力、Provider対応、重複、件数上限が有効な場合true。
 * @note 候補0件で成立したProvider IDも指定し、そのProviderの旧recordを除去できる。
 */
[[nodiscard]] bool mergeLocalOfficialReleaseObservations(
	std::span<const LocalOfficialReleaseObservation> previous,
	std::span<const std::wstring>					 refreshedProviderIds,
	std::span<const LocalOfficialReleaseObservation> current,
	std::vector<LocalOfficialReleaseObservation>	&merged) ;

} // namespace drivercrate
