//------------------------------------------------------------------------------
/**
 * @file official_discovery_record_adapter.h
 * @brief 公式自動探索routeを固定root resolverと秘密record保持へ接続する契約。
 * @version 01.02.01
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  固定root adapterと秘密record sessionを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  検査用取得対象とEULA snapshot生成を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  通常scanの表示専用payload descriptor生成を追加。
 * Ver.01.02.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 一objectをProvider worker threadだけで直列使用します。Resolverへは組み込みsource policyの
 *       固定endpointだけを渡し、device hint、Hardware ID、提出URLを渡しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_discovery.h"
#include "core/official_preparation.h"
#include "platform/official_discovery_eula.h"
#include "platform/official_discovery_package.h"
#include "platform/official_record_resolution.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace drivercrate {

// 一つの固定root応答へ許可するADR 0157の最大本文byte数。
inline constexpr std::uint64_t OFFICIAL_DISCOVERY_RECORD_BYTES_LIMIT = 2ULL * 1'024ULL * 1'024ULL ;

/**
 * @brief Provider固有resolverが返す固定root探索の有限状態。
 */
enum class OfficialDiscoveryFixedRootState {
	/// Resolverをまだ実行していません。
	NOT_STARTED,
	/// 一つの型付き配布recordを構築しました。
	RESOLVED,
	/// 固定rootを正常に確認したが対応recordがありません。
	NO_RECORD,
	/// 利用者または終了処理により協調取消ししました。
	CANCELLED,
	/// Network、I/OまたはProvider内部処理が失敗しました。
	FAILED,
	/// 組み込み公式source境界の検証に失敗しました。
	SOURCE_REJECTED,
	/// 固定root metadataのschemaまたは内容を拒否しました。
	METADATA_REJECTED,
} ;

/**
 * @brief 固定root resolverのURL非保持終端結果。
 */
struct OfficialDiscoveryFixedRootResult {
	/// 一回のresolverが到達した有限状態。
	OfficialDiscoveryFixedRootState state{OfficialDiscoveryFixedRootState::NOT_STARTED} ;
	/// 失敗・source拒否・metadata拒否時のHRESULT bit pattern。
	NativeError						error{} ;
} ;

/**
 * @brief 組み込み固定rootから最大一つの型付きrecordを解決するProvider adapter callback。
 * @param[in] scanSessionId 現在のworker scan session ID。
 * @param[in] recordEvidenceId Sessionが今回だけ割り当てたrecord証拠ID。
 * @param[in] providerId RouteとProvider registryへ照合済みのstable ID。
 * @param[in] rootResourceId Source policyへ照合済みのlandingまたはmetadata resource ID。
 * @param[in] builtInRootUrl 組み込みsource policyから取得した固定HTTPS endpoint。
 * @param[in] maximumRecordBytes 一応答へ許可する2 MiB以下の上限。
 * @param[in] fetchMode 秘密URLを永続cacheへ保存しない固定mode。
 * @param[out] record `RESOLVED`時だけ設定する秘密URL所有record。
 * @return URL非保持の有限終了状態と診断値。
 * @warning Device hint、Hardware ID、instance ID、serial、利用者提出URLを引数へ追加しません。
 */
using OfficialDiscoveryFixedRootResolver = std::function<OfficialDiscoveryFixedRootResult(
	ScanSessionId scanSessionId, std::uint64_t recordEvidenceId, std::wstring_view providerId,
	std::wstring_view rootResourceId, std::wstring_view builtInRootUrl,
	std::uint64_t maximumRecordBytes, OfficialRecordFetchMode fetchMode,
	OfficialDistributionRecord &record)> ;

/**
 * @brief 一つの自動探索route種別をProvider固有固定root resolverへ結合する。
 */
struct OfficialDiscoveryFixedRootAdapter {
	/// Provider registryのstable ID。
	std::wstring_view				   providerId ;
	/// Source policy内のlandingまたはmetadata resource ID。
	std::wstring_view				   rootResourceId ;
	/// 専用または汎用固定rootのroute種別。
	OfficialDiscoveryRouteKind		   kind{OfficialDiscoveryRouteKind::DEDICATED} ;
	/// 一応答へ許可する2 MiB以下の有限byte上限。
	std::uint64_t					   maximumRecordBytes{} ;
	/// Provider固有parserへ固定rootだけを渡すcallback。
	OfficialDiscoveryFixedRootResolver resolver ;
} ;

/**
 * @brief 一adapterをroute、Provider registry、source policyへ完全一致で検証する。
 * @param[in] adapter 検証する固定root adapter。
 * @param[in] route Plannerが作成した一route。
 * @param[in] devices 同じinventory snapshotのraw ID非保持hint集合。
 * @param[in] descriptors Provider registryの正本または同じ合成copy。
 * @return Provider、root、種別、上限、callbackが全て一致する場合true。
 */
[[nodiscard]] bool validateOfficialDiscoveryFixedRootAdapter(
	const OfficialDiscoveryFixedRootAdapter &adapter, const OfficialDiscoveryRoute &route,
	std::span<const OfficialDiscoveryDeviceHint> devices,
	std::span<const ProviderDescriptor>			 descriptors) noexcept ;

/**
 * @brief 自動探索の秘密record、URL非保持package参照、実行済みrouteを一sessionで所有する。
 * @note Mutexを持たずProvider worker threadだけで直列使用します。新sessionと失効で全recordを破棄します。
 */
class OfficialDiscoveryRecordAdapterSession final {
public:
	/**
	 * @brief 有効sessionを持たないadapter sessionを作成する。
	 */
	OfficialDiscoveryRecordAdapterSession() = default ;

	/**
	 * @brief 保持中の秘密recordとpackage参照を破棄する。
	 */
	~OfficialDiscoveryRecordAdapterSession() = default ;

	/**
	 * @brief 秘密recordと実行済みrouteのsession結合の二重管理を防ぐため、コピー構築を禁止する。
	 */
	OfficialDiscoveryRecordAdapterSession( const OfficialDiscoveryRecordAdapterSession &) = delete ;
	/**
	 * @brief 秘密recordと実行済みrouteのsession結合を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	OfficialDiscoveryRecordAdapterSession &operator=(
		const OfficialDiscoveryRecordAdapterSession &) = delete ;
	/**
	 * @brief 秘密recordと実行済みrouteのsession結合を元のadapter sessionに留めるため、移動構築を禁止する。
	 */
	OfficialDiscoveryRecordAdapterSession( OfficialDiscoveryRecordAdapterSession &&) = delete ;
	/**
	 * @brief 元のadapter sessionへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	OfficialDiscoveryRecordAdapterSession &operator=( OfficialDiscoveryRecordAdapterSession &&) =
		delete ;

	/**
	 * @brief 旧recordを失効させ、新しい探索bindingとrequestを開始する。
	 * @param[in] binding Operation、scan session、inventory generationの開始時binding。
	 * @param[in] request Provider範囲と権限を固定した開始時request。
	 * @param[in] descriptors Provider registryの正本または同じ合成copy。
	 * @return 新しい単調bindingと要求を受理した場合0、それ以外はHRESULT bit pattern。
	 * @post 成功時は保持record、package参照、実行済みrouteが全て0件です。
	 */
	[[nodiscard]] NativeError beginSession(
		const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
		std::span<const ProviderDescriptor> descriptors) noexcept ;

	/**
	 * @brief 一routeを固定root adapterで一回だけ解決し、秘密recordとpackage参照を保持する。
	 * @param[in] request 開始時と完全一致する探索request。
	 * @param[in] route Plannerが作成した一route。
	 * @param[in] devices 同じinventory snapshotのraw ID非保持hint集合。
	 * @param[in] adapter Routeと完全一致する固定root adapter。
	 * @param[in] cancellation Workerが所有する同一operationの非blocking取消しcallback。
	 * @return URL、root endpoint、record本文を含まないroute summary。
	 * @post `RESOLVED`時だけ一recordと全payloadのpackage参照を追加します。
	 * @note Resolverへdevice hintを渡さず、適合判定は後続の端末内matcherだけで行います。
	 */
	[[nodiscard]] OfficialDiscoveryRouteSummary resolveRoute(
		const OfficialDiscoveryRequest &request, const OfficialDiscoveryRoute &route,
		std::span<const OfficialDiscoveryDeviceHint> devices,
		const OfficialDiscoveryFixedRootAdapter		&adapter,
		const OfficialRecordResolutionCancellation	&cancellation) noexcept ;

	/**
	 * @brief 保持中のURL非保持package参照を初出順で借用する。
	 * @return 次session、失効またはobject破棄まで有効な非所有span。
	 */
	[[nodiscard]] std::span<const OfficialDiscoveryResolvedPackage> resolvedPackages()
		const noexcept ;

	/**
	 * @brief 解決済みpackage groupを取得権限なしの表示用descriptorへ変換する。
	 * @param[in] binding 現在のoperation、scan session、inventory generation。
	 * @param[in] groups 重複排除済みpackage group集合。
	 * @param[out] payloadDescriptors 成功時だけ各groupと同順のURL非保持descriptor集合。
	 * @return 全record、payload、groupを再照合できた場合0。それ以外はHRESULT bit pattern。
	 * @post 失敗時は出力を空にし、秘密recordをclaimしません。
	 * @note Unsupported payloadも方式表示のため保持し、download grantやEULA判断を発行しません。
	 */
	[[nodiscard]] NativeError describeDisplayPayloads(
		const OfficialDiscoveryBinding				  &binding,
		std::span<const OfficialDiscoveryPackageGroup> groups,
		std::vector<OfficialRecordPayloadDescriptor>  &payloadDescriptors) const noexcept ;

	/**
	 * @brief 解決済みpackage groupを既存の取得準備対象とEULA snapshotへ変換する。
	 * @param[in] binding 現在のoperation、scan session、inventory generation。
	 * @param[in] groups 同じpayloadを一取得へまとめた4件以下のgroup集合。
	 * @param[out] targets 成功時だけ既存取得準備UIへ渡すURL非保持対象集合。
	 * @param[out] eulaPackages 成功時だけ同意必須対象の全文snapshot集合。
	 * @param[out] payloadDescriptors 成功時だけ各対象と同順の表示用payload descriptor集合。
	 * @return 全record、payload、groupを再照合できた場合0。それ以外はHRESULT bit pattern。
	 * @post 失敗時は全出力を空にし、秘密recordをclaimしません。
	 * @note Unsupported payloadは対象へ含めず、公式installerは後続専用監査前の取得対象に留めます。
	 */
	[[nodiscard]] NativeError describePreparationTargets(
		const OfficialDiscoveryBinding				  &binding,
		std::span<const OfficialDiscoveryPackageGroup> groups,
		std::vector<OfficialPreparationTarget>		  &targets,
		std::vector<OfficialDiscoveryEulaPackage>	  &eulaPackages,
		std::vector<OfficialRecordPayloadDescriptor>  &payloadDescriptors) const noexcept ;

	/**
	 * @brief 保持recordをsession・証拠IDで一回だけclaimする。
	 * @param[in] scanSessionId 現在のworker scan session ID。
	 * @param[in] recordEvidenceId Package groupが保持する0ではない証拠ID。
	 * @param[out] record 成功時だけ秘密recordと証拠の所有権を受け取る出力。
	 * @return Claim成功時0、stale、未知、再使用IDはHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError claimResolvedRecord(
		ScanSessionId scanSessionId, std::uint64_t recordEvidenceId,
		ResolvedOfficialDistributionRecord &record) noexcept ;

	/**
	 * @brief 現在sessionと全秘密record、package参照、route claimを失効させる。
	 */
	void								   invalidate() noexcept ;

	/**
	 * @brief 現在保持する未claim秘密record件数を返す。
	 * @return 0件以上64件以下のrecord数。
	 */
	[[nodiscard]] std::size_t			   retainedRecordCount() const noexcept ;

	/**
	 * @brief 現在有効な開始時bindingを返す。
	 * @return 有効sessionのbinding。未開始・失効後は全0です。
	 */
	[[nodiscard]] OfficialDiscoveryBinding activeBinding() const noexcept ;

private:
	/// 現在有効な探索開始時binding。
	OfficialDiscoveryBinding											  binding_ ;
	/// 現在有効なProvider範囲と権限の所有copy。
	OfficialDiscoveryRequest											  request_ ;
	/// 開始時に検証して所有するProvider registry snapshot。
	std::vector<ProviderDescriptor>										  providerDescriptors_ ;
	/// 再使用・逆行を拒否する過去最大operation ID。
	OperationId															  latestOperationId_{} ;
	/// 再使用・逆行を拒否する過去最大scan session ID。
	ScanSessionId														  latestSessionId_{} ;
	/// 現在sessionで次に割り当てるrecord証拠ID。
	std::uint64_t														  nextRecordEvidenceId_{1U} ;
	/// Opaque証拠IDから秘密recordへのworker内索引。
	std::unordered_map<std::uint64_t, ResolvedOfficialDistributionRecord> records_ ;
	/// Route初出順で保持するURL非保持package参照。
	std::vector<OfficialDiscoveryResolvedPackage>						  packages_ ;
	/// 一sessionで二重実行を拒否するroute ID集合。
	std::unordered_set<std::uint64_t>									  resolvedRouteIds_ ;
} ;

} // namespace drivercrate
